/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Nokia Corporation
 *  Copyright (C) 2011  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <gdbus/gdbus.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <glib.h>

#include <bluetooth/bluetooth.h>

#include "lib/uuid.h"
#include "dbus-common.h"
#include "adapter.h"
#include "device.h"
#include "error.h"
#include "log.h"
#include "gatt.h"
#include "proximity.h"
#include "monitor.h"
#include "textfile.h"

#define PROXIMITY_INTERFACE "org.bluez.ProximityMonitor1"

#define IMMEDIATE_TIMEOUT	5

struct monitor {
	struct btd_device *device;
	struct btd_attribute *linkloss;		/* LL Alert Level */
	struct btd_attribute *immediate;	/* Immediate Alert Level */
	struct enabled enabled;
	char *linklosslevel;		/* Link Loss Alert Level */
	char *fallbacklevel;		/* Immediate fallback alert level */
	char *immediatelevel;		/* Immediate Alert Level */
	char *signallevel;		/* Path Loss RSSI level */
	guint immediateto;		/* Reset Immediate Alert to "none" */
};

static GSList *monitors = NULL;

static struct monitor *find_monitor(struct btd_device *device)
{
	GSList *l;

	for (l = monitors; l; l = l->next) {
		struct monitor *monitor = l->data;

		if (monitor->device == device)
			return monitor;
	}

	return NULL;
}

static void write_proximity_config(struct btd_device *device, const char *alert,
					const char *level)
{
	char *filename;
	GKeyFile *key_file;
	char *data;
	gsize length = 0;

	filename = btd_device_get_storage_path(device, "proximity");
	if (!filename) {
		warn("Unable to get proximity storage path for device");
		return;
	}

	key_file = g_key_file_new();
	g_key_file_load_from_file(key_file, filename, 0, NULL);

	if (level)
		g_key_file_set_string(key_file, alert, "Level", level);
	else
		g_key_file_remove_group(key_file, alert, NULL);

	data = g_key_file_to_data(key_file, &length, NULL);
	if (length > 0) {
		create_file(filename, S_IRUSR | S_IWUSR);
		g_file_set_contents(filename, data, length, NULL);
	}

	g_free(data);
	g_free(filename);
	g_key_file_free(key_file);
}

static char *read_proximity_config(struct btd_device *device, const char *alert)
{
	char *filename;
	GKeyFile *key_file;
	char *str;

	filename = btd_device_get_storage_path(device, "proximity");
	if (!filename) {
		warn("Unable to get proximity storage path for device");
		return NULL;
	}

	key_file = g_key_file_new();
	g_key_file_load_from_file(key_file, filename, 0, NULL);

	str = g_key_file_get_string(key_file, alert, "Level", NULL);

	g_free(filename);
	g_key_file_free(key_file);

	return str;
}

static uint8_t str2level(const char *level)
{
	if (g_strcmp0("high", level) == 0)
		return HIGH_ALERT;
	else if (g_strcmp0("mild", level) == 0)
		return MILD_ALERT;

	return NO_ALERT;
}

static void linkloss_alert_written(int err, void *user_data)
{
	struct monitor *monitor = user_data;
	struct btd_device *device = monitor->device;
	const char *path = device_get_path(device);

	if (err) {
		error("Proximity Monitor: Link Loss Write Request failed: %s",
							strerror(err));
		return;
	}

	DBG("Proximity Monitor: Link Loss Alert Level written");

	g_dbus_emit_property_changed(btd_get_dbus_connection(), path,
				PROXIMITY_INTERFACE, "LinkLossAlertLevel");
}

static gboolean immediate_timeout(gpointer user_data);

static void immediate_alert_written(int err, void *user_data)
{
	struct monitor *monitor = user_data;
	const char *path = device_get_path(monitor->device);

	/*
	 * This callback gets called by SetProperties or a when a timeout
	 * occurs to reset the Immediate Alert Level. This timeout is
	 * BlueZ specific logic, it is not defined in the Find Me Profile.
	 */
	if (err) {
		error("Proximity Monitor: Immediate Alert Write " \
				"Request failed: %s", strerror(err));

		if (monitor->fallbacklevel) {
			g_free(monitor->immediatelevel);
			monitor->immediatelevel = monitor->fallbacklevel;
			monitor->fallbacklevel = NULL;
		}

		/* Emit signal even when write fails */
		goto done;
	}

	g_free(monitor->fallbacklevel);
	monitor->fallbacklevel = NULL;

	 /* For Find Me: stop alerting after 5 seconds */
	if (g_strcmp0(monitor->immediatelevel, "none") != 0)
		monitor->immediateto = g_timeout_add_seconds(IMMEDIATE_TIMEOUT,
						immediate_timeout, monitor);

done:
	g_dbus_emit_property_changed(btd_get_dbus_connection(), path,
				PROXIMITY_INTERFACE, "ImmediateAlertLevel");
}

static gboolean immediate_timeout(gpointer user_data)
{
	struct monitor *monitor = user_data;
	uint8_t value = NO_ALERT;

	monitor->immediateto = 0;

	if (g_strcmp0(monitor->immediatelevel, "none") == 0)
		return FALSE;

	g_free(monitor->immediatelevel);
	monitor->immediatelevel = g_strdup("none");

	/* If connected: reset alert level to NO_ALERT */
	btd_gatt_write_attribute(monitor->device, monitor->immediate,
					&value, sizeof(value), 0,
					immediate_alert_written, monitor);

	return FALSE;
}

static gboolean level_is_valid(const char *level)
{
	return (g_str_equal("none", level) ||
			g_str_equal("mild", level) ||
			g_str_equal("high", level));
}

static gboolean property_get_link_loss_level(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct monitor *monitor = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
						&monitor->linklosslevel);

	return TRUE;
}

static void property_set_link_loss_level(const GDBusPropertyTable *property,
		DBusMessageIter *iter, GDBusPendingPropertySet id, void *data)
{
	struct monitor *monitor = data;
	const char *level;
	uint8_t value;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING) {
		g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");
		return;
	}

	dbus_message_iter_get_basic(iter, &level);

	if (!level_is_valid(level)) {
		g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");
		return;
	}

	if (g_strcmp0(monitor->linklosslevel, level) == 0)
		goto done;

	g_free(monitor->linklosslevel);
	monitor->linklosslevel = g_strdup(level);

	write_proximity_config(monitor->device, "LinkLossAlertLevel", level);

	value = str2level(monitor->linklosslevel);
	btd_gatt_write_attribute(monitor->device, monitor->linkloss,
					&value, sizeof(value), 0,
					linkloss_alert_written, monitor);

done:
	g_dbus_pending_property_success(id);
}

static gboolean property_exists_link_loss_level(
				const GDBusPropertyTable *property, void *data)
{
	struct monitor *monitor = data;

	if (!monitor->enabled.linkloss)
		return FALSE;

	return TRUE;
}

static gboolean property_get_immediate_alert_level(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct monitor *monitor = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
						&monitor->immediatelevel);

	return TRUE;
}

static void property_set_immediate_alert_level(
		const GDBusPropertyTable *property, DBusMessageIter *iter,
		GDBusPendingPropertySet id, void *data)
{
	struct monitor *monitor = data;
	const char *level;
	uint8_t value;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING) {
		g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");
		return;
	}

	dbus_message_iter_get_basic(iter, &level);

	if (!level_is_valid(level)) {
		g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");
		return;
	}

	if (g_strcmp0(monitor->immediatelevel, level) == 0)
		goto done;

	if (monitor->immediateto) {
		g_source_remove(monitor->immediateto);
		monitor->immediateto = 0;
	}

	/* Previous Immediate Alert level if connection/write fails */
	g_free(monitor->fallbacklevel);
	monitor->fallbacklevel = monitor->immediatelevel;

	monitor->immediatelevel = g_strdup(level);

	/*
	 * Means that Link/Path Loss are disabled or there is a pending
	 * writting for Find Me(Immediate Alert characteristic value).
	 * If enabled, Path Loss always registers a connection callback
	 * when the Proximity Monitor starts.
	 */
	value = str2level(monitor->immediatelevel);
	btd_gatt_write_attribute(monitor->device, monitor->immediate, &value,
			sizeof(value), 0, immediate_alert_written, monitor);

done:
	g_dbus_pending_property_success(id);
}

static gboolean property_exists_immediate_alert_level(
				const GDBusPropertyTable *property, void *data)
{
	struct monitor *monitor = data;

	if (!(monitor->enabled.findme))
		return FALSE;

	return TRUE;
}

static gboolean property_get_signal_level(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct monitor *monitor = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
						&monitor->signallevel);

	return TRUE;
}

static gboolean property_exists_signal_level(const GDBusPropertyTable *property,
								void *data)
{
	return FALSE;
}

static const GDBusPropertyTable monitor_device_properties[] = {
	{ "LinkLossAlertLevel", "s", property_get_link_loss_level,
					property_set_link_loss_level,
					property_exists_link_loss_level },
	{ "ImmediateAlertLevel", "s", property_get_immediate_alert_level,
					property_set_immediate_alert_level,
					property_exists_immediate_alert_level },
	{ "SignalLevel", "s", property_get_signal_level, NULL,
					property_exists_signal_level },
	{ }
};

static void monitor_destroy(gpointer user_data)
{
	struct monitor *monitor = user_data;

	btd_device_unref(monitor->device);
	g_free(monitor->linklosslevel);
	g_free(monitor->immediatelevel);
	g_free(monitor->signallevel);
	g_free(monitor);

	monitors = g_slist_remove(monitors, monitor);
}

static struct monitor *register_monitor(struct btd_device *device)
{
	const char *path = device_get_path(device);
	struct monitor *monitor;
	char *level;

	monitor = find_monitor(device);
	if (monitor != NULL)
		return monitor;

	level = read_proximity_config(device, "LinkLossAlertLevel");

	monitor = g_new0(struct monitor, 1);
	monitor->device = btd_device_ref(device);
	monitor->linklosslevel = (level ? : g_strdup("high"));
	monitor->signallevel = g_strdup("unknown");
	monitor->immediatelevel = g_strdup("none");

	monitors = g_slist_append(monitors, monitor);

	if (g_dbus_register_interface(btd_get_dbus_connection(), path,
				PROXIMITY_INTERFACE,
				NULL, NULL, monitor_device_properties,
				monitor, monitor_destroy) == FALSE) {
		error("D-Bus failed to register %s interface",
						PROXIMITY_INTERFACE);
		monitor_destroy(monitor);
		return NULL;
	}

	DBG("Proximity Monitor: Registered interface %s on path %s",
					PROXIMITY_INTERFACE, path);

	return monitor;
}

int monitor_register_linkloss(struct btd_device *device,
						struct enabled *enabled)
{
	struct monitor *monitor;
	GSList *list;
	struct btd_attribute *lls;
	struct btd_attribute *level;
	bt_uuid_t uuid;

	if (!enabled->linkloss)
		return 0;

	/* Accessing Link Loss Service declaration */
	bt_uuid16_create(&uuid, LINK_LOSS_SVC_UUID);
	list = btd_gatt_get_services(device, &uuid);
	if (list == NULL) {
		DBG("Proximity Monitor: LLS missing!");
		return -1;
	}

	lls = list->data;
	g_slist_free(list);

	/* Accessing Link Loss Alert Level declaration */
	bt_uuid16_create(&uuid, ALERT_LEVEL_CHR_UUID);
	list = btd_gatt_get_chars_decl(device, lls, &uuid);
	if (list == NULL) {
		DBG("Proximity Monitor: LLS Alert Level declaration missing!");
		return -1;
	}

	/* Accessing Immediate Alert Level value */
	level = btd_gatt_get_char_value(device, list->data);
	g_slist_free(list);
	if (level == NULL) {
		DBG("Proximity Monitor: LLS Alert Level value missing!");
		return -1;
	}

	monitor = register_monitor(device);
	if (monitor == NULL)
		return -1;

	monitor->linkloss = level;
	monitor->enabled.linkloss = TRUE;

	DBG("Proximity Monitor Link Loss: %s, FindMe: %s",
				monitor->enabled.linkloss ? "TRUE" : "FALSE",
				monitor->enabled.findme ? "TRUE" : "FALSE");

	return 0;
}

int monitor_register_immediate(struct btd_device *device,
						struct enabled *enabled)
{
	struct monitor *monitor;
	GSList *list;
	struct btd_attribute *ias;
	struct btd_attribute *level;
	bt_uuid_t uuid;

	if (!enabled->findme)
		return 0;

	/* Accessing Immediate Alert Service declaration */
	bt_uuid16_create(&uuid, IMMEDIATE_ALERT_SVC_UUID);
	list = btd_gatt_get_services(device, &uuid);
	if (list == NULL) {
		DBG("Proximity Monitor: IAS missing!");
		return -1;
	}

	ias = list->data;
	g_slist_free(list);

	/* Accessing Immediate Alert Level declaration */
	bt_uuid16_create(&uuid, ALERT_LEVEL_CHR_UUID);
	list = btd_gatt_get_chars_decl(device, ias, &uuid);
	if (list == NULL) {
		DBG("Proximity Monitor: IAS Alert Level declaration missing!");
		return -1;
	}

	/* Accessing Immediate Alert Level value */
	level = btd_gatt_get_char_value(device, list->data);
	g_slist_free(list);
	if (level == NULL) {
		DBG("Proximity Monitor: IAS Alert Level value missing!");
		return -1;
	}

	monitor = register_monitor(device);
	if (monitor == NULL)
		return -1;

	monitor->immediate = level;
	monitor->enabled.findme = TRUE;

	DBG("Proximity Monitor Link Loss: %s, FindMe: %s",
				monitor->enabled.linkloss ? "TRUE" : "FALSE",
				monitor->enabled.findme ? "TRUE" : "FALSE");

	return 0;
}

static void cleanup_monitor(struct monitor *monitor)
{
	struct btd_device *device = monitor->device;
	const char *path = device_get_path(device);

	if (monitor->immediate != NULL)
		return;

	if (monitor->immediateto != 0) {
		g_source_remove(monitor->immediateto);
		monitor->immediateto = 0;
	}

	if (monitor->linkloss != NULL)
		return;

	g_dbus_unregister_interface(btd_get_dbus_connection(), path,
							PROXIMITY_INTERFACE);
}

void monitor_unregister_linkloss(struct btd_device *device)
{
	struct monitor *monitor;

	monitor = find_monitor(device);
	if (monitor == NULL)
		return;

	monitor->linkloss = NULL;
	monitor->enabled.linkloss = FALSE;

	cleanup_monitor(monitor);
}

void monitor_unregister_immediate(struct btd_device *device)
{
	struct monitor *monitor;

	monitor = find_monitor(device);
	if (monitor == NULL)
		return;

	monitor->immediate = NULL;
	monitor->enabled.findme = FALSE;

	cleanup_monitor(monitor);
}
