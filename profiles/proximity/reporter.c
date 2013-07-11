/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Instituto Nokia de Tecnologia - INdT
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdbool.h>
#include <errno.h>

#include <glib.h>
#include <adapter.h>

#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "log.h"

#include "lib/uuid.h"
#include "dbus-common.h"
#include "device.h"
#include "profile.h"
#include "service.h"
#include "attrib/att.h"
#include "gatt.h"
#include "textfile.h"

#include "proximity.h"
#include "reporter.h"

static GHashTable *linkloss_levels = NULL;

static struct btd_attribute *linkloss_service = NULL;
static struct btd_attribute *linkloss_alert_level = NULL;

static struct btd_attribute *immediate_service = NULL;
static struct btd_attribute *immediate_alert_level = NULL;

/*
 * IAS defines a single instance of the <<Alert Level>>
 * characteristic. The object path used to emit the signal
 * defines only which device wrote in the characteristic.
 * TODO: multiple adapters are not properly addressed.
 */
static uint8_t immediate_level = NO_ALERT;

static void create_proximity_file_name(struct btd_device *device,
						char *buffer, size_t size)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	char srcaddr[18], dstaddr[18];
	const bdaddr_t *sba, *dba;

	sba = adapter_get_address(adapter);
	ba2str(sba, srcaddr);

	dba = device_get_address(device);
	ba2str(dba, dstaddr);

	snprintf(buffer, size, STORAGEDIR "/%s/%s/proximity",
							srcaddr, dstaddr);
}

static void store_lls_al(struct btd_device *device, uint8_t value)
{
	char filename[PATH_MAX + 1];
	GKeyFile *key_file;
	char *data;
	size_t data_size;

	create_proximity_file_name(device, filename, sizeof(filename));
	key_file = g_key_file_new();

	/*
	 * Format:
	 * [Reporter]
	 * LinkLossAlertLevel=none
	 */
	g_key_file_set_integer(key_file, "Reporter", "LinkLossAlertLevel",
								value);
	data = g_key_file_to_data(key_file, &data_size, NULL);
	if (data_size > 0) {
		create_file(filename, S_IRUSR | S_IWUSR);
		g_file_set_contents(filename, data, data_size, NULL);
		g_free(data);
	}

	g_key_file_free(key_file);
}

static int read_lls_al(struct btd_device *device, uint8_t *level)
{
	char filename[PATH_MAX + 1];
	GKeyFile *key_file;
	GError *gerr = NULL;
	int keyval, retval = 0;

	key_file = g_key_file_new();

	create_proximity_file_name(device, filename, sizeof(filename));
	if (g_key_file_load_from_file(key_file, filename,
					G_KEY_FILE_NONE, NULL) == FALSE) {
		retval = -ENOENT;
		goto done;
	}

	keyval = g_key_file_get_integer(key_file, "Reporter",
					"LinkLossAlertLevel", &gerr);

	if (gerr) {
		DBG("LinkLossAlertLevel: %s", gerr->message);
		g_error_free(gerr);
		retval = -ENOENT;
		goto done;
	}

	*level = keyval;

done:
	g_key_file_free(key_file);

	return retval;
}

static void emit_ias_alert_level(struct btd_device *device, uint8_t level)
{
	const char *path;

	if (immediate_level == level)
		return;

	immediate_level = level;

	path = device_get_path(device);

	g_dbus_emit_property_changed(btd_get_dbus_connection(), path,
			PROXIMITY_REPORTER_INTERFACE, "ImmediateAlertLevel");
}

static void write_ias_al_cb(struct btd_device *device,
			struct btd_attribute *attr,
			uint8_t *value, size_t len, uint16_t offset,
			btd_attr_write_result_t result, void *user_data)
{
	/*
	 * For Write Without Response "result" callback doesn't
	 * need to called. Confirmation is not applied.
	 */

	if (len != 1 || (value[0] != NO_ALERT && value[0] != MILD_ALERT &&
						value[0] != HIGH_ALERT)) {
		error("Invalid \"Alert Level\" characteristic value");
		emit_ias_alert_level(device, NO_ALERT);
		return;
	}

	DBG("Immediate Alert Level: 0x%02x", value[0]);

	emit_ias_alert_level(device, value[0]);
}

static gboolean property_get_link_loss_level(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_service *service = data;
	uint8_t *linkloss_level;
	const char *level;

	linkloss_level = g_hash_table_lookup(linkloss_levels,
					btd_service_get_device(service));
	level = proximity_level2string(*linkloss_level);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &level);

	return TRUE;
}

static gboolean property_get_immediate_alert_level(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	const char *level;

	level = proximity_level2string(immediate_level);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &level);

	return TRUE;
}

static const GDBusPropertyTable reporter_device_properties[] = {
	{ "LinkLossAlertLevel", "s", property_get_link_loss_level },
	{ "ImmediateAlertLevel", "s", property_get_immediate_alert_level },
	{ }
};

static void state_changed(struct btd_service *service,
						btd_service_state_t old_state,
						btd_service_state_t new_state,
						void *user_data)
{
	uint8_t *linkloss_level;
	struct btd_device *device;
	const char *path;

	if (service != user_data)
		return;

	if (old_state == BTD_SERVICE_STATE_UNAVAILABLE)
		return;

	if (new_state != BTD_SERVICE_STATE_DISCONNECTED)
		return;

	device = btd_service_get_device(service);
	path = device_get_path(device);

	linkloss_level = g_hash_table_lookup(linkloss_levels,
					btd_service_get_device(service));

	info("Link Loss Alert %s", proximity_level2string(*linkloss_level));

	/*
	 * For Link Loss Service emit LinkLossAlertLevel signal indicating
	 * to the upper-layer that the link has been dropped. For Immediate
	 * Alert Service, emit ImmediateAlertLevel "NO_ALERT" indicating
	 * that the upper-layer can stop alerting if the current Immediate
	 * Alert Level value is different that "NO_ALERT".
	 */
	g_dbus_emit_property_changed(btd_get_dbus_connection(), path,
			PROXIMITY_REPORTER_INTERFACE, "LinkLossAlertLevel");

	emit_ias_alert_level(device, NO_ALERT);
}

int reporter_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	const char *path = device_get_path(device);
	uint8_t *linkloss_level, level;

	g_dbus_register_interface(btd_get_dbus_connection(), path,
				PROXIMITY_REPORTER_INTERFACE,
				NULL, NULL, reporter_device_properties,
				btd_service_ref(service),
				(GDBusDestroyFunction) btd_service_unref);

	DBG("Register Proximity Reporter for %s", path);

	linkloss_level = g_new0(uint8_t, 1);

	if (read_lls_al(device, &level) < 0)
		*linkloss_level = HIGH_ALERT;
	else
		*linkloss_level = level;

	DBG("LinkLossAlertLevel: %s", proximity_level2string(*linkloss_level));

	g_hash_table_insert(linkloss_levels, device, linkloss_level);

	btd_service_add_state_cb(state_changed, service);

	return 0;
}

void reporter_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	const char *path = device_get_path(device);

	DBG("Unregister Proximity Reporter for %s", path);

	if (linkloss_levels)
		g_hash_table_remove(linkloss_levels, device);

	g_dbus_unregister_interface(btd_get_dbus_connection(), path,
					PROXIMITY_REPORTER_INTERFACE);
}

static void ias_init(void)
{
	bt_uuid_t uuid;

	/* Immediate Alert Primary Service declaration */
	bt_uuid16_create(&uuid, IMMEDIATE_ALERT_SVC_UUID);
	immediate_service = btd_gatt_add_service(&uuid, true);

	/* Declaration and Value: Alert Level */
	bt_uuid16_create(&uuid, ALERT_LEVEL_CHR_UUID);
	immediate_alert_level = btd_gatt_add_char(&uuid,
					ATT_CHAR_PROPER_WRITE_WITHOUT_RESP,
					NULL, write_ias_al_cb, BT_SECURITY_LOW,
					BT_SECURITY_LOW, 0);

	btd_gatt_dump_local_attribute_database();
}

static void read_lls_al_cb(struct btd_device *device,
				struct btd_attribute *attr,
				btd_attr_read_result_t result,
				void *user_data)
{
	uint8_t *linkloss_level;

	DBG("Link Loss Alert Level Read cb");

	linkloss_level = g_hash_table_lookup(linkloss_levels, device);
	if (linkloss_level == NULL) {
		result(ENOENT, NULL, 0, user_data);
		return;
	}

	DBG("LinkLossAlertLevel: %s", proximity_level2string(*linkloss_level));

	result(0, linkloss_level, sizeof(uint8_t), user_data);
}

static void write_lls_al_cb(struct btd_device *device,
			struct btd_attribute *attr,
			uint8_t *value, size_t len, uint16_t offset,
			btd_attr_write_result_t result, void *user_data)
{
	uint8_t *linkloss_level;

	/*
	 * Link Loss <<Alert Level>> supports ATT Write Request only.
	 * "result" callback should be called to notify the core that a
	 * response should be sent to the remote confirming the operation.
	 */
	if (len != 1 || (value[0] != NO_ALERT && value[0] != MILD_ALERT &&
						value[0] != HIGH_ALERT)) {
		result(EINVAL, user_data);

		error("Invalid \"Alert Level\" characteristic value");
		return;
	}

	linkloss_level = g_hash_table_lookup(linkloss_levels, device);
	if (linkloss_level == NULL) {
		result(ENOENT, user_data);
		return;
	}

	result(0, user_data);

	*linkloss_level = value[0];

	DBG("LinkLossAlertLevel: %s", proximity_level2string(*linkloss_level));

	store_lls_al(device, value[0]);
}

static void lls_init(void)
{
	bt_uuid_t uuid;

	/* Link Loss Primary Service declaration */
	bt_uuid16_create(&uuid, LINK_LOSS_SVC_UUID);
	linkloss_service = btd_gatt_add_service(&uuid, true);

	/* Declaration and Value: Alert Level */
	bt_uuid16_create(&uuid, ALERT_LEVEL_CHR_UUID);
	linkloss_alert_level = btd_gatt_add_char(&uuid,
				ATT_CHAR_PROPER_READ | ATT_CHAR_PROPER_WRITE,
				read_lls_al_cb, write_lls_al_cb,
				BT_SECURITY_LOW, BT_SECURITY_LOW, 0);

	btd_gatt_dump_local_attribute_database();
}

int reporter_init(void)
{
	linkloss_levels = g_hash_table_new_full(g_direct_hash, g_direct_equal,
								NULL, g_free);

	ias_init();
	lls_init();

	return 0;
}

void reporter_exit(void)
{
	btd_gatt_remove_service(linkloss_service);
	btd_gatt_remove_service(immediate_service);

	g_hash_table_destroy(linkloss_levels);
	linkloss_levels = NULL;
}
