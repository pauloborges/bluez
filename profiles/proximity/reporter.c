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

#include "proximity.h"
#include "reporter.h"

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

static void emit_alert_level(struct btd_device *device, uint8_t level)
{
	const char *path;

	if (immediate_level == level)
		return;

	immediate_level = level;

	path = device_get_path(device);

	g_dbus_emit_property_changed(btd_get_dbus_connection(), path,
			PROXIMITY_REPORTER_INTERFACE, "ImmediateAlertLevel");
}

static void write_ial_cb(struct btd_device *device,
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
		emit_alert_level(device, NO_ALERT);
		return;
	}

	DBG("Immediate Alert Level: 0x%02x", value[0]);

	emit_alert_level(device, value[0]);
}

static gboolean property_get_link_loss_level(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	/* FIXME: per device alert level */
	const char *level = proximity_level2string(NO_ALERT);

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

	if (service != user_data)
		return;

	linkloss_level = btd_service_get_user_data(service);

	if (new_state == BTD_SERVICE_STATE_DISCONNECTED)
		info("Link loss alert %s",
				proximity_level2string(*linkloss_level));
}

int reporter_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	const char *path = device_get_path(device);
	uint8_t *linkloss_level;

	g_dbus_register_interface(btd_get_dbus_connection(), path,
				PROXIMITY_REPORTER_INTERFACE,
				NULL, NULL, NULL,
				btd_device_ref(device),
				(GDBusDestroyFunction) btd_device_unref);

	DBG("Register Proximity Reporter for %s", path);

	linkloss_level = g_new0(uint8_t, 1);
	*linkloss_level = NO_ALERT;

	btd_service_set_user_data(service, linkloss_level);

	btd_service_add_state_cb(state_changed, service);

	return 0;
}

void reporter_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	const char *path = device_get_path(device);

	DBG("Unregister Proximity Reporter for %s", path);

	g_dbus_unregister_interface(btd_get_dbus_connection(), path,
					PROXIMITY_REPORTER_INTERFACE);

	g_free(btd_service_get_user_data(service));
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
					NULL, write_ial_cb, BT_SECURITY_LOW,
					BT_SECURITY_LOW, 0);

	btd_gatt_dump_local_attribute_database();
}

static void read_al_cb(struct btd_device *device, struct btd_attribute *attr,
			btd_attr_read_result_t result, void *user_data)
{
	DBG("Link Loss Alert Level Read cb");
}

static void write_al_cb(struct btd_device *device,
			struct btd_attribute *attr,
			uint8_t *value, size_t len, uint16_t offset,
			btd_attr_write_result_t result, void *user_data)
{
	if (len != 1 || (value[0] != NO_ALERT && value[0] != MILD_ALERT &&
						value[0] != HIGH_ALERT)) {
		error("Invalid \"Alert Level\" characteristic value");
		return;
	}

	DBG("Link Loss Alert Level Write cb");
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
				read_al_cb, write_al_cb,
				BT_SECURITY_LOW, BT_SECURITY_LOW, 0);

	btd_gatt_dump_local_attribute_database();
}

int reporter_init(void)
{
	ias_init();
	lls_init();

	return 0;
}

void reporter_exit(void)
{
	btd_gatt_remove_service(linkloss_service);
	btd_gatt_remove_service(immediate_service);
}
