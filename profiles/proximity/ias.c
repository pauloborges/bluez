/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Instituto Nokia de Tecnologia - INdT
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
#include <stddef.h>
#include <stdint.h>

#include <glib.h>
#include <gdbus.h>

#include "lib/uuid.h"
#include "attrib/att.h"
#include "dbus-common.h"

#include "adapter.h"
#include "device.h"
#include "log.h"

#include "gatt.h"
#include "proximity.h"
#include "ias.h"

static struct btd_attribute *ias = NULL;
static struct btd_attribute *ial = NULL;

/*
 * IAS defines a single instance of the <<Alert Level>>
 * characteristic. The object path used to emit the signal
 * defines only which device wrote in the characteristic.
 * TODO: multiple adapters are not properly addressed.
 */
static uint8_t ias_level = NO_ALERT;

static void emit_alert_level(struct btd_device *device, uint8_t level)
{
	const char *path;

	if (ias_level == level)
		return;

	ias_level = level;

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
		return;
	}

	DBG("Immediate Alert Level: 0x%02x", value[0]);

	emit_alert_level(device, value[0]);
}

void ias_init(void)
{
	bt_uuid_t uuid;

	/* Immediate Alert Primary Service declaration */
	bt_uuid16_create(&uuid, IMMEDIATE_ALERT_SVC_UUID);
	ias = btd_gatt_add_service(&uuid, true);

	/* Declaration and Value: Alert Level */
	bt_uuid16_create(&uuid, ALERT_LEVEL_CHR_UUID);
	ial = btd_gatt_add_char(&uuid, ATT_CHAR_PROPER_WRITE_WITHOUT_RESP,
							NULL, write_ial_cb,
							BT_SECURITY_LOW,
							BT_SECURITY_LOW,
							0);

	btd_gatt_dump_local_attribute_database();
}

void ias_exit(void)
{
	btd_gatt_remove_service(ias);
}

const char *ias_get_level(void)
{
	return proximity_level2string(ias_level);
}
