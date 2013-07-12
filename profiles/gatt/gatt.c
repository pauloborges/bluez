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

#include <glib.h>

#include "lib/uuid.h"
#include "plugin.h"
#include "adapter.h"
#include "device.h"
#include "profile.h"
#include "service.h"
#include "gatt.h"
#include "attrib/att.h"
#include "log.h"

static GSList *devices = NULL;

static void read_device_name_chr_cb(int err, uint8_t *value, size_t len,
							void *user_data)
{
	struct btd_device *device = user_data;

	if (err) {
		error("Error reading <<Device Name>>: %s", strerror(err));
		return;
	}

	value[len - 1] = '\0';
	btd_device_device_set_name(device, (const char *) value);
}

static void read_device_name_chr(struct btd_device *device,
						struct btd_attribute *gap)
{
	struct btd_attribute *chr, *chr_value;
	bt_uuid_t uuid;
	GSList *list;

	bt_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	list = btd_gatt_get_chars_decl(device, gap, &uuid);
	if (!list) {
		error("<<Device Name>> characteristic is mandatory");
		return;
	}

	chr = list->data;
	g_slist_free(list);

	chr_value = btd_gatt_get_char_value(device, chr);
	btd_gatt_read_attribute(device, chr_value, read_device_name_chr_cb,
								device);
}

static void read_appearance_chr_cb(int err, uint8_t *value, size_t len,
							void *user_data)
{
	struct btd_device *device = user_data;
	uint16_t appearance;

	if (err) {
		error("Error reading <<Appearance>>: %s", strerror(err));
		return;
	}

	appearance = att_get_u16(value);
	device_set_appearance(device, appearance);
}

static void read_appearance_chr(struct btd_device *device,
						struct btd_attribute *gap)
{
	struct btd_attribute *chr, *chr_value;
	bt_uuid_t uuid;
	GSList *list;

	bt_uuid16_create(&uuid, GATT_CHARAC_APPEARANCE);
	list = btd_gatt_get_chars_decl(device, gap, &uuid);
	if (!list) {
		error("<<Appearance>> characteristic is mandatory");
		return;
	}

	chr = list->data;
	g_slist_free(list);

	chr_value = btd_gatt_get_char_value(device, chr);
	btd_gatt_read_attribute(device, chr_value, read_appearance_chr_cb,
								device);
}

static void find_gap(struct btd_device *device)
{
	struct btd_attribute *gap;
	bt_uuid_t uuid;
	GSList *list;

	bt_uuid16_create(&uuid, GENERIC_ACCESS_PROFILE_ID);
	list = btd_gatt_get_services(device, &uuid);
	if (!list) {
		error("<<GAP Service>> is mandatory");
		return;
	}

	gap = list->data;
	g_slist_free(list);

	read_device_name_chr(device, gap);
	read_appearance_chr(device, gap);
}

static void ccc_written(int err, void *user_data)
{
	DBG("Service Changed CCC enabled");
}

static bool service_changed(uint8_t *value, size_t len, void *user_data)
{
	uint16_t start, end;

	DBG("Service Changed: %zu", len);

	if (len != 4)
		return true;

	start = att_get_u16(&value[0]);
	end = att_get_u16(&value[2]);

	DBG("Service Changed: 0x%04x 0x%04x", start, end);

	return true;
}

static void find_gatt(struct btd_device *device)
{
	struct btd_attribute *gatt, *attr;
	bt_uuid_t uuid;
	GSList *list;
	uint8_t ccc[2];

	bt_uuid16_create(&uuid, GENERIC_ATTRIB_PROFILE_ID);
	list = btd_gatt_get_services(device, &uuid);
	if (!list) {
		error("<<GATT Service>> is mandatory");
		return;
	}

	/* Get Service Changed declaration */
	gatt = list->data;
	g_slist_free(list);
	bt_uuid16_create(&uuid, GATT_CHARAC_SERVICE_CHANGED);
	list = btd_gatt_get_chars_decl(device, gatt, &uuid);
	if (!list) {
		DBG("<<GATT Service>>: Service Changed not found");
		return;
	}

	attr = list->data;
	g_slist_free(list);

	/* Get Service Changed CCC */
	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	attr = btd_gatt_get_char_desc(device, attr, &uuid);
	if (attr == NULL) {
		DBG("<<GATT Service>>: Service Changed CCC not found");
		return;
	}

	DBG("Enabling Service Changed CCC on handle %p", attr);

	/* Enable indication */
	att_put_u16(0x0002, &ccc);
	btd_gatt_write_attribute(device, attr, ccc, sizeof(ccc), 0,
							ccc_written, NULL);

	btd_gatt_add_notifier(attr, service_changed, device);
}

static void state_changed(struct btd_service *service,
						btd_service_state_t old_state,
						btd_service_state_t new_state,
						void *user_data)
{
	struct btd_device *device = btd_service_get_device(service);

	if (service != user_data)
		return;

	if (new_state != BTD_SERVICE_STATE_CONNECTED)
		return;

	find_gap(device);
	find_gatt(device);
}

static int gatt_driver_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);

	DBG("Probing device");

	btd_service_add_state_cb(state_changed, service);

	devices = g_slist_append(devices, device);

	return 0;
}

static void gatt_driver_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);

	DBG("Removing device");

	devices = g_slist_remove(devices, device);
}

static struct btd_profile gatt_profile = {
	.name		= "gatt-gap-profile",
	.remote_uuid	= GATT_UUID,
	.device_probe	= gatt_driver_probe,
	.device_remove	= gatt_driver_remove,
	.connect	= btd_gatt_connect,
	.disconnect	= btd_gatt_disconnect,
	.auto_connect	= true
};

static int gatt_init(void)
{
	DBG("Initializing GATT/GAP plugin");

	btd_profile_register(&gatt_profile);

	return 0;
}

static void gatt_exit(void)
{
	DBG("Finishing GATT/GAP plugin");

	btd_profile_unregister(&gatt_profile);
}

BLUETOOTH_PLUGIN_DEFINE(gatt, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
					gatt_init, gatt_exit)
