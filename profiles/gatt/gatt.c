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

struct gatt_device {
	struct btd_device *dvc;
	struct btd_attribute *svc_chd_chr;
	unsigned int svc_chd_notif_id;
};

static GSList *devices = NULL;

static void gatt_device_destroy(struct gatt_device *device)
{
	if (device->svc_chd_notif_id)
		btd_gatt_remove_notifier(device->dvc, device->svc_chd_chr,
						device->svc_chd_notif_id);

	g_free(device);
}

static gint gatt_device_cmp(gconstpointer a, gconstpointer b)
{
	const struct gatt_device *device = a;
	const struct btd_device *dvc = b;

	return device->dvc != dvc;
}

static void read_device_name_chr_cb(int err, uint8_t *value, size_t len,
							void *user_data)
{
	struct btd_device *device = user_data;

	if (err) {
		error("Error reading <<Device Name>>: %d", err);
		return;
	}

	value[len - 1] = '\0';
	device_set_name(device, (char *) value);
}

static void read_device_name_chr(struct gatt_device *device, GList *attrib_db,
						struct btd_attribute *gap)
{
	struct btd_attribute *chr, *chr_value;
	bt_uuid_t uuid;
	GSList *list;

	bt_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	list = btd_gatt_get_chars_decl(attrib_db, gap, &uuid);
	if (!list) {
		error("<<Device Name>> characteristic is mandatory");
		return;
	}

	chr = list->data;

	chr_value = btd_gatt_get_char_value(attrib_db, chr);
	btd_gatt_read_attribute(device->dvc, chr_value,
					read_device_name_chr_cb, device);
}

static void read_appearance_chr_cb(int err, uint8_t *value, size_t len,
							void *user_data)
{
	struct gatt_device *device = user_data;
	uint16_t appearance;

	if (err) {
		error("Error reading <<Appearance>>: %d", err);
		return;
	}

	appearance = att_get_u16(value);
	device_set_appearance(device->dvc, appearance);
}

static void read_appearance_chr(struct gatt_device *device, GList *attrib_db,
						struct btd_attribute *gap)
{
	struct btd_attribute *chr, *chr_value;
	bt_uuid_t uuid;
	GSList *list;

	bt_uuid16_create(&uuid, GATT_CHARAC_APPEARANCE);
	list = btd_gatt_get_chars_decl(attrib_db, gap, &uuid);
	if (!list) {
		error("<<Appearance>> characteristic is mandatory");
		return;
	}

	chr = list->data;

	chr_value = btd_gatt_get_char_value(attrib_db, chr);
	btd_gatt_read_attribute(device->dvc, chr_value, read_appearance_chr_cb,
								device);
}

static void find_gap(struct gatt_device *device)
{
	struct btd_attribute *gap;
	GList *attrib_db;
	bt_uuid_t uuid;
	GSList *list;

	attrib_db = btd_device_get_attribute_database(device->dvc);

	bt_uuid16_create(&uuid, GENERIC_ACCESS_PROFILE_ID);
	list = btd_gatt_get_services(attrib_db, &uuid);
	if (!list) {
		error("<<GAP Service>> is mandatory");
		return;
	}

	gap = list->data;

	read_device_name_chr(device, attrib_db, gap);
	read_appearance_chr(device, attrib_db, gap);
}

static bool service_changed_chr_changed_cb(uint8_t *value, size_t len,
							void *user_data)
{
	/* TODO Handle Service Changed indication */
	DBG("<<Service Changed>> INDICATION received");

	return true;
}

static void read_service_changed_chr(struct gatt_device *device,
						GList *attrib_db,
						struct btd_attribute *gatt)
{
	struct btd_attribute *dsc;
	bt_uuid_t uuid;
	GSList *list;

	bt_uuid16_create(&uuid, GATT_CHARAC_SERVICE_CHANGED);
	list = btd_gatt_get_chars_decl(attrib_db, gatt, &uuid);
	if (!list) {
		error("<<Service Changed>> characteristic is mandatory");
		return;
	}

	device->svc_chd_chr = list->data;

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	dsc = btd_gatt_get_char_desc(attrib_db, device->svc_chd_chr, &uuid);

	device->svc_chd_notif_id = btd_gatt_add_notifier(device->dvc, dsc,
				service_changed_chr_changed_cb, device);
}

static void find_gatt(struct gatt_device *device)
{
	struct btd_attribute *gatt;
	GList *attrib_db;
	bt_uuid_t uuid;
	GSList *list;

	attrib_db = btd_device_get_attribute_database(device->dvc);

	bt_uuid16_create(&uuid, GENERIC_ATTRIB_PROFILE_ID);
	list = btd_gatt_get_services(attrib_db, &uuid);
	if (!list) {
		error("<<GATT Service>> is mandatory");
		return;
	}

	gatt = list->data;

	read_service_changed_chr(device, attrib_db, gatt);
}

static int gatt_driver_probe(struct btd_service *service)
{
	struct btd_device *dvc = btd_service_get_device(service);
	struct gatt_device *device;

	DBG("Probing device");

	device = g_new0(struct gatt_device, 1);
	device->dvc = dvc;

	find_gap(device);
	find_gatt(device);

	devices = g_slist_append(devices, device);

	return 0;
}

static void gatt_driver_remove(struct btd_service *service)
{
	struct btd_device *dvc = btd_service_get_device(service);
	struct gatt_device *device;
	GSList *list;

	DBG("Removing device");

	list = g_slist_find_custom(devices, dvc, gatt_device_cmp);
	if (list == NULL)
		return;

	device = list->data;
	devices = g_slist_remove(devices, device);
	gatt_device_destroy(device);
}

static struct btd_profile gatt_profile = {
	.name		= "gatt-gap-profile",
	.remote_uuid	= GATT_UUID,
	.device_probe	= gatt_driver_probe,
	.device_remove	= gatt_driver_remove
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