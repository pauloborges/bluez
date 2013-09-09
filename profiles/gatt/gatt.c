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
#include <errno.h>

#include "lib/uuid.h"
#include "plugin.h"
#include "adapter.h"
#include "device.h"
#include "profile.h"
#include "service.h"
#include "gatt.h"
#include "attrib/att.h"
#include "log.h"

struct service_data {
	unsigned int state_id;
	struct btd_attribute *name;
	struct btd_attribute *appearance;
};

static void read_device_name_chr_cb(int err, uint8_t *value, size_t len,
							void *user_data)
{
	struct btd_device *device = user_data;

	if (err) {
		error("<<Device Name>> read: %s", strerror(err));
		return;
	}

	value[len - 1] = '\0';

	DBG("<<Device Name>>: %s", value);
	btd_device_device_set_name(device, (const char *) value);
}

static void read_appearance_chr_cb(int err, uint8_t *value, size_t len,
							void *user_data)
{
	struct btd_device *device = user_data;
	uint16_t appearance;

	if (err) {
		error("<<Appearance>> read: %s", strerror(err));
		return;
	}

	appearance = att_get_u16(value);

	DBG("Device <<Appearance>>: 0x%04X", appearance);

	device_set_appearance(device, appearance);
}

static void refresh_gap(struct btd_device *device, struct service_data *data)
{
	btd_gatt_read_attribute(device, data->name, read_device_name_chr_cb,
								device);

	btd_gatt_read_attribute(device, data->appearance,
						read_appearance_chr_cb, device);
}

static bool service_changed(uint8_t *value, size_t len, void *user_data)
{
	uint16_t start, end;

	/* FIXME: Missing attribute discovery */

	DBG("Remote Service Changed: %zu", len);

	if (len != 4)
		return true;

	start = att_get_u16(&value[0]);
	end = att_get_u16(&value[2]);

	DBG("Service Changed: 0x%04x 0x%04x", start, end);

	return true;
}

static void state_changed(struct btd_service *service,
						btd_service_state_t old_state,
						btd_service_state_t new_state,
						void *user_data)
{
	struct btd_device *device = btd_service_get_device(service);
	struct service_data *data;

	if (service != user_data)
		return;

	if (new_state != BTD_SERVICE_STATE_CONNECTED)
		return;

	data = btd_service_get_user_data(service);
	refresh_gap(device, data);
}

static int gatt_driver_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct service_data *data;
	struct btd_attribute *decl, *name, *appearance, *attr;
	GSList *list;
	bt_uuid_t uuid;

	/* Generic Access Profile */
	bt_uuid16_create(&uuid, GENERIC_ACCESS_PROFILE_ID);
	list = btd_gatt_get_services(device, &uuid);
	if (!list) {
		error("<<GAP Service>> is mandatory");
		return -EIO;
	}

	decl = list->data;
	g_slist_free(list);

	bt_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	list = btd_gatt_get_chars_decl(device, decl, &uuid);
	if (!list) {
		error("<<Device Name>> characteristic is mandatory");
		return -EIO;
	}

	name = btd_gatt_get_char_value(device, list->data);
	g_slist_free(list);

	bt_uuid16_create(&uuid, GATT_CHARAC_APPEARANCE);
	list = btd_gatt_get_chars_decl(device, decl, &uuid);
	if (!list) {
		error("<<Appearance>> characteristic is mandatory");
		return -EIO;
	}

	appearance = btd_gatt_get_char_value(device, list->data);
	g_slist_free(list);

	/* Generic Attribute Profile */
	bt_uuid16_create(&uuid, GENERIC_ATTRIB_PROFILE_ID);
	list = btd_gatt_get_services(device, &uuid);
	if (!list) {
		error("<<GATT Service>> is mandatory");
		return -EIO;
	}

	/* Get Service Changed declaration: Optional in the client */
	decl = list->data;
	g_slist_free(list);
	bt_uuid16_create(&uuid, GATT_CHARAC_SERVICE_CHANGED);
	list = btd_gatt_get_chars_decl(device, decl, &uuid);
	if (!list) {
		DBG("<<GATT Service>>: Service Changed not found");
		goto done;
	}

	attr = btd_gatt_get_char_value(device, list->data);
	g_slist_free(list);

	/* Monitor remote Service Changed indication */
	btd_gatt_add_notifier(attr, service_changed, device);

done:
	data = g_new0(struct service_data, 1);
	data->name = name;
	data->appearance = appearance;
	data->state_id = btd_service_add_state_cb(state_changed, service);

	btd_service_set_user_data(service, data);

	return 0;
}

static void gatt_driver_remove(struct btd_service *service)
{
	struct service_data *data = btd_service_get_user_data(service);

	DBG("Removing device");

	btd_service_remove_state_cb(data->state_id);
	g_free(data);
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

static int gatt_profile_init(void)
{
	DBG("Initializing GATT/GAP plugin");

	btd_profile_register(&gatt_profile);

	return 0;
}

static void gatt_profile_exit(void)
{
	DBG("Finishing GATT/GAP plugin");

	btd_profile_unregister(&gatt_profile);
}

BLUETOOTH_PLUGIN_DEFINE(gatt, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
					gatt_profile_init, gatt_profile_exit)
