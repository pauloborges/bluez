/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Nordic Semiconductor Inc.
 *  Copyright (C) 2012  Instituto Nokia de Tecnologia - INdT
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

#include "lib/uuid.h"
#include "log.h"
#include "plugin.h"
#include "adapter.h"
#include "device.h"
#include "profile.h"
#include "service.h"
#include "attrib/att.h"
#include "gatt.h"

#define SCAN_PARAMETERS_UUID128		"00001813-0000-1000-8000-00805f9b34fb"
#define SCAN_PARAMETERS_UUID		0x1813

#define SCAN_INTERVAL_WIN_UUID		0x2A4F
#define SCAN_REFRESH_UUID		0x2A31

/*
 * TODO: Use dynamic value defined by the upper
 * layer or based on the active profiles.
 */
#define SCAN_INTERVAL		0x0060
#define SCAN_WINDOW		0x0030

#define SERVER_REQUIRES_REFRESH	0x00

struct scan {
	struct btd_attribute *interval;
	struct btd_attribute *refresh;
	unsigned int state_id;
};

static bool refresh_cb(uint8_t *value, size_t len, void *user_data)
{
	struct btd_service *service = user_data;
	struct btd_device *device = btd_service_get_device(service);
	struct scan *scan = btd_service_get_user_data(service);
	uint8_t params[4];

	DBG("Server requires refresh? %d", value[0]);

	if (value[0] != SERVER_REQUIRES_REFRESH)
		return true;

	att_put_u16(SCAN_INTERVAL, &params[0]);
	att_put_u16(SCAN_WINDOW, &params[2]);

	btd_gatt_write_attribute(device, scan->interval,
				params, sizeof(params), 0, NULL, NULL);

	return true;
}

static void state_changed(struct btd_service *service,
				btd_service_state_t old_state,
				btd_service_state_t new_state,
				void *user_data)
{
	struct btd_device *device = btd_service_get_device(service);
	struct scan *scan;
	uint8_t params[4];

	if (service != user_data)
		return;

	if (new_state != BTD_SERVICE_STATE_CONNECTED)
		return;

	scan = btd_service_get_user_data(service);
	/* If Refresh exists: write interval when notification arrives */
	if (scan->refresh && device_is_bonded(device))
		return;

	att_put_u16(SCAN_INTERVAL, &params[0]);
	att_put_u16(SCAN_WINDOW, &params[2]);

	DBG("Writting Scan Parameters ...");

	btd_gatt_write_attribute(device, scan->interval,
			params, sizeof(params), 0, NULL, NULL);
}

static void scan_param_remove(struct btd_service *service)
{
	struct scan *scan = btd_service_get_user_data(service);

	DBG("Removing Scan Parameters");

	btd_service_remove_state_cb(scan->state_id);

	g_free(scan);
}

static int scan_param_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct btd_attribute *scan_decl, *interval, *refresh;
	struct scan *scan;
	GSList *list;
	bt_uuid_t uuid;

	DBG("Probing Scan Parameters");

	/* Accessing Scan Parameters Service declaration */
	bt_uuid16_create(&uuid, SCAN_PARAMETERS_UUID);
	list = btd_gatt_get_services(device, &uuid);
	if (list == NULL) {
		DBG("Scan Parameters: Service missing!");
		return -1;
	}

	scan_decl = list->data;
	g_slist_free(list);

	/* Accessing Scan Interval Window declaration */
	bt_uuid16_create(&uuid, SCAN_INTERVAL_WIN_UUID);
	list = btd_gatt_get_chars_decl(device, scan_decl, &uuid);
	if (list == NULL) {
		DBG("Scan Parameters: Mandatory Interval Window missing!");
		return -1;
	}

	/* Accessing Scan Interval Window value */
	interval = btd_gatt_get_char_value(device, list->data);
	g_slist_free(list);
	if (interval == NULL) {
		DBG("Scan Parameters: Mandatory Interval Window missing!");
		return -1;
	}

	/* Accessing Scan Refresh declaration */
	bt_uuid16_create(&uuid, SCAN_REFRESH_UUID);
	list = btd_gatt_get_chars_decl(device, scan_decl, &uuid);
	if (list == NULL) {
		DBG("Scan Parameters: Refresh (Optional) not supported");
		return 0;
	}

	/* Accessing Scan Refresh value */
	refresh = btd_gatt_get_char_value(device, list->data);
	g_slist_free(list);

	if (refresh)
		btd_gatt_add_notifier(refresh, refresh_cb, service);

	scan = g_new0(struct scan, 1);
	scan->interval = interval;
	scan->refresh = refresh;
	scan->state_id = btd_service_add_state_cb(state_changed, service);

	btd_service_set_user_data(service, scan);

	return 0;
}

static struct btd_profile scan_profile = {
	.name = "Scan Parameters Client Driver",
	.remote_uuid = SCAN_PARAMETERS_UUID128,
	.device_probe = scan_param_probe,
	.device_remove = scan_param_remove,
};

static int scan_param_init(void)
{
	return btd_profile_register(&scan_profile);
}

static void scan_param_exit(void)
{
	btd_profile_unregister(&scan_profile);
}

BLUETOOTH_PLUGIN_DEFINE(scanparam, VERSION,
			BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
			scan_param_init, scan_param_exit)
