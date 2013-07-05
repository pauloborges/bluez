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
#include "lls.h"

static struct btd_attribute *lls = NULL;
static struct btd_attribute *al = NULL;

static uint8_t lls_level = NO_ALERT;

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
	DBG("Link Loss Alert Level Write cb");
}

void lls_init(void)
{
	bt_uuid_t uuid;

	/* Link Loss Primary Service declaration */
	bt_uuid16_create(&uuid, LINK_LOSS_SVC_UUID);
	lls = btd_gatt_add_service(&uuid, true);

	/* Declaration and Value: Alert Level */
	bt_uuid16_create(&uuid, ALERT_LEVEL_CHR_UUID);
	al = btd_gatt_add_char(&uuid, ATT_CHAR_PROPER_READ | ATT_CHAR_PROPER_WRITE,
							read_al_cb,
							write_al_cb,
							BT_SECURITY_LOW,
							BT_SECURITY_LOW,
							0);

	btd_gatt_dump_local_attribute_database();
}

void lls_exit(void)
{
	btd_gatt_remove_service(lls);
}

const char *lls_get_alert_level(void)
{
	return proximity_level2string(lls_level);
}
