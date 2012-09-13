/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012 Texas Instruments, Inc.
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
#include <bluetooth/uuid.h>
#include <stdbool.h>

#include "adapter.h"
#include "device.h"
#include "profile.h"
#include "plugin.h"
#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "attrib/gatt.h"
#include "attio.h"
#include "log.h"

struct battery {
	struct btd_device	*dev;		/* Device reference */
	GAttrib			*attrib;	/* GATT connection */
	guint			attioid;	/* Att watcher id */
	struct att_range	*svc_range;	/* Battery range */
	GSList			*chars;		/* Characteristics */
};

struct characteristic {
	struct gatt_char	attr;		/* Characteristic */
	struct battery		*batt;		/* Parent Battery Service */
	GSList			*desc;		/* Descriptors */
};

struct descriptor {
	struct characteristic	*ch;		/* Parent Characteristic */
	uint16_t		handle;		/* Descriptor Handle */
	bt_uuid_t		uuid;		/* UUID */
};

static GSList *servers;

static gint cmp_device(gconstpointer a, gconstpointer b)
{
	const struct battery *batt = a;
	const struct btd_device *dev = b;

	if (dev == batt->dev)
		return 0;

	return -1;
}

static void char_free(gpointer user_data)
{
	struct characteristic *c = user_data;

	g_slist_free_full(c->desc, g_free);

	g_free(c);
}

static void battery_free(gpointer user_data)
{
	struct battery *batt = user_data;

	if (batt->chars != NULL)
		g_slist_free_full(batt->chars, char_free);

	if (batt->attioid > 0)
		btd_device_remove_attio_callback(batt->dev, batt->attioid);

	if (batt->attrib != NULL)
		g_attrib_unref(batt->attrib);

	btd_device_unref(batt->dev);
	g_free(batt->svc_range);
	g_free(batt);
}

static void discover_desc_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct characteristic *ch = user_data;
	struct att_data_list *list;
	uint8_t format;
	int i;

	if (status != 0) {
		error("Discover all characteristic descriptors failed [%s]: %s",
					ch->attr.uuid, att_ecode2str(status));
		return;
	}

	list = dec_find_info_resp(pdu, len, &format);
	if (list == NULL)
		return;

	for (i = 0; i < list->num; i++) {
		struct descriptor *desc;
		uint8_t *value;

		value = list->data[i];
		desc = g_new0(struct descriptor, 1);
		desc->handle = att_get_u16(value);
		desc->ch = ch;

		if (format == 0x01)
			desc->uuid = att_get_uuid16(&value[2]);
		else
			desc->uuid = att_get_uuid128(&value[2]);

		ch->desc = g_slist_append(ch->desc, desc);
	}

	att_data_list_free(list);
}

static void configure_battery_cb(GSList *characteristics, guint8 status,
							gpointer user_data)
{
	struct battery *batt = user_data;
	GSList *l;

	if (status != 0) {
		error("Discover Battery characteristics: %s",
							att_ecode2str(status));
		return;
	}

	for (l = characteristics; l; l = l->next) {
		struct gatt_char *c = l->data;
		struct characteristic *ch;
		uint16_t start, end;

		ch = g_new0(struct characteristic, 1);
		ch->attr.handle = c->handle;
		ch->attr.properties = c->properties;
		ch->attr.value_handle = c->value_handle;
		memcpy(ch->attr.uuid, c->uuid, MAX_LEN_UUID_STR + 1);
		ch->batt = batt;

		batt->chars = g_slist_append(batt->chars, ch);

		start = c->value_handle + 1;

		if (l->next != NULL) {
			struct gatt_char *c = l->next->data;
			if (start == c->handle)
				continue;
			end = c->handle - 1;
		} else if (c->value_handle != batt->svc_range->end)
			end = batt->svc_range->end;
		else
			continue;

		gatt_find_info(batt->attrib, start, end, discover_desc_cb, ch);
	}
}

static void attio_connected_cb(GAttrib *attrib, gpointer user_data)
{
	struct battery *batt = user_data;

	batt->attrib = g_attrib_ref(attrib);

	if (batt->chars == NULL) {
		gatt_discover_char(batt->attrib, batt->svc_range->start,
					batt->svc_range->end, NULL,
					configure_battery_cb, batt);
	}
}

static void attio_disconnected_cb(gpointer user_data)
{
	struct battery *batt = user_data;

	g_attrib_unref(batt->attrib);
	batt->attrib = NULL;
}

static gint primary_uuid_cmp(gconstpointer a, gconstpointer b)
{
	const struct gatt_primary *prim = a;
	const char *uuid = b;

	return g_strcmp0(prim->uuid, uuid);
}

static int battery_register(struct btd_device *device)
{
	struct battery *batt;
	struct gatt_primary *prim;
	GSList *primaries, *l;

	primaries = btd_device_get_primaries(device);

	while ((l = g_slist_find_custom(primaries, BATTERY_SERVICE_UUID,
							primary_uuid_cmp))) {
		prim = l->data;

		batt = g_new0(struct battery, 1);
		batt->dev = btd_device_ref(device);

		batt->svc_range = g_new0(struct att_range, 1);
		batt->svc_range->start = prim->range.start;
		batt->svc_range->end = prim->range.end;

		servers = g_slist_prepend(servers, batt);

		batt->attioid = btd_device_add_attio_callback(device,
			attio_connected_cb, attio_disconnected_cb, batt);

		primaries = g_slist_remove(primaries, prim);
	}

	return 0;
}

static void battery_unregister(struct btd_device *device)
{
	struct battery *batt;
	GSList *l;

	while ((l = g_slist_find_custom(servers, device, cmp_device))) {
		batt = l->data;
		servers = g_slist_remove(servers, batt);

		battery_free(batt);
	}
}

static int battery_driver_probe(struct btd_profile *p,
						struct btd_device *device,
						GSList *uuids)
{
	return battery_register(device);
}

static void battery_driver_remove(struct btd_profile *p,
						struct btd_device *device)
{
	battery_unregister(device);
}

static struct btd_profile battery_profile = {
	.name		= "battery",
	.remote_uuids	= BTD_UUIDS(BATTERY_SERVICE_UUID),
	.device_probe	= battery_driver_probe,
	.device_remove	= battery_driver_remove
};

static int battery_manager_init(void)
{
	return btd_profile_register(&battery_profile);
}

static void battery_manager_exit(void)
{
	btd_profile_unregister(&battery_profile);
}

BLUETOOTH_PLUGIN_DEFINE(battery, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
				battery_manager_init, battery_manager_exit)
