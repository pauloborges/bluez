/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010  Nokia Corporation
 *  Copyright (C) 2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <bluetooth/sdp.h>

typedef bool (*gatt_cb_t) (uint8_t status, GSList *l, void *user_data);
typedef void (*gatt_exchange_mtu_cb_t) (uint8_t status, uint16_t mtu,
							void *user_data);
typedef void (*gatt_read_char_cb_t) (uint8_t status, const uint8_t *value,
						size_t vlen, void *user_data);
typedef void (*gatt_write_char_cb_t) (uint8_t status, void *user_data);

typedef void (*gatt_func_by_type_t) (uint8_t status, uint16_t handle,
					uint8_t *value, size_t vlen,
					void *user_data);

typedef void (*gatt_func_by_info_t) (uint8_t status, uint16_t handle,
					bt_uuid_t *type, void *user_data);

struct gatt_primary {
	char uuid[MAX_LEN_UUID_STR + 1];
	gboolean changed;
	struct att_range range;
};

struct gatt_included {
	char uuid[MAX_LEN_UUID_STR + 1];
	uint16_t handle;
	struct att_range range;
};

struct gatt_char {
	char uuid[MAX_LEN_UUID_STR + 1];
	uint16_t handle;
	uint8_t properties;
	uint16_t value_handle;
};

struct gatt_char_desc {
	uint16_t handle;
	bt_uuid_t uuid;
};

struct gatt_att {
	uint16_t handle;
	uint8_t *value;
	size_t size;
};

guint gatt_discover_primary(GAttrib *attrib, bt_uuid_t *uuid, gatt_cb_t func,
							gpointer user_data);

unsigned int gatt_find_included(GAttrib *attrib, uint16_t start, uint16_t end,
					gatt_cb_t func, gpointer user_data);

guint gatt_discover_char(GAttrib *attrib, uint16_t start, uint16_t end,
					bt_uuid_t *uuid, gatt_cb_t func,
					gpointer user_data);

guint gatt_read_char(GAttrib *attrib, uint16_t handle, gatt_read_char_cb_t func,
							void *user_data);

guint gatt_write_char(GAttrib *attrib, uint16_t handle, const uint8_t *value,
					size_t vlen, gatt_write_char_cb_t func,
					void *user_data);

guint gatt_discover_char_desc(GAttrib *attrib, uint16_t start, uint16_t end,
					gatt_cb_t func, gpointer user_data);

guint gatt_write_cmd(GAttrib *attrib, uint16_t handle, uint8_t *value, int vlen,
				GDestroyNotify notify, gpointer user_data);

guint gatt_read_char_by_uuid(GAttrib *attrib, uint16_t start, uint16_t end,
						bt_uuid_t *uuid, gatt_cb_t func,
						gpointer user_data);

guint gatt_exchange_mtu(GAttrib *attrib, uint16_t mtu,
				gatt_exchange_mtu_cb_t func, void *user_data);

gboolean gatt_parse_record(const sdp_record_t *rec,
					uuid_t *prim_uuid, uint16_t *psm,
					uint16_t *start, uint16_t *end);

guint gatt_foreach_by_type(GAttrib *attrib, uint16_t start, uint16_t end,
				bt_uuid_t *type, gatt_func_by_type_t func,
				void *user_data);

unsigned int gatt_foreach_by_info(GAttrib *attrib, uint16_t start,
				uint16_t end, gatt_func_by_info_t func,
				void *user_data);
