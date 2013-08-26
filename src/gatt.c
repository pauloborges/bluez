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

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <errno.h>

#include <glib.h>

#include "adapter.h"
#include "device.h"
#include "service.h"

#include "log.h"
#include "error.h"
#include "lib/uuid.h"
#include "btio.h"
#include "textfile.h"
#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "attrib/gatt_lib.h"

#include "gatt-dbus.h"
#include "gatt.h"

/*
 * Internal timeout for asynchronous operations. Prevents
 * client that never calls the result callback.
 */
#define TRANSACTION_TIMEOUT	20

/*
 * Ref. Bluetooth Core SPEC page 1902, Table 3.11: Client
 * Characteristic Configuration bit field definition
 */
#define CCC_NOTIFICATION_BIT	(1 << 0)
#define CCC_INDICATION_BIT	(1 << 1)

/* Common GATT UUIDs */
static const bt_uuid_t primary_uuid  = { .type = BT_UUID16,
					.value.u16 = GATT_PRIM_SVC_UUID };
static const bt_uuid_t secondary_uuid  = { .type = BT_UUID16,
					.value.u16 = GATT_SND_SVC_UUID };
static const bt_uuid_t chr_uuid = { .type = BT_UUID16,
					.value.u16 = GATT_CHARAC_UUID };

struct btd_attribute {
	uint16_t handle;
	bt_uuid_t type;
	btd_attr_read_t read_cb;
	btd_attr_write_t write_cb;
	int read_sec;
	int write_sec;
	int key_size;
	GHashTable *notifiers;
	uint16_t value_len;
	uint8_t value[0];
};

struct notifier {
	btd_attr_value_t value_cb;
	void *user_data;
};

struct remote_read_data {
	btd_attr_read_result_t func;
	void *user_data;
};

struct remote_write_data {
	btd_attr_write_result_t func;
	uint8_t *value;
	size_t vlen;
	uint16_t offset;
	void *user_data;
};

struct att_transaction {
	struct btd_attribute *attr;
	struct btd_device *device;
};

struct attr_notif_data {
	btd_attr_write_result_t func;
	void *user_data;
};

struct read_by_type_transaction {
	struct btd_device *device;
	GList *match;			/* List of matching attributes */
	size_t vlen;			/* Pattern: length of each value */
	size_t olen;			/* Output PDU length */
	uint8_t opdu[0];		/* Output PDU */
};

struct find_info {
	struct btd_device *device;
	int refcount;
};

struct gatt_device {
	GAttrib *attrib;
	GList *database;		/* Remote attributes */
	GIOChannel *io;			/* While GAttrib is not created */
	GSList *svc_objs;      		/* Service object paths */
	GHashTable *chr_objs;  		/* Map: { Handle : char path } */
	GSList *services;		/* Refs for btd_service */
	unsigned int channel_id;	/* ERR and HUP watch */
	unsigned int attrib_id;		/* GAttrib events/cmds handler */
	gboolean out;			/* Outgoing or incoming connection */

	/*
	 * Callback for notifying that service discovery
	 * has finished, so caller can destroy resources.
	 */
	GDestroyNotify destroy;
	void *user_data;

	/*
	 * Local services overlay: per device attributes. Stores
	 * << CCC >> descriptor values changed by the remote.
	 */
	char *ccc_fname;
	GKeyFile *ccc_keyfile;
};

static GList *local_attribute_db = NULL;
static unsigned int next_notifier_id = 1;
static uint16_t next_handle = 1;
static GIOChannel *bredr_io = NULL;
static GIOChannel *le_io = NULL;
static GHashTable *gatt_devices = NULL;

static uint8_t errno_to_att(int err)
{
	switch (err) {
	case EACCES:
		return ATT_ECODE_AUTHORIZATION;
	case EINVAL:
		return ATT_ECODE_INVAL_ATTR_VALUE_LEN;
	default:
		return ATT_ECODE_UNLIKELY;
	}
}

static void print_attribute(gpointer a, gpointer b)
{
	struct btd_attribute *attr = a;
	char type[MAX_LEN_UUID_STR];
	char value_str[attr->value_len * 2 + 1];
	int i;

	memset(type, 0, sizeof(type));
	bt_uuid_to_string(&attr->type, type, sizeof(type));

	memset(value_str, 0, sizeof(value_str));
	for (i = 0; i < attr->value_len; i++)
		sprintf(&value_str[i * 2], "%02X", attr->value[i]);

	DBG("handle: 0x%04x Type: %s read_cb: %p write_cb: %p value: %s",
			attr->handle, type, attr->read_cb, attr->write_cb, value_str);
}

void btd_gatt_dump_local_attribute_database(void)
{
	DBG("======== begin =========");
	g_list_foreach(local_attribute_db, print_attribute, NULL);
	DBG("========= end ==========");
}

static void dump_database(GList *database)
{
	DBG("======== begin =========");
	g_list_foreach(database, print_attribute, NULL);
	DBG("========= end ==========");
}

static void send_error(GAttrib *attrib, uint8_t opcode, uint16_t handle,
								uint8_t ecode)
{
	uint8_t pdu[ATT_DEFAULT_LE_MTU];
	size_t plen;

	plen = enc_error_resp(opcode, handle, ecode, pdu, sizeof(pdu));

	g_attrib_send(attrib, 0, pdu, plen, NULL, NULL, NULL);
}

static void destroy_attribute(struct btd_attribute *attr)
{
	if (attr->notifiers != NULL)
		g_hash_table_destroy(attr->notifiers);
	g_free(attr);
}

static void gatt_device_clear(struct gatt_device *gdev)
{
	GHashTableIter iter;
	gpointer key, hashval;
	GSList *l;
	char *path;

	DBG("");

	g_hash_table_iter_init(&iter, gdev->chr_objs);
	while (g_hash_table_iter_next(&iter, &key, &hashval)) {
		path = hashval;

		gatt_dbus_characteristic_unregister(path);
	}

	g_hash_table_remove_all(gdev->chr_objs);

	for (l = gdev->svc_objs; l; l = g_slist_next(l)) {
		path = l->data;
		gatt_dbus_service_unregister(path);
	}

	g_slist_free_full(gdev->svc_objs, g_free);
	gdev->svc_objs = NULL;

	g_list_free_full(gdev->database, (GDestroyNotify) destroy_attribute);
	gdev->database = NULL;

	g_slist_free(gdev->services);
	gdev->services = NULL;
}

static struct gatt_device *gatt_device_new(struct btd_device *device)
{
	struct gatt_device *gdev = g_new0(struct gatt_device, 1);
	struct btd_adapter *adapter = device_get_adapter(device);
	char srcaddr[18], dstaddr[18];
	const bdaddr_t *src, *dst;

	src = adapter_get_address(adapter);
	ba2str(src, srcaddr);

	dst = device_get_address(device);
	ba2str(dst, dstaddr);

	gdev->ccc_fname = g_strdup_printf("%s/%s/%s/ccc",
						STORAGEDIR, srcaddr, dstaddr);

	gdev->ccc_keyfile = g_key_file_new();

	g_key_file_load_from_file(gdev->ccc_keyfile, gdev->ccc_fname,
						G_KEY_FILE_NONE, NULL);

	gdev->chr_objs = g_hash_table_new_full(g_direct_hash, g_direct_equal,
								NULL, g_free);

	return gdev;
}

static void gatt_device_free(gpointer user_data)
{
	struct gatt_device *gdev = user_data;
	char *data;
	size_t len;

	if (gdev->channel_id > 0) {
		g_source_remove(gdev->channel_id);
		gdev->channel_id = 0;
	}

	gatt_device_clear(gdev);
	g_hash_table_destroy(gdev->chr_objs);

	if (gdev->attrib) {
		g_attrib_unregister(gdev->attrib, gdev->attrib_id);
		g_attrib_unref(gdev->attrib);
	}

	/* Flushing data to Local Database overlay */
	data = g_key_file_to_data(gdev->ccc_keyfile, &len, NULL);
	if (len > 0) {
		create_file(gdev->ccc_fname, S_IRUSR | S_IWUSR);
		g_file_set_contents(gdev->ccc_fname, data, len, NULL);
	}
	g_free(data);

	g_free(gdev->ccc_fname);
	g_key_file_free(gdev->ccc_keyfile);

	g_free(gdev);
}

int btd_attribute_value_get(struct btd_attribute *attr, uint8_t *buf,
							int buflen)
{
	int len = MIN(buflen, attr->value_len);

	memcpy(buf, attr->value, len);

	return len;
}

/* new_const_attribute - Create a new fixed value attribute.
 * @type:	Attribute type in ATT byte order.
 * @value:	Value of the attribute in ATT byte order.
 * @len:	Length of value in bytes.
 *
 * Returns a new attribute.
 */
static struct btd_attribute *new_const_attribute(const bt_uuid_t *type,
							const uint8_t *value,
							uint16_t len)
{
	struct btd_attribute *attr = g_malloc0(sizeof(struct btd_attribute) +
						len);

	memcpy(&attr->type, type, sizeof(*type));
	memcpy(&attr->value, value, len);
	attr->value_len = len;

	return attr;
}

static struct btd_attribute *new_attribute(const bt_uuid_t *type,
						btd_attr_read_t read_cb,
						btd_attr_write_t write_cb)
{
	struct btd_attribute *attr = g_new0(struct btd_attribute, 1);

	memcpy(&attr->type, type, sizeof(*type));
	attr->read_cb = read_cb;
	attr->write_cb = write_cb;
	attr->notifiers = g_hash_table_new_full(g_direct_hash, g_direct_equal,
								NULL, g_free);

	return attr;
}

static void local_database_add(struct btd_attribute *attr)
{
	/* TODO: Throw error if next_handle overflows */
	attr->handle = next_handle++;

	local_attribute_db = g_list_append(local_attribute_db, attr);
}

static int attribute_cmp(gconstpointer a, gconstpointer b)
{
	const struct btd_attribute *attr1 = a, *attr2 = b;

	return attr1->handle - attr2->handle;
}

static void remote_database_add(struct btd_device *device,
					struct btd_attribute *attr)
{
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);
	gdev->database = g_list_insert_sorted(gdev->database, attr, attribute_cmp);
}

struct btd_attribute *btd_gatt_add_service(bt_uuid_t *uuid, bool primary)
{
	struct btd_attribute *attr;
	const bt_uuid_t *type;
	uint16_t len = bt_uuid_len(uuid);
	uint8_t value[len];

	/* Set attribute type */
	type = (primary ? &primary_uuid : &secondary_uuid);

	/* Set attribute value */
	att_put_uuid(*uuid, value);

	attr = new_const_attribute(type, value, len);

	local_database_add(attr);

	return attr;
}

static bool is_service(struct btd_attribute *attr)
{
	if (attr->type.type != BT_UUID16)
		return false;

	if (attr->type.value.u16 == GATT_PRIM_SVC_UUID ||
				attr->type.value.u16 == GATT_SND_SVC_UUID)
		return true;
	else
		return false;

}

static bool is_characteristic(struct btd_attribute *attr)
{
	if (attr->type.value.u16 == GATT_CHARAC_UUID)
		return true;
	else
		return false;
}

void btd_gatt_remove_service(struct btd_attribute *service)
{
	GList *list = g_list_find(local_attribute_db, service);

	if (list == NULL)
		return;

	/* Remove service declaration attribute */
	destroy_attribute(list->data);
	list = g_list_delete_link(list, list);

	/* Remove all characteristics until next service declaration */
	while (list && !is_service(list->data)) {
		destroy_attribute(list->data);
		list = g_list_delete_link(list, list);
	}
}

static gint find_by_handle(gconstpointer a, gconstpointer b)
{
	const struct btd_attribute *attr = a;

	return attr->handle - GPOINTER_TO_UINT(b);
}

static struct btd_attribute *find_declaration(GList *list, uint16_t handle)
{
	GList *l;
	struct btd_attribute *decl = NULL, *attr;

	/*
	 * Given a handle, this function returns the characteristic
	 * declaration attribute which this attribute belongs to.
	 * At this point, Descriptor/Value Attribute may not be inserted
	 * in the database, search needs to be sequential.
	 */
	for (l = g_list_first(list); l; l = g_list_next(l)) {
		attr = l->data;

		if (attr->handle >= handle)
			break;

		/* Characteristic Declaration ? */
		if (is_characteristic(attr))
			decl = attr;
	}

	return decl;
}

static struct btd_attribute *find_value(struct btd_attribute *desc)
{
	GList *l;

	/*
	 * Characteristic Value Attribute is always the next
	 * attribute after the Characteristic Declaration attribute.
	 * << Characteristic >>: Declaration
	 *     << UUID >>: Characteristic UUID
	 *     << Descriptors 1 >>: Characteristic Descriptors
	 */
	for (l = g_list_find(local_attribute_db, desc); l;
						l = g_list_previous(l)) {
		GList *next;

		/* Characteristic Declaration? */
		if (!is_characteristic(l->data))
			continue;

		/* Characteristic Value */
		next = g_list_next(l);

		return (next ? next->data : NULL);
	}

	return NULL;
}

static void read_ccc_cb(struct btd_device *device,
				struct btd_attribute *attr,
				btd_attr_read_result_t result, void *user_data)
{
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);
	struct btd_attribute *char_value;
	char handle[7];
	uint8_t value[2];
	uint16_t ccc;

	char_value = find_value(attr);
	if (char_value == NULL) {
		DBG("CCC 0x%04x: Characteristic declaration missing",
							attr->handle);
		result(EPERM, NULL, 0, user_data);
		return;
	}

	snprintf(handle, sizeof(handle), "0x%04x", char_value->handle);
	ccc = g_key_file_get_integer(gdev->ccc_keyfile, handle, "Value", NULL);

	att_put_u16(ccc, value);

	result(0, value, sizeof(value), user_data);
}

static void database_store_ccc(struct btd_device *device,
				uint16_t handle, uint16_t value)
{
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);
	char group[7];

	/*
	 * When notification or indication arrives, it contains the handle of
	 * Characteristic Attribute value. In order to simplify the logic, the
	 * CCC storage uses the Attribute Characteristic value handle as key
	 * instead of using the Descriptor handle.
	 */

	snprintf(group, sizeof(group), "0x%04x", handle);

	if (value == 0x0000)
		g_key_file_remove_key(gdev->ccc_keyfile, group, "Value",
								NULL);
	else
		g_key_file_set_integer(gdev->ccc_keyfile, group, "Value",
								value);
}

static void write_ccc_cb(struct btd_device *device,
				struct btd_attribute *attr, uint8_t *value,
				size_t len, uint16_t offset,
				btd_attr_write_result_t result, void *user_data)
{
	struct btd_attribute *char_value;
	uint16_t ccc;

	if (len != 2) {
		DBG("Invalid size for Characteristic Configuration Bits");
		result(EINVAL, user_data);
		return;
	}

	char_value = find_value(attr);
	if (char_value == NULL) {
		DBG("CCC 0x%04x: Characteristic declaration missing",
							attr->handle);
		result(EPERM, user_data);
		return;
	}

	ccc = att_get_u16(value);
	database_store_ccc(device, char_value->handle, ccc);

	result(0, user_data);
}

struct btd_attribute *btd_gatt_add_char(bt_uuid_t *uuid, uint8_t properties,
					btd_attr_read_t read_cb,
					btd_attr_write_t write_cb,
					int read_sec, int write_sec,
					int key_size)
{
	struct btd_attribute *char_decl, *char_value;
	bt_uuid_t char_type;
	/* Characteristic properties (1 octet), characteristic value attribute
	 * handle (2 octets) and characteristic UUID (2 or 16 octets).
	 */
	uint16_t len = 1 + 2 + bt_uuid_len(uuid);
	uint8_t value[len];

	/*
	 * Create and add the characteristic declaration attribute
	 */
	value[0] = properties;

	/* Since we don't know yet the characteristic value attribute handle,
	 * we skip and set it later.
	 */

	att_put_uuid(*uuid, &value[3]);

	char_decl = new_const_attribute(&chr_uuid, value, len);
	local_database_add(char_decl);

	/*
	 * Create and add the characteristic value attribute
	 */
	char_value = new_attribute(uuid, read_cb, write_cb);
	char_value->read_sec = read_sec;
	char_value->write_sec = write_sec;
	char_value->key_size = key_size;

	local_database_add(char_value);

	/* Update characteristic value handle in characteristic declaration
	 * attribute.
	 */
	att_put_u16(char_value->handle, &char_decl->value[1]);

	if (properties & (ATT_CHAR_PROPER_NOTIFY | ATT_CHAR_PROPER_INDICATE)) {
		bt_uuid16_create(&char_type, GATT_CLIENT_CHARAC_CFG_UUID);
		btd_gatt_add_char_desc(&char_type, read_ccc_cb,
					write_ccc_cb, read_sec, write_sec,
					key_size);
	}

	return char_value;
}

void btd_gatt_add_char_desc(bt_uuid_t *uuid, btd_attr_read_t read_cb,
				btd_attr_write_t write_cb,
				int read_sec, int write_sec, int key_size)
{
	struct btd_attribute *attr;

	attr = new_attribute(uuid, read_cb, write_cb);
	attr->read_sec = read_sec;
	attr->write_sec = write_sec;
	attr->key_size = key_size;

	local_database_add(attr);
}

GSList *btd_gatt_get_services(struct btd_device *device, bt_uuid_t *service)
{
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);
	GList *list;
	GSList *services = NULL;

	for (list = g_list_first(gdev->database); list; list = g_list_next(list)) {
		struct btd_attribute *attr = list->data;

		if (is_service(attr)) {
			bt_uuid_t curr_svc;
			if (attr->value_len == 2)
				curr_svc = att_get_uuid16(attr->value);
			else
				curr_svc = att_get_uuid128(attr->value);

			if (!bt_uuid_cmp(&curr_svc, service))
				services = g_slist_prepend(services, attr);
		}
	}

	return services;
}

GSList *btd_gatt_get_chars_decl(struct btd_device *device,
					struct btd_attribute *service,
					bt_uuid_t *type)
{
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);
	GList *list;
	GSList *chars = NULL;

	if (!gdev->database)
		return NULL;

	list = g_list_find(gdev->database, service);
	if (!list)
		goto error;

	for (list = g_list_next(list); list && !is_service(list->data);
						list = g_list_next(list)) {
		struct btd_attribute *attr = list->data;

		if (is_characteristic(attr)) {
			GList *next_attr = g_list_next(list);
			struct btd_attribute *value_decl = next_attr->data;

			if (!bt_uuid_cmp(&value_decl->type, type))
				chars = g_slist_prepend(chars, attr);

			/*
			 * Avoid searching for a characteristic declaration in
			 * a characteristic value declaration.
			*/
			list = next_attr;
		}
	}

error:
	return chars;
}

struct btd_attribute *btd_gatt_get_char_desc(struct btd_device *device,
						struct btd_attribute *chr,
						bt_uuid_t *type)
{
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);
	GList *list;

	if (!gdev->database)
		goto error;

	list = g_list_find(gdev->database, chr);
	if (!list)
		goto error;

	for (list = g_list_nth(list, 2); list && !is_service(list->data)
					&& !is_characteristic(list->data);
						list = g_list_next(list)) {
		struct btd_attribute *attr = list->data;

		if (!bt_uuid_cmp(&attr->type, type))
			return attr;
	}

error:
	return NULL;
}

struct btd_attribute *btd_gatt_get_char_value(struct btd_device *device,
						struct btd_attribute *chr)
{
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);
	GList *list;

	if (!gdev->database)
		return NULL;

	list = g_list_find(gdev->database, chr);
	if (!list)
		return NULL;

	list = g_list_next(list);
	return list->data;
}

void btd_gatt_read_attribute(struct btd_device *device,
					struct btd_attribute *attr,
					btd_attr_read_result_t result,
					void *user_data)
{
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);

	if (gdev->attrib == NULL)
		result(ECOMM, NULL, 0, user_data);

	if (attr->read_cb)
		attr->read_cb(device, attr, result, user_data);
	else if (attr->value_len > 0)
		result(0, attr->value, attr->value_len, user_data);
	else
		result(EPERM, NULL, 0, user_data);
}

static void remote_read_attribute_response(uint8_t status,
						const uint8_t *value,
						size_t vlen, void *user_data)
{
	struct remote_read_data *data = user_data;
	btd_attr_read_result_t func = data->func;

	if (status)
		func(status, NULL, 0, data->user_data);
	else
		func(status, (uint8_t *) value, vlen, data->user_data);

	g_free(data);
}

static void remote_read_attribute_cb(struct btd_device *device,
						struct btd_attribute *attr,
						btd_attr_read_result_t result,
						void *user_data)
{
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);
	struct remote_read_data *data;

	if (gdev->attrib == NULL) {
		DBG("ATT disconnected");
		result(ECOMM, NULL, 0, user_data);
		return;
	}

	data = g_new0(struct remote_read_data, 1);
	data->func = result;
	data->user_data = user_data;

	if (gatt_read_char(gdev->attrib, attr->handle,
				remote_read_attribute_response, data) == 0) {
		result(EIO, NULL, 0, user_data);
		g_free(data);
	}
}

static void indication_result(guint8 status, const guint8 *pdu,
					guint16 len, gpointer user_data)
{
	struct attr_notif_data *nd = user_data;
	btd_attr_write_result_t func = nd->func;

	DBG("");
	func(status, nd->user_data);

	g_free(nd);
}

static void notify_value_changed(struct btd_attribute *attr, uint8_t *value,
						size_t len,
						btd_attr_write_result_t result,
						void *user_data)
{
	char handle[7];
	GHashTableIter iter;
	gpointer key, hashval;

	snprintf(handle, sizeof(handle), "0x%04x", attr->handle);

	g_hash_table_iter_init(&iter, gatt_devices);
	while (g_hash_table_iter_next(&iter, &key, &hashval)) {
		struct gatt_device *gdev = hashval;
		struct attr_notif_data *nd;
		uint8_t opdu[ATT_DEFAULT_LE_MTU];
		uint16_t ccc;
		size_t olen;

		if (gdev->attrib == NULL)
			continue;

		ccc = g_key_file_get_integer(gdev->ccc_keyfile, handle,
							"Value", NULL);
		nd = NULL;

		if (ccc & CCC_INDICATION_BIT) {
			olen = enc_indication(attr->handle, value, len, opdu,
								sizeof(opdu));
			nd = g_new0(struct attr_notif_data, 1);
			nd->func = result;
			nd->user_data = user_data;
		} else if (ccc & CCC_NOTIFICATION_BIT) {
			olen = enc_notification(attr->handle, value, len, opdu,
								sizeof(opdu));
		} else
			continue;

		g_attrib_send(gdev->attrib, 0, opdu, olen, indication_result, nd, NULL);
	}

	result(0, user_data);
}

void btd_gatt_write_attribute(struct btd_device *device,
				struct btd_attribute *attr,
				uint8_t *value, size_t len, uint16_t offset,
				btd_attr_write_result_t result,
				void *user_data)
{
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);

	/* Profiles whose characteristic value is accessed by callbacks can
	 * report to core that this value has changed by calling
	 * btd_gatt_write_attribute() with device parameter set to NULL. This
	 * will skip the write callback call and instead report the new value
	 * to all devices that have enabled notifications/indications. For
	 * indications, the result callback will be called when the
	 * confirmation is received, so the upper layer gets acknowledged. */
	if (device == NULL) {
		notify_value_changed(attr, value, len, result, user_data);
		return;
	}

	if (gdev->attrib == NULL)
		result(ECOMM, user_data);

	if (attr->write_cb)
		attr->write_cb(device, attr, value, len, offset,
						result, user_data);
	else
		result(EPERM, user_data);
}

static void remote_write_attribute_response(uint8_t status, void *user_data)
{
	struct remote_write_data *data = user_data;
	btd_attr_write_result_t func = data->func;

	func(status, data->user_data);
	g_free(data);
}

static void remote_write_attribute_cb(struct btd_device *device,
					struct btd_attribute *attr,
					uint8_t *value, size_t len,
					uint16_t offset,
					btd_attr_write_result_t result,
					void *user_data)
{
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);
	struct remote_write_data *data;

	if (gdev->attrib == NULL) {
		result(ECOMM, user_data);
		return;
	}

	data = g_new0(struct remote_write_data, 1);
	data->func = result;
	data->user_data = user_data;

	if (gatt_write_char(gdev->attrib, attr->handle, offset, value, len,
				remote_write_attribute_response, data) == 0) {
		result(EIO, user_data);
		g_free(data);
	}
}

static void remote_write_notify(void *user_data)
{
	remote_write_attribute_response(0, user_data);
}

static void remote_write_without_resp_cb(struct btd_device *device,
						struct btd_attribute *attr,
						uint8_t *value, size_t len,
						uint16_t offset,
						btd_attr_write_result_t result,
						void *user_data)
{
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);
	struct remote_write_data *data;

	if (gdev->attrib == NULL) {
		result(ECOMM, user_data);
		return;
	}

	data = g_new0(struct remote_write_data, 1);
	data->func = result;
	data->user_data = user_data;

	/* NOTE: offset is ignored for Write Without Response */
	if (gatt_write_cmd(gdev->attrib, attr->handle, value, len,
					remote_write_notify, data) == 0) {
		result(EIO, user_data);
		g_free(data);
	}
}

unsigned int btd_gatt_add_notifier(struct btd_attribute *attr,
						btd_attr_value_t value_cb,
						void *user_data)
{
	struct notifier *notif;
	unsigned int id;

	if (!attr->notifiers)
		return -1;

	notif = g_new0(struct notifier, 1);
	notif->value_cb = value_cb;
	notif->user_data = user_data;

	id = next_notifier_id++;
	g_hash_table_insert(attr->notifiers, &id, notif);

	return id;
}

void btd_gatt_remove_notifier(struct btd_attribute *attr, unsigned int id)
{
	if (!attr->notifiers)
		return;

	g_hash_table_remove(attr->notifiers, &id);
}

static char *buf2str(const uint8_t *buf, size_t buflen)
{
	size_t i;
	char *str;

	if (buflen == 0)
		return NULL;

	str = g_try_new0(char, (buflen * 2) + 1);
	if (str == NULL)
		return NULL;

	for (i = 0; i < buflen; i++)
		sprintf(str + (i * 2), "%2.2x", buf[i]);

	return str;
}

static int str2buf(const char *str, uint8_t *buf, size_t blen)
{
	int i, dlen;

	if (str == NULL)
		return -EINVAL;

	memset(buf, 0, blen);

	dlen = MIN((strlen(str) / 2), blen);

	for (i = 0; i < dlen; i++)
		sscanf(str + (i * 2), "%02hhX", &buf[i]);

	return dlen;
}

static void database_store(struct btd_device *device, GList *database)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	char srcaddr[18], dstaddr[18], handle[7], uuidstr[MAX_LEN_UUID_STR];
	char filename[PATH_MAX + 1], *data;
	struct btd_attribute *prev, *attr;
	const bdaddr_t *src, *dst;
	GKeyFile *key_file;
	GList *list;
	size_t len;

	if (device_is_bonded(device) == FALSE)
		return;

	src = btd_adapter_get_address(adapter);
	ba2str(src, srcaddr);

	dst = device_get_address(device);
	ba2str(dst, dstaddr);

	snprintf(filename, PATH_MAX, STORAGEDIR "/%s/%s/attrib-database",
							srcaddr, dstaddr);
	key_file = g_key_file_new();

	g_key_file_load_from_file(key_file, filename, G_KEY_FILE_NONE, NULL);

	for (list = database, prev = NULL; list;
				list = g_list_next(list), prev = attr) {
		char *str;

		attr = list->data;
		/* Skip storing characteristic value */
		if ((attr->value_len == 0) && prev && is_characteristic(prev))
			continue;

		snprintf(handle, sizeof(handle), "0x%04x", attr->handle);

		bt_uuid_to_string(&attr->type, uuidstr, sizeof(uuidstr));
		g_key_file_set_string(key_file, handle, "Type", uuidstr);

		str = buf2str(attr->value, attr->value_len);
		if (str) {
			g_key_file_set_string(key_file, handle, "Value", str);
			g_free(str);
		}

		data = g_key_file_to_data(key_file, &len, NULL);
		if (len > 0) {
			create_file(filename, S_IRUSR | S_IWUSR);
			g_file_set_contents(filename, data, len, NULL);
		}
		g_free(data);
	}

	g_key_file_free(key_file);
}

static struct btd_attribute *new_const_remote_attribute(uint16_t handle,
					const bt_uuid_t *type, uint8_t *value,
					size_t vlen)
{
	struct btd_attribute *attr;

	attr = new_const_attribute(type, value, vlen);
	attr->handle = handle;

	return attr;
}

static struct btd_attribute *new_remote_attribute(uint16_t handle,
					bt_uuid_t *type,
					btd_attr_read_t read_cb,
					btd_attr_write_t write_cb)
{
	struct btd_attribute *attr;

	attr = new_attribute(type, read_cb, write_cb);
	attr->handle = handle;

	return attr;
}

static void connecting_complete(gpointer data, gpointer user_data)
{
	struct btd_service *service = data;
	struct gatt_device *gdev = user_data;

	DBG("service %p", service);
	btd_service_connecting_complete(service, 0);

	gdev->attrib = g_attrib_ref(gdev->attrib);
	gdev->services = g_slist_append(gdev->services,
					btd_service_ref(service));
}

static void prim_service_create(uint8_t status, uint16_t handle,
				uint8_t *value, size_t vlen, void *user_data)
{
	struct btd_device *device = user_data;
	struct btd_attribute *attr;

	if (status)
		return;

	attr = new_const_remote_attribute(handle, &primary_uuid, value, vlen);
	remote_database_add(device, attr);
}

static void snd_service_create(uint8_t status, uint16_t handle,
				uint8_t *value, size_t vlen, void *user_data)
{
	struct btd_device *device = user_data;
	struct btd_attribute *attr;

	if (status)
		return;

	attr = new_const_remote_attribute(handle, &secondary_uuid,
							value, vlen);

	remote_database_add(device, attr);
}

static void char_declaration_create(uint8_t status,
				uint16_t handle, uint8_t *value,
				size_t vlen, void *user_data)
{
	struct btd_device *device = user_data;
	struct btd_attribute *attr;
	bt_uuid_t value_uuid;
	uint16_t value_handle;
	uint8_t value_properties;
	btd_attr_read_t read_cb = NULL;
	btd_attr_write_t write_cb = NULL;

	if (status)
		return;

	/* Characteristic Declaration */
	attr = new_const_remote_attribute(handle, &chr_uuid, value, vlen);

	remote_database_add(device, attr);

	/* Characteristic Value Attribute */
	value_properties = value[0];

	value_handle = att_get_u16(&value[1]);

	vlen -= 3; /* Discarding 2 (handle) + 1 (properties) bytes */

	if (vlen == 2)
		value_uuid = att_get_uuid16(&value[3]);
	else if (vlen == 16)
		value_uuid = att_get_uuid128(&value[3]);

	if (value_properties & ATT_CHAR_PROPER_READ)
		read_cb = remote_read_attribute_cb;

	/* If characteristic supports both Write and Write Without Response,
	 * use the most reliable operation. */
	if (value_properties & ATT_CHAR_PROPER_WRITE)
		write_cb = remote_write_attribute_cb;
	else if (value_properties & ATT_CHAR_PROPER_WRITE_WITHOUT_RESP)
		write_cb = remote_write_without_resp_cb;

	attr = new_remote_attribute(value_handle, &value_uuid,
						read_cb, write_cb);

	remote_database_add(device, attr);
}

static void include_create(uint8_t status, uint16_t handle,
				uint8_t *value, size_t vlen, void *user_data)
{
	struct btd_device *device = user_data;
	struct btd_attribute *attr;
	bt_uuid_t uuid;

	bt_uuid16_create(&uuid, GATT_INCLUDE_UUID);

	attr = new_const_attribute(&uuid, value, vlen);
	attr->handle = handle;

	remote_database_add(device, attr);
}

static struct btd_attribute *descriptor_create(uint16_t handle, bt_uuid_t *type,
						uint8_t *value, size_t vlen,
						struct btd_device *device)
{
	struct btd_attribute *attr;

	/*
	 * For descriptors (specially CCC), default value should be set.
	 * Some descriptors may not be readable or writeable, the upper-layer
	 * defines its requirements. Read callback has higher priority
	 * than the local cached value, see btd_gatt_read_attribute().
	 */
	attr = new_const_remote_attribute(handle, type, value, vlen);
	attr->write_cb = remote_write_attribute_cb;
	attr->read_cb = remote_read_attribute_cb;

	remote_database_add(device, attr);

	return attr;
}

static void remote_ccc_enabled(int err, void *user_data)
{
	struct btd_attribute *attr = user_data;

	if (err == 0)
		return;

	DBG("(%p) 0x%04x CCC write failed", attr, attr->handle);

	/*
	 * Reset copy of CCC descriptor value. A new attempt to enable
	 * notification or indication will be triggered in the next
	 * connection establishment.
	 */

	memset(attr->value, 0, attr->value_len);
}

static void descriptor_cb(uint8_t status, uint16_t handle,
					bt_uuid_t *type, void *user_data)
{
	struct find_info *find = user_data;
	struct gatt_device *gdev;
	struct btd_attribute *attr, *decl;
	uint16_t enable;
	uint8_t value[2];
	bt_uuid_t uuid;

	if (status)
		return;

	/* Descriptor: Others different than CCC */
	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	if (bt_uuid_cmp(type, &uuid) != 0) {
		attr = descriptor_create(handle, type, NULL, 0, find->device);
		return;
	}

	/* Descriptor: <<< Client Characteristic Configuration >>> */

	gdev = g_hash_table_lookup(gatt_devices, find->device);

	/* Finding Characteristic Declaration */
	decl = find_declaration(gdev->database, handle);
	if (!decl) {
		error("Declaration not found");
		return;
	}

	if (decl->value[0] & ATT_CHAR_PROPER_NOTIFY)
		enable = CCC_NOTIFICATION_BIT;
	else if (decl->value[0] & ATT_CHAR_PROPER_INDICATE)
		enable = CCC_INDICATION_BIT;
	else
		return;

	/*
	 * Enable automatically notification or indication if
	 * the remote characteristic supports.
	 */
	att_put_u16(enable, &value);
	attr = descriptor_create(handle, type, value, sizeof(value),
						find->device);

	btd_gatt_write_attribute(find->device, attr, value, sizeof(value),
					0x00, remote_ccc_enabled, attr);
}

static void register_objects(struct btd_device *device, struct gatt_device *gdev)
{
	GList *l;
	char *service_path = NULL;

	/*
	 * Registering all services and characteristics objects.
	 * Assuming that the attributes handles are properly in
	 * sequence, a given characteristic always belongs to the
	 * last service declaration.
	 */
	for (l = gdev->database; l; l = g_list_next(l)) {
		struct btd_attribute *attr = l->data;
		char uuidstr[MAX_LEN_UUID_STR];
		bt_uuid_t uuid;

		/* Primary services */
		if (bt_uuid_cmp(&primary_uuid, &attr->type) == 0) {

			/*
			 * Attribute value is: 2 or 16 octets (UUID)
			 */
			uuid = (attr->value_len == 2 ?
					att_get_uuid16(attr->value) :
					att_get_uuid128(attr->value));

			bt_uuid_to_128string(&uuid, uuidstr, sizeof(uuidstr));

			service_path = gatt_dbus_service_register(device,
							attr->handle, uuidstr,
							attr);
			gdev->svc_objs = g_slist_append(gdev->svc_objs,
							service_path);
		} else if (bt_uuid_cmp(&chr_uuid, &attr->type) == 0) {
			char *path;
			uint8_t properties = attr->value[0];

			 /* Jump to Characteristic Value Attribute */

			l = g_list_next(l);
			attr = l->data;

			bt_uuid_to_128string(&attr->type, uuidstr, sizeof(uuidstr));

			path = gatt_dbus_characteristic_register(device,
							service_path,
							attr->handle, uuidstr,
							properties,
							attr);
			g_hash_table_insert(gdev->chr_objs,
					GINT_TO_POINTER(attr->handle), path);
		}
	}
}

bool gatt_load_from_storage(struct btd_device *device)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	struct gatt_device *gdev;
	char srcaddr[18], dstaddr[18];
	char filename[PATH_MAX + 1];
	char **groups, **group;
	const bdaddr_t *src, *dst;
	GKeyFile *key_file;

	src = btd_adapter_get_address(adapter);
	ba2str(src, srcaddr);

	dst = device_get_address(device);
	ba2str(dst, dstaddr);

	DBG("src %s dst %s", dstaddr, srcaddr);

	snprintf(filename, PATH_MAX, STORAGEDIR "/%s/%s/attrib-database",
							srcaddr, dstaddr);
	key_file = g_key_file_new();

	if (g_key_file_load_from_file(key_file, filename,
					G_KEY_FILE_NONE, NULL) == FALSE) {
		g_key_file_free(key_file);
		return false;
	}

	gdev = gatt_device_new(device);
	g_hash_table_insert(gatt_devices, btd_device_ref(device), gdev);

	groups = g_key_file_get_groups(key_file, NULL);

	for (group = groups; *group; group++) {
		uint16_t handle;
		size_t buflen;
		uint8_t buf[32];
		char *uuidstr, *valuestr;
		bt_uuid_t uuid;

		DBG("group %s", *group);

		handle = strtol(*group, NULL, 16);

		uuidstr = g_key_file_get_string(key_file, *group, "Type",
								NULL);
		bt_string_to_uuid(&uuid, uuidstr);

		valuestr = g_key_file_get_string(key_file, *group, "Value",
								NULL);

		buflen = 0;
		if (valuestr)
			buflen = str2buf(valuestr, buf, sizeof(buf));

		if (uuid.type == BT_UUID16) {
			switch (uuid.value.u16) {
			case GATT_PRIM_SVC_UUID:
				prim_service_create(0, handle, buf, buflen,
								device);
				break;
			case GATT_SND_SVC_UUID:
				snd_service_create(0, handle, buf,
							buflen, device);
				break;
			case GATT_CHARAC_UUID:
				char_declaration_create(0, handle, buf,
							buflen, device);
				break;
			case GATT_INCLUDE_UUID:
				include_create(0, handle, buf, buflen, device);
				break;
			default:
				descriptor_create(handle, &uuid, buf, buflen, device);
			}
		} else {
			descriptor_create(handle, &uuid, buf, buflen, device);
		}

		g_free(valuestr);
		g_free(uuidstr);
	}

	g_strfreev(groups);

	g_key_file_free(key_file);

	register_objects(device, gdev);

	return true;
}

static void read_local_name_cb(struct btd_device *device,
				struct btd_attribute *attr,
				btd_attr_read_result_t result,
				void *user_data)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	const char *name = btd_adapter_get_name(adapter);

	result(0, (uint8_t *) name, strlen(name), user_data);
}

static void read_local_appearance_cb(struct btd_device *device,
				struct btd_attribute *attr,
				btd_attr_read_result_t result,
				void *user_data)
{
	uint8_t appearance[] = { 0x00, 0x00 };

	result(0, appearance, sizeof(appearance), user_data);
}

static void add_gap(void)
{
	bt_uuid_t uuid;

	/* Primary Service: <<GAP Service>> */
	bt_uuid16_create(&uuid, GENERIC_ACCESS_PROFILE_ID);
	btd_gatt_add_service(&uuid, true);

	/* Declaration and Value: <<Device Name>>*/
	bt_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	btd_gatt_add_char(&uuid, ATT_CHAR_PROPER_READ, read_local_name_cb,
				NULL, BT_SECURITY_LOW, BT_SECURITY_LOW, 0);

	/* Declaration and Value: <<Appearance>>*/
	bt_uuid16_create(&uuid, GATT_CHARAC_APPEARANCE);
	btd_gatt_add_char(&uuid, ATT_CHAR_PROPER_READ, read_local_appearance_cb,
				NULL, BT_SECURITY_LOW, BT_SECURITY_LOW, 0);
}

static void add_gatt(void)
{
	bt_uuid_t uuid;

	/* Primary Service: <<GATT Service>> */
	bt_uuid16_create(&uuid, GENERIC_ATTRIB_PROFILE_ID);
	btd_gatt_add_service(&uuid, true);

	/* Declaration and Value: <<Service Changed>> */
	bt_uuid16_create(&uuid, GATT_CHARAC_SERVICE_CHANGED);
	btd_gatt_add_char(&uuid, ATT_CHAR_PROPER_INDICATE, NULL, NULL,
					BT_SECURITY_LOW, BT_SECURITY_LOW, 0);

	btd_gatt_dump_local_attribute_database();
}

static void channel_remove(gpointer user_data)
{
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices,
								user_data);

	/* If called from the destroy func of the hash table, this function
	 * is called when the element is already not present in the hash table
	 */
	DBG("");
	if (gdev == NULL)
		return;

	if (gdev->attrib) {
		g_attrib_cancel_all(gdev->attrib);
		gdev->attrib = NULL;
	}
}

static uint8_t check_attribute_security(struct btd_attribute *attr,
						GAttrib *attrib,
						uint16_t opcode)
{
	int op_sec_level, chan_sec_level;
	int key_size;

	switch (opcode) {
	case ATT_OP_READ_BY_TYPE_REQ:
	case ATT_OP_READ_REQ:
	case ATT_OP_READ_BLOB_REQ:
	case ATT_OP_READ_MULTI_REQ:
	case ATT_OP_READ_BY_GROUP_REQ:
		op_sec_level = attr->read_sec;
		break;
	case ATT_OP_WRITE_REQ:
	case ATT_OP_WRITE_CMD:
	case ATT_OP_PREP_WRITE_REQ:
	case ATT_OP_EXEC_WRITE_REQ:
	case ATT_OP_SIGNED_WRITE_CMD:
		op_sec_level = attr->write_sec;
		break;
	default:
		return 0;
	}

	if (op_sec_level == BT_SECURITY_LOW)
		return 0;

	chan_sec_level = g_attrib_get_sec_level(attrib);

	if (chan_sec_level < op_sec_level) {
		if (op_sec_level == BT_SECURITY_HIGH)
			return ATT_ECODE_AUTHENTICATION;
		else
			return ATT_ECODE_INSUFF_ENC;
	}

	key_size = g_attrib_get_key_size(attrib);

	if (key_size < attr->key_size)
		return ATT_ECODE_INSUFF_ENCR_KEY_SIZE;

	return 0;
}

static void read_by_type_result(int err, uint8_t *value, size_t vlen,
							void *user_data)

{
	struct read_by_type_transaction *trans = user_data;
	struct btd_device *device = trans->device;
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);
	GList *head = trans->match;
	struct btd_attribute *attr = head->data;
	uint16_t mtu;

	if (gdev->attrib == NULL)
		goto done;

	if (err) {
		send_error(gdev->attrib, ATT_OP_READ_BY_TYPE_REQ, attr->handle,
							errno_to_att(err));
		goto done;
	}

	trans->match = g_list_delete_link(trans->match, head);

	/* According to Core v4.0 spec, page 1853, if the attribute
	 * value is longer than (ATT_MTU - 4) or 253 octets, whichever
	 * is smaller, then the first (ATT_MTU - 4) or 253 octets shall
	 * be included in this response.
	 */

	mtu = g_attrib_get_mtu(gdev->attrib);
	if (trans->olen == 0) {
		trans->vlen = MIN((uint16_t) (mtu - 4), MIN(vlen, 253));

		/* First entry: Set handle-value length */
		trans->opdu[trans->olen++] = ATT_OP_READ_BY_TYPE_RESP;
		trans->opdu[trans->olen++] = 2 + trans->vlen;
	} else if (trans->vlen != MIN(vlen, 253))
		/* Length doesn't match with handle-value length */
		goto send;

	/* It there space enough for another handle-value pair? */
	if (trans->olen + 2 + trans->vlen > mtu)
		goto send;

	/* Copy attribute handle into opdu */
	att_put_u16(attr->handle, &trans->opdu[trans->olen]);
	trans->olen += 2;

	/* Copy attribute value into opdu */
	memcpy(&trans->opdu[trans->olen], value, trans->vlen);
	trans->olen += trans->vlen;

	if (trans->match == NULL)
		goto send;

	/* Getting the next attribute */
	attr = trans->match->data;

	if (attr->value_len)
		read_by_type_result(0, attr->value, attr->value_len, trans);
	else
		attr->read_cb(device, attr, read_by_type_result, trans);
	return;

send:
	g_attrib_send(gdev->attrib, 0, trans->opdu, trans->olen, NULL, NULL,
									NULL);

done:
	g_list_free(trans->match);
	g_free(trans);
}

static void read_by_type(struct btd_device *device, GAttrib *attrib,
					const uint8_t *ipdu, size_t ilen)
{
	struct read_by_type_transaction *trans;
	struct btd_attribute *attr;
	GList *list;
	uint16_t start, end;
	bt_uuid_t uuid;
	uint8_t status = 0;

	if (dec_read_by_type_req(ipdu, ilen, &start, &end, &uuid) == 0) {
		send_error(attrib, ipdu[0], 0x0000,
						ATT_ECODE_INVALID_PDU);
		return;
	}

	if (start == 0x0000 || start > end) {
		send_error(attrib, ipdu[0], 0x0000, ATT_ECODE_INVALID_HANDLE);
		return;
	}

	trans = g_malloc0(sizeof(*trans) + g_attrib_get_mtu(attrib));
	trans->device = device;

	for (list = local_attribute_db; list; list = g_list_next(list)) {
		attr = list->data;

		if (attr->handle < start)
			continue;

		if (attr->handle > end)
			break;

		if (bt_uuid_cmp(&attr->type, &uuid) != 0)
			continue;

		/* Checking attribute consistency */
		if (attr->value_len == 0 && attr->read_cb == NULL)
			continue;

		status = check_attribute_security(attr, attrib, ipdu[0]);
		if (status)
			break;

		trans->match = g_list_append(trans->match, attr);
	}

	if (trans->match == NULL) {
		if (status)
			send_error(attrib, ipdu[0], start, status);
		else
			send_error(attrib, ipdu[0], start,
						ATT_ECODE_ATTR_NOT_FOUND);
		g_free(trans);
		return;
	}

	/* Processing the first element */
	attr = trans->match->data;

	if (attr->value_len)
		read_by_type_result(0, attr->value, attr->value_len, trans);
	else
		attr->read_cb(device, attr, read_by_type_result, trans);
}

static void find_info_request(struct btd_device *device, GAttrib *attrib,
				const uint8_t *ipdu, size_t ilen)
{
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);
	struct btd_attribute *attr;
	size_t plen = 0, olen = 0, uuid_len;
	uint16_t start, end;
	uint16_t mtu = g_attrib_get_mtu(gdev->attrib);
	uint8_t opdu[mtu];
	GList *list;

	if (dec_find_info_req(ipdu, ilen, &start, &end) == 0) {
		send_error(attrib, ipdu[0], 0x0000,
						ATT_ECODE_INVALID_PDU);
		return;
	}

	if (start == 0x0000 || start > end) {
		send_error(attrib, ipdu[0], 0x0000, ATT_ECODE_INVALID_HANDLE);
		return;
	}

	for (list = local_attribute_db; list; list = g_list_next(list)) {
		attr = list->data;

		if (attr->handle < start)
			continue;

		if (attr->handle > end)
			break;

		uuid_len = (size_t)bt_uuid_len(&attr->type);

		if (olen == 0) {
			/* Add opcode and data format */

			/* Pair UUID and handle length */
			plen = uuid_len + 2;

			opdu[olen++] = ATT_OP_FIND_INFO_RESP;

			if (attr->type.type == BT_UUID16)
				opdu[olen++] = ATT_FIND_INFO_RESP_FMT_16BIT;
			else
				opdu[olen++] = ATT_FIND_INFO_RESP_FMT_128BIT;
		} else if (plen != uuid_len + 2)
			/* Found a different UUID format */
			goto send;

		/* Check it there space enough for another handle-uuid pair */
		if (olen + plen > mtu)
			goto send;

		/* Copy attribute handle into opdu */
		att_put_u16(attr->handle, &opdu[olen]);
		olen += 2;

		/* Copy attribute UUID into opdu */
		att_put_uuid(attr->type, &opdu[olen]);
		olen += uuid_len;
	}

	if (olen == 0) {
		send_error(attrib, ipdu[0], start, ATT_ECODE_ATTR_NOT_FOUND);
		return;
	}

send:
	g_attrib_send(gdev->attrib, 0, opdu, olen, NULL, NULL, NULL);
}

static GList *get_char_decl_from_attr(GList *attr_node)
{
	GList *char_decl_node;
	struct btd_attribute *attr;

	char_decl_node = g_list_previous(attr_node);
	if (char_decl_node == NULL)
		return NULL;

	attr = char_decl_node->data;
	if (bt_uuid_cmp(&chr_uuid, &attr->type) != 0)
		return NULL;

	return char_decl_node;
}

static bool validate_att_operation(GList *attr_node, uint16_t opcode)
{
	GList *char_decl_node;
	struct btd_attribute *attr;

	attr = attr_node->data;

	char_decl_node = get_char_decl_from_attr(attr_node);
	if (char_decl_node == NULL)
		return true;

	attr = char_decl_node->data;

	switch (opcode) {
	case ATT_OP_WRITE_REQ:
		if (attr->value[0] & 0x08)
			return true;
	case ATT_OP_WRITE_CMD:
		if (attr->value[0] & 0x04)
			return true;
	case ATT_OP_READ_REQ:
		if (attr->value[0] & 0x02)
			return true;
	}

	return false;
}

static void read_request_result(int err, uint8_t *value, size_t len,
							void *user_data)
{
	struct att_transaction *trans = user_data;
	struct btd_attribute *attr = trans->attr;
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices,
							trans->device);

	g_free(trans);

	if (gdev->attrib) {
		uint8_t opdu[g_attrib_get_mtu(gdev->attrib)];
		size_t olen;

		if (err) {
			send_error(gdev->attrib, ATT_OP_READ_REQ, attr->handle,
							errno_to_att(err));
			return;
		}

		olen = enc_read_resp(value, len, opdu, sizeof(opdu));

		g_attrib_send(gdev->attrib, 0, opdu, olen, NULL, NULL, NULL);
	}
}

static void read_request(struct btd_device *device, GAttrib *attrib,
					const uint8_t *ipdu, size_t ilen)
{
	uint16_t handle;
	GList *list;
	struct btd_attribute *attr;
	struct att_transaction *trans;
	uint8_t status;

	if (dec_read_req(ipdu, ilen, &handle) == 0) {
		send_error(attrib, ipdu[0], 0x0000, ATT_ECODE_INVALID_PDU);
		return;
	}

	list = g_list_find_custom(local_attribute_db,
				GUINT_TO_POINTER(handle), find_by_handle);
	if (!list) {
		send_error(attrib, ipdu[0], 0x0000, ATT_ECODE_INVALID_HANDLE);
		return;
	}

	attr = list->data;

	status = check_attribute_security(attr, attrib, ipdu[0]);
	if (status) {
		send_error(attrib, ATT_OP_READ_REQ, attr->handle, status);
		return;
	}

	if (!validate_att_operation(list, ATT_OP_READ_REQ)) {
		send_error(attrib, ATT_OP_READ_REQ, attr->handle,
						ATT_ECODE_READ_NOT_PERM);
		return;
	}

	if (attr->value_len > 0) {
		uint8_t opdu[g_attrib_get_mtu(attrib)];
		size_t olen = enc_read_resp(attr->value, attr->value_len, opdu,
								sizeof(opdu));

		g_attrib_send(attrib, 0, opdu, olen, NULL, NULL, NULL);
		return;
	}

	if (attr->read_cb == NULL) {
		send_error(attrib, ATT_OP_READ_REQ, attr->handle,
						ATT_ECODE_READ_NOT_PERM);
		return;
	}

	trans = g_new0(struct att_transaction, 1);
	trans->attr = attr;
	trans->device = device;

	attr->read_cb(device, attr, read_request_result, trans);
}

static void read_by_group_resp(GAttrib *attrib, uint16_t start,
					uint16_t end, bt_uuid_t *pattern)
{
	uint16_t mtu = g_attrib_get_mtu(attrib);
	uint8_t opdu[mtu];
	GList *list;
	struct btd_attribute *last = NULL;
	uint8_t *group_start, *group_end = NULL, *group_uuid;
	unsigned int uuid_type = BT_UUID_UNSPEC;
	size_t group_len = 0, plen = 0;

	/*
	 * Read By Group Type Response format:
	 *    Attribute Opcode: 1 byte
	 *    Length: 1 byte (size of each group)
	 *    Group: start | end | <<UUID>>
	 */

	opdu[0] = ATT_OP_READ_BY_GROUP_RESP;
	group_start = &opdu[2];
	group_uuid = &opdu[6];

	for (list = local_attribute_db; list;
			last = list->data, list = g_list_next(list)) {
		struct btd_attribute *attr = list->data;

		if (attr->handle < start)
			continue;

		if (attr->handle > end)
			break;

		if (bt_uuid_cmp(&attr->type, pattern) != 0)
			continue;

		if (uuid_type != BT_UUID_UNSPEC &&
						uuid_type != attr->type.type) {
			/*
			 * Groups should contain the same length: UUID16 and
			 * UUID128 should be sent on different ATT PDUs
			 */
			break;
		}

		/*
		 * MTU checking should not be shifted up, otherwise the
		 * handle of last end group will not be set properly.
		 */
		if ((plen + group_len) >= mtu)
			break;

		/* Start Grouping handle */
		att_put_u16(attr->handle, group_start);

		/* Grouping <<UUID>>: Value is little endian */
		memcpy(group_uuid, attr->value, attr->value_len);

		if (last && group_end) {
			att_put_u16(last->handle, group_end);
			group_end += group_len;
			plen += group_len;
		}

		/* Grouping initial settings: First grouping */
		if (uuid_type == BT_UUID_UNSPEC) {
			uuid_type = attr->type.type;

			/* start(0xXXXX) | end(0xXXXX) | <<UUID>> */
			group_len = 2 + 2 + bt_uuid_len(&attr->type);

			/* 2: ATT Opcode and Length */
			plen = 2 + group_len;

			/* Size of each Attribute Data */
			opdu[1] = group_len;

			group_end = &opdu[4];
		}

		group_start += group_len;
		group_uuid += group_len;
	}

	if (plen == 0) {
		send_error(attrib, ATT_OP_READ_BY_GROUP_REQ, start,
						ATT_ECODE_ATTR_NOT_FOUND);
		return;
	}

	if (group_end)
		att_put_u16(last->handle, group_end);

	g_attrib_send(attrib, 0, opdu, plen, NULL, NULL, NULL);
}

static void read_by_group(struct btd_device *device, GAttrib *attrib,
					const uint8_t *ipdu, size_t ilen)
{
	uint16_t decoded, start, end;
	bt_uuid_t pattern;

	decoded = dec_read_by_grp_req(ipdu, ilen, &start, &end, &pattern);
	if (decoded == 0) {
		send_error(attrib, ipdu[0], 0x0000, ATT_ECODE_INVALID_PDU);
		return;
	}

	if (start > end || start == 0x0000) {
		send_error(attrib, ipdu[0], start, ATT_ECODE_INVALID_HANDLE);
		return;
	}

	 /*
	  * Restricting Read By Group Type to <<Primary>>.
	  * Removing the checking below requires changes to support
	  * dynamic values(defined in the upper layer) and additional
	  * security verification.
	  */
	if (bt_uuid_cmp(&pattern, &primary_uuid) != 0) {
		send_error(attrib, ipdu[0], start, ATT_ECODE_UNSUPP_GRP_TYPE);
		return;
	}

	read_by_group_resp(attrib, start, end, &pattern);
}

static void value_changed(struct gatt_device *gdev, const uint8_t *ipdu,
								size_t ilen)
{
	uint8_t opdu[g_attrib_get_mtu(gdev->attrib)];
	struct btd_attribute *attr;
	struct notifier *notif;
	GHashTableIter iter;
	GList *list;
	uint16_t handle = att_get_u16(&ipdu[1]);
	gpointer key, value;
	bool cfm = true;
	char *path = g_hash_table_lookup(gdev->chr_objs,
					GINT_TO_POINTER(handle));

	/* Correct PDU for Indication/Notification has at least: opcode
	 * (1 octet) + handle (2 octets) + value parameter (can be 0 or more
	 * octets). So, for malformed PDU (< 3 octets): Ignore */
	if (ilen < 3)
		return;

	if (path == NULL) {
		DBG("Path not found");
		return;
	}

	/* TODO: Missing checking for <<CCC>> */
	list = g_list_find_custom(gdev->database,
				GUINT_TO_POINTER(handle), find_by_handle);
	if (!list)
		goto done;

	attr = list->data;

	if (attr->notifiers == NULL)
		return;

	g_hash_table_iter_init(&iter, attr->notifiers);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		notif = value;

		/* Skip opcode and handle */
		if (!notif->value_cb((uint8_t *) &ipdu[3], ilen - 3,
							notif->user_data))
			cfm = false;
	}

	/*
	 * Below: Processing Indication. If at least one client/watcher
	 * didn't get the data properly ATT confirmation should not be sent.
	 * No further indications to this client shall occur until the
	 * confirmation has been received by the server.
	 *
	 * TODO: Missing a mechanism to avoid blocking indications due
	 * missing confirmation.
	 */
	if (cfm == false)
		return;

done:
	/*
	 * From Core SPEC 4.0 page 1870:
	 * If the attribute handle or the attribute value is invalid, the
	 * client shall send a handle value confirmation in response and
	 * shall discard the handle and value from the received indication.
	 */

	if (ipdu[0] == ATT_OP_HANDLE_IND) {
		opdu[0] = ATT_OP_HANDLE_CNF;
		g_attrib_send(gdev->attrib, 0, opdu, 1, NULL, NULL, NULL);
	}
}

static void write_cmd(struct btd_device *device, GAttrib *attrib,
					const uint8_t *ipdu, size_t ilen)
{
	uint16_t handle;
	GList *list;
	struct btd_attribute *attr;
	size_t vlen;
	uint8_t value[g_attrib_get_mtu(attrib)];
	uint8_t status;

	if (dec_write_cmd(ipdu, ilen, &handle, value, &vlen) == 0)
		return;

	list = g_list_find_custom(local_attribute_db,
				GUINT_TO_POINTER(handle), find_by_handle);

	if (!list)
		return;

	attr = list->data;

	if (attr->write_cb == NULL)
		return;

	status = check_attribute_security(attr, attrib, ipdu[0]);
	if (status)
		return;

	if (!validate_att_operation(list, ATT_OP_WRITE_CMD))
		return;

	attr->write_cb(device, attr, value, vlen, 0, NULL, NULL);
}

static void write_request_result(int err, void *user_data)
{
	struct att_transaction *trans = user_data;
	struct btd_attribute *attr = trans->attr;
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices,
							trans->device);
	uint8_t opdu[ATT_DEFAULT_LE_MTU];
	uint16_t olen;

	if (gdev->attrib == NULL)
		goto done;

	if (err != 0)
		olen = enc_error_resp(ATT_OP_WRITE_REQ, attr->handle,
					errno_to_att(err), opdu, sizeof(opdu));
	else
		olen = enc_write_resp(opdu);

	g_attrib_send(gdev->attrib, 0, opdu, olen, NULL, NULL, NULL);

done:
	g_free(trans);
}

static void write_request(struct btd_device *device, GAttrib *attrib,
					const uint8_t *ipdu, size_t ilen)
{
	GList *list;
	struct att_transaction *trans;
	struct btd_attribute *attr;
	size_t vlen;
	uint16_t handle;
	uint8_t value[g_attrib_get_mtu(attrib)];
	uint8_t status;

	if (dec_write_req(ipdu, ilen, &handle, value, &vlen) == 0) {
		send_error(attrib, ipdu[0], 0x0000, ATT_ECODE_INVALID_PDU);
		return;
	}

	list = g_list_find_custom(local_attribute_db, GUINT_TO_POINTER(handle),
								find_by_handle);
	if (!list) {
		send_error(attrib, ipdu[0], handle, ATT_ECODE_INVALID_HANDLE);
		return;
	}

	attr = list->data;

	if (attr->write_cb == NULL) {
		send_error(attrib, ipdu[0], handle, ATT_ECODE_WRITE_NOT_PERM);
		return;
	}

	status = check_attribute_security(attr, attrib, ipdu[0]);
	if (status) {
		send_error(attrib, ATT_OP_WRITE_REQ, attr->handle, status);
		return;
	}

	if (!validate_att_operation(list, ATT_OP_WRITE_REQ)) {
		send_error(attrib, ipdu[0], handle, ATT_ECODE_WRITE_NOT_PERM);
		return;
	}

	trans = g_new0(struct att_transaction, 1);
	trans->device = device;
	trans->attr = attr;

	attr->write_cb(device, attr, value, vlen, 0, write_request_result,
								trans);
}

static gboolean channel_watch_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices,
								user_data);

	GSList *list;

	DBG("%p Disconnected", user_data);

	for (list = gdev->services; list; ) {
		struct btd_service *service = list->data;

		/*
		 * Get the next service before profile disconnect
		 * callback removes the node from the list: See
		 * btd_gatt_disconnect()
		 */
		list = g_slist_next(list);

		btd_service_disconnect(service);
	}

	return FALSE;
}

static void channel_handler_cb(const uint8_t *ipdu, uint16_t ilen,
							gpointer user_data)
{
	struct btd_device *device = user_data;
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);

	switch (ipdu[0]) {
	case ATT_OP_ERROR:
		break;

	/* Requests */
	case ATT_OP_WRITE_CMD:
		write_cmd(device, gdev->attrib, ipdu, ilen);
		break;

	case ATT_OP_WRITE_REQ:
		write_request(device, gdev->attrib, ipdu, ilen);
		break;

	case ATT_OP_READ_REQ:
		read_request(device, gdev->attrib, ipdu, ilen);
		break;

	case ATT_OP_READ_BY_TYPE_REQ:
		read_by_type(device, gdev->attrib, ipdu, ilen);
		break;

	case ATT_OP_FIND_INFO_REQ:
		find_info_request(device, gdev->attrib, ipdu, ilen);
		break;

	case ATT_OP_MTU_REQ:
	case ATT_OP_FIND_BY_TYPE_REQ:
	case ATT_OP_READ_BLOB_REQ:
	case ATT_OP_READ_MULTI_REQ:
	case ATT_OP_PREP_WRITE_REQ:
	case ATT_OP_EXEC_WRITE_REQ:
	case ATT_OP_SIGNED_WRITE_CMD:
		send_error(gdev->attrib, ipdu[0], 0x0000,
						ATT_ECODE_REQ_NOT_SUPP);
		break;

	case ATT_OP_READ_BY_GROUP_REQ:
		read_by_group(device, gdev->attrib, ipdu, ilen);
		break;

	/* Responses */
	case ATT_OP_MTU_RESP:
	case ATT_OP_FIND_INFO_RESP:
	case ATT_OP_FIND_BY_TYPE_RESP:
	case ATT_OP_READ_BY_TYPE_RESP:
	case ATT_OP_READ_RESP:
	case ATT_OP_READ_BLOB_RESP:
	case ATT_OP_READ_MULTI_RESP:
	case ATT_OP_READ_BY_GROUP_RESP:
	case ATT_OP_WRITE_RESP:
	case ATT_OP_PREP_WRITE_RESP:
	case ATT_OP_EXEC_WRITE_RESP:
	case ATT_OP_HANDLE_CNF:
		break;

	/* Notification & Indication */
	case ATT_OP_HANDLE_NOTIFY:
	case ATT_OP_HANDLE_IND:
		value_changed(gdev, ipdu, ilen);
		break;
	}
}

static GSList *database_get_profiles(GList *database)
{
	GList *list;
	GSList *profiles = NULL;
	bt_uuid_t uuid;

	for (list = database; list; list = g_list_next(list)) {
		struct btd_attribute *attr = list->data;
		char *str;

		if (bt_uuid_cmp(&attr->type, &primary_uuid) != 0)
			continue;

		uuid = (attr->value_len == 2 ?
				att_get_uuid16(attr->value) :
				att_get_uuid128(attr->value));

		str = g_malloc(MAX_LEN_UUID_STR);
		bt_uuid_to_128string(&uuid, str, MAX_LEN_UUID_STR);
		profiles = g_slist_append(profiles, str);
		DBG("Profile: %s", str);
	}

	return profiles;
}

static void probe_profiles(gpointer user_data)
{
	struct find_info *find = user_data;
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices,
							find->device);
	GSList *profiles;

	find->refcount--;
	/*
	 * Find Info Transactions pending? Device probe must
	 * be called when descriptor discovery finishes.
	 */
	if (find->refcount > 0)
		return;

	if (gdev->database == NULL)
		goto done;

	register_objects(find->device, gdev);

	profiles = database_get_profiles(gdev->database);
	device_probe_profiles(find->device, profiles);
	g_slist_free_full(profiles, g_free);

	if (gdev->out == FALSE)
		/* Incoming connection */
		btd_device_service_foreach(find->device,
					connecting_complete, gdev);

	dump_database(gdev->database);

done:
	if (device_is_bonded(find->device) == TRUE)
		database_store(find->device, gdev->database);

	if (gdev->destroy)
		gdev->destroy(gdev->user_data);

	g_free(find);

	/*
	 * After probing, profiles should increment the GAttrib ref
	 * counting assigning it's profile callback to btd_gatt_connect.
	 * One GAttrib reference left belongs to the Generic Attribute
	 * API implemented in this source file.
	 */
}

static void char_declaration_complete(gpointer user_data)
{
	struct btd_device *device = user_data;
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);
	struct find_info *find;
	GList *list;

	/*
	 * At this point the database contains a mirror of the
	 * remote attributes, except the characteristic descriptors.
	 */

	find = g_new0(struct find_info, 1);
	find->device = device; /* Weak reference */

	for (list = gdev->database; list; list = g_list_next(list)) {
		struct btd_attribute *attr, *value, *next;
		uint16_t start, end;

		attr = list->data;

		/* Characteristic declaration? */
		if (bt_uuid_cmp(&chr_uuid, &attr->type) != 0)
			continue;

		/* Access characteristic value */
		list = g_list_next(list);
		if (list == NULL)
			return;

		value = list->data;
		start = value->handle + 1;

		/* Access next attribute: Unknown type */
		list = g_list_next(list);
		if (list != NULL) {
			next = list->data;
			end = next->handle - 1;
		} else
			end = 0xffff;

		if (end < start)
			continue;

		find->refcount++;

		gatt_foreach_by_info(gdev->attrib, start, end,
				descriptor_cb, find, probe_profiles);
	}

	if (find->refcount == 0)
		probe_profiles(find);
}

static void snd_service_complete(gpointer user_data)
{
	struct btd_device *device = user_data;
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);

	gatt_foreach_by_type(gdev->attrib, 0x0001, 0xffff, &chr_uuid,
					char_declaration_create, device,
					char_declaration_complete);
}

static void include_complete(gpointer user_data)
{
	struct btd_device *device = user_data;
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);

	gatt_foreach_by_type(gdev->attrib, 0x0001, 0xffff, &secondary_uuid,
			snd_service_create, device, snd_service_complete);
}

static void prim_service_complete(gpointer user_data)
{
	struct btd_device *device = user_data;
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);
	bt_uuid_t uuid;

	bt_uuid16_create(&uuid, GATT_INCLUDE_UUID);
	gatt_foreach_by_type(gdev->attrib, 0x0001, 0xffff, &uuid,
				include_create, device, include_complete);

}

static void connect_cb(GIOChannel *io, GError *gerr, void *user_data)
{
	struct btd_service *service = user_data;
	struct btd_adapter *adapter;
	struct btd_device *device;
	struct gatt_device *gdev = NULL;
	char src[18], dst[18];
	bdaddr_t sba;
	bdaddr_t dba;
	int err = 0;

	bt_io_get(io, NULL,
			BT_IO_OPT_SOURCE_BDADDR, &sba,
			BT_IO_OPT_DEST_BDADDR, &dba,
			BT_IO_OPT_INVALID);

	ba2str(&sba, src);
	ba2str(&dba, dst);

	DBG("master: %s > %s", src, dst);

	adapter = adapter_find(&sba);
	device = btd_adapter_find_device(adapter, &dba);

	gdev = g_hash_table_lookup(gatt_devices, device);
	if (gdev == NULL) {
		gdev = gatt_device_new(device);
		g_hash_table_insert(gatt_devices, btd_device_ref(device), gdev);
	}

	if (gdev->io) {
		g_io_channel_unref(gdev->io);
		gdev->io = NULL;
	}

	if (gerr) {
		err = gerr->code;
		error("ATT Connect: %s", gerr->message);
		goto done;
	}

	gdev->out = TRUE;
	gdev->attrib = g_attrib_new(io); /* Generic API ref */

	gdev->attrib_id = g_attrib_register(gdev->attrib, GATTRIB_ALL_EVENTS,
				GATTRIB_ALL_HANDLES, channel_handler_cb,
				device, NULL);

	gdev->channel_id = g_io_add_watch_full(io, G_PRIORITY_DEFAULT,
				G_IO_ERR | G_IO_HUP, channel_watch_cb,
				device, (GDestroyNotify) channel_remove);

	/*
	 * When bonding, attribute discovery starts when
	 * gatt_discover_attributes function is called.
	 */
	if (device_is_bonding(device, NULL)) {
		DBG("%s bonding to %s", src, dst);
		return;
	}

	if (gdev->database) {
		/* Attributes already discovered, we may continue informing
		 * the services that the device is connected
		 */
		DBG("Skipping attribute discovery");
		goto done;
	}

	/* Trigger attributes discovery */

	gatt_foreach_by_type(gdev->attrib, 0x0001, 0xffff, &primary_uuid,
				prim_service_create, device,
				prim_service_complete);

	return;

done:
	device_probe_profiles(device, NULL);

	btd_service_connecting_complete(service, err);

	gdev->attrib = g_attrib_ref(gdev->attrib);
	gdev->services = g_slist_append(gdev->services,
					btd_service_ref(service));
}

static void listen_cb(GIOChannel *io, GError *gerr, void *user_data)
{
	struct btd_adapter *adapter;
	struct btd_device *device;
	struct gatt_device *gdev = NULL;
	char src[18], dst[18];
	bdaddr_t sba;
	bdaddr_t dba;

	bt_io_get(io, NULL,
			BT_IO_OPT_SOURCE_BDADDR, &sba,
			BT_IO_OPT_DEST_BDADDR, &dba,
			BT_IO_OPT_INVALID);

	ba2str(&sba, src);
	ba2str(&dba, dst);

	DBG("slave: %s < %s", src, dst);

	adapter = adapter_find(&sba);
	device = btd_adapter_find_device(adapter, &dba);

	gdev = g_hash_table_lookup(gatt_devices, device);

	if (gdev == NULL) {
		/* For incomming connections we may not have an gatt_device */
		gdev = gatt_device_new(device);
		g_hash_table_insert(gatt_devices, btd_device_ref(device), gdev);
	}

	gdev->out = FALSE;
	gdev->attrib = g_attrib_new(io); /* Generic API ref */

	gdev->attrib_id = g_attrib_register(gdev->attrib, GATTRIB_ALL_EVENTS,
				GATTRIB_ALL_HANDLES, channel_handler_cb,
				device, NULL);

	gdev->channel_id = g_io_add_watch_full(io, G_PRIORITY_DEFAULT,
				G_IO_ERR | G_IO_HUP, channel_watch_cb,
				device, (GDestroyNotify) channel_remove);

	if (gdev->database) {
		/* Attributes already discovered, we may continue informing
		 * the services that the device is connected
		 */
		DBG("Skipping attribute discovery");

		btd_device_service_foreach(device, connecting_complete, gdev);

		return;
	}

	/*
	 * Re-connecting: Trigger attribute discovery if there isn't
	 * storage associated with this device. This approach will
	 * keep the compatibility with the devices bonded using the
	 * old attribute storage format.
	 */

	gatt_foreach_by_type(gdev->attrib, 0x0001, 0xffff, &primary_uuid,
				prim_service_create, device,
				prim_service_complete);
}


static int gatt_connect(struct btd_device *device, void *user_data)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);
	GError *gerr = NULL;
	const bdaddr_t *addr;
	char addrstr[18];
	uint8_t addr_type;
	int seclevel;

	addr = device_get_address(device);
	addr_type = device_get_address_type(device);

	ba2str(addr, addrstr);

	/* FIXME: over BR/EDR */
	DBG("Connecting to: %s", addrstr);

	if (device_is_bonded(device))
		seclevel = BT_IO_SEC_MEDIUM;
	else
		seclevel = BT_IO_SEC_LOW;

	gdev->io = bt_io_connect(connect_cb, user_data, NULL, &gerr,
			BT_IO_OPT_SOURCE_BDADDR,
			btd_adapter_get_address(adapter),
			BT_IO_OPT_SOURCE_TYPE, BDADDR_LE_PUBLIC,
			BT_IO_OPT_DEST_BDADDR, addr,
			BT_IO_OPT_DEST_TYPE, addr_type,
			BT_IO_OPT_SEC_LEVEL, seclevel,
			BT_IO_OPT_CID, ATT_CID,
			BT_IO_OPT_INVALID);

	if (gdev->io == NULL) {
		error("Could not connect to %s (%s)", addrstr, gerr->message);
		g_error_free(gerr);
		return -ENOTCONN;
	}

	return 0;
}

int gatt_discover_attributes(struct btd_device *device, void *user_data,
							GDestroyNotify destroy)
{
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);

	if (gdev == NULL) {
		gdev = gatt_device_new(device);
		g_hash_table_insert(gatt_devices, btd_device_ref(device), gdev);
	}

	gdev->destroy = destroy;
	gdev->user_data = user_data;

	/*
	 * Pairing and discovery are executed in parallel. If pairing fails and
	 * the remote disconnects the link, some attributes may already be
	 * discovered. To prevent inconsistent attributes/objects, all attributes
	 * are removed/cleared if the core calls discover attribute twice.
	 */

	if (gdev->database)
		gatt_device_clear(gdev);

	if (gdev->attrib == NULL)
		return gatt_connect(device, NULL);

	gatt_foreach_by_type(gdev->attrib, 0x0001, 0xffff, &primary_uuid,
				prim_service_create, device,
				prim_service_complete);

	return 0;
}

void gatt_device_remove(struct btd_device *device)
{
	if (gatt_devices)
		g_hash_table_remove(gatt_devices, device);
}

void gatt_server_bind(GIOChannel *io)
{
	connect_cb(io, NULL, NULL);
}

int btd_gatt_connect(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);
	int err;

	/*
	 * gdev can be NULL if the device is not bonded: BlueZ has storage
	 * of the discovered attributes for bonded devices only.
	 */
	if (gdev == NULL) {
		gdev = gatt_device_new(device);
		g_hash_table_insert(gatt_devices, btd_device_ref(device), gdev);
	}

	if (gdev->attrib) {
		/* Already connected */
		gdev->attrib = g_attrib_ref(gdev->attrib);
		gdev->services = g_slist_append(gdev->services,
					btd_service_ref(service));

		btd_service_connecting_complete(service, 0);
		return 0;
	}

	/* FIXME: over BR/EDR */
	err = gatt_connect(device, service);
	if (err) {
		btd_service_connecting_complete(service, err);
		return 0;
	}

	return 0;
}

int btd_gatt_disconnect(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct gatt_device *gdev = g_hash_table_lookup(gatt_devices, device);

	if (gdev->io) {
		g_io_channel_unref(gdev->io);
		gdev->io = NULL;
	}

	btd_service_disconnecting_complete(service, 0);

	if (g_slist_find(gdev->services, service) == NULL)
		return -ENOTCONN;

	gdev->services = g_slist_remove(gdev->services, service);
	btd_service_unref(service);

	g_attrib_unref(gdev->attrib);

	return 0;
}

void gatt_init(void)
{
	GError *gerr = NULL;

	DBG("Starting GATT server");

	bredr_io = bt_io_listen(listen_cb, NULL, NULL, NULL, &gerr,
					BT_IO_OPT_SOURCE_BDADDR, BDADDR_ANY,
					BT_IO_OPT_PSM, ATT_PSM,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_INVALID);

	if (bredr_io == NULL) {
		error("%s", gerr->message);
		g_error_free(gerr);
		return;
	}

	/* LE socket */
	le_io = bt_io_listen(listen_cb, NULL, NULL, NULL, &gerr,
					BT_IO_OPT_SOURCE_BDADDR, BDADDR_ANY,
					BT_IO_OPT_SOURCE_TYPE, BDADDR_LE_PUBLIC,
					BT_IO_OPT_CID, ATT_CID,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_INVALID);
	if (le_io == NULL) {
		error("%s", gerr->message);
		g_error_free(gerr);
		/* Doesn't have LE support, continue */
	}

	add_gap();
	add_gatt();

	gatt_dbus_manager_register();

	gatt_devices = g_hash_table_new_full(g_direct_hash, g_direct_equal,
					(GDestroyNotify) btd_device_unref,
					gatt_device_free);
}

void gatt_cleanup(void)
{
	gatt_dbus_manager_unregister();

	if (le_io != NULL) {
		g_io_channel_shutdown(le_io, FALSE, NULL);
		g_io_channel_unref(le_io);
	}

	if (bredr_io != NULL) {
		g_io_channel_shutdown(bredr_io, FALSE, NULL);
		g_io_channel_unref(bredr_io);
	}

	g_hash_table_destroy(gatt_devices);
	gatt_devices = NULL;
}
