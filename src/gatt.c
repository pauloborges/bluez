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

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "adapter.h"
#include "device.h"

#include "dbus-common.h"
#include "log.h"
#include "error.h"
#include "uuid.h"
#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "attrib/gatt_lib.h"

#include "gatt.h"

#define SERVICE_INTERFACE "org.bluez.gatt.Service1"
#define CHARACTERISTIC_INTERFACE "org.bluez.gatt.Characteristic1"

/* GATT Profile Attribute types */
#define GATT_PRIM_SVC_UUID		0x2800
#define GATT_SND_SVC_UUID		0x2801
#define GATT_CHARAC_UUID		0x2803

struct characteristic {
	char *path;
	char *uuid;
};

struct service {
	char *path;
	char *uuid;
	GDBusClient *client;
	GSList *chrs;
};

struct application {
	char *owner;
	GSList *services;
	unsigned int watch;
};

static GSList *applications = NULL;

struct btd_attribute {
	uint16_t handle;
	bt_uuid_t type;
	btd_attr_read_t read_cb;
	btd_attr_write_t write_cb;
	uint16_t value_len;
	uint8_t value[0];
};

struct device_root {
	GList *database;
	const char *path;
};

struct attribute_iface {
	struct btd_attribute *attr;
	char *path;
};

static GList *local_attribute_db = NULL;
static uint16_t next_handle = 1;

static struct btd_attribute *new_const_attribute(bt_uuid_t *type,
							uint8_t *value,
							uint16_t len)
{
	struct btd_attribute *attr = g_malloc0(sizeof(struct btd_attribute) +
						len);

	memcpy(&attr->type, type, sizeof(*type));
	memcpy(&attr->value, value, len);
	attr->value_len = len;

	return attr;
}

static struct btd_attribute *new_attribute(bt_uuid_t *type,
						btd_attr_read_t read_cb,
						btd_attr_write_t write_cb)
{
	struct btd_attribute *attr = g_new0(struct btd_attribute, 1);

	memcpy(&attr->type, type, sizeof(*type));
	attr->read_cb = read_cb;
	attr->write_cb = write_cb;

	return attr;
}

static void add_attribute(struct btd_attribute *attr)
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

static GList *insert_attribute(GList *attr_database, struct btd_attribute *attr)
{
	return g_list_insert_sorted(attr_database, attr, attribute_cmp);
}

struct btd_attribute *btd_gatt_add_service(bt_uuid_t *uuid, bool primary)
{
	struct btd_attribute *attr;
	bt_uuid_t type;
	uint16_t len = bt_uuid_len(uuid);
	uint8_t value[len];

	/* Set attribute type */
	if (primary)
		bt_uuid16_create(&type, GATT_PRIM_SVC_UUID);
	else
		bt_uuid16_create(&type, GATT_SND_SVC_UUID);

	/* Set attribute value */
	att_put_uuid(*uuid, value);

	attr = new_const_attribute(&type, value, len);

	add_attribute(attr);

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
void btd_gatt_remove_service(struct btd_attribute *service)
{
	GList *list = g_list_find(local_attribute_db, service);

	if (list == NULL)
		return;

	/* Remove service declaration attribute */
	g_free(list->data);
	list = g_list_delete_link(list, list);

	/* Remove all characteristics until next service declaration */
	while (list && !is_service(list->data)) {
		g_free(list->data);
		list = g_list_delete_link(list, list);
	}
}

struct btd_attribute *btd_gatt_add_char(bt_uuid_t *uuid, uint8_t properties,
					btd_attr_read_t read_cb,
					btd_attr_write_t write_cb)
{
	struct btd_attribute *char_decl, *char_value;
	bt_uuid_t type;
	/* Characteristic properties (1 octet), characteristic value attribute
	 * handle (2 octets) and characteristic UUID (2 or 16 octets).
	 */
	uint16_t len = 1 + 2 + bt_uuid_len(uuid);
	uint8_t value[len];

	/*
	 * Create and add the characteristic declaration attribute
	 */
	bt_uuid16_create(&type, GATT_CHARAC_UUID);

	value[0] = properties;

	/* Since we don't know yet the characteristic value attribute handle,
	 * we skip and set it later.
	 */

	att_put_uuid(*uuid, &value[3]);

	char_decl = new_const_attribute(&type, value, len);
	add_attribute(char_decl);

	/*
	 * Create and add the characteristic value attribute
	 */
	char_value = new_attribute(uuid, read_cb, write_cb);
	add_attribute(char_value);

	/* Update characteristic value handle in characteristic declaration
	 * attribute.
	 */
	att_put_u16(char_value->handle, &char_decl->value[1]);

	return char_value;
}

void btd_gatt_add_char_desc(bt_uuid_t *uuid, btd_attr_read_t read_cb,
				btd_attr_write_t write_cb)
{
	struct btd_attribute *attr = new_attribute(uuid, read_cb, write_cb);

	add_attribute(attr);
}

GSList *btd_gatt_get_services(GList *database, bt_uuid_t *service)
{
	GList *list;
	GSList *services = NULL;

	for (list = g_list_first(database); list; list = g_list_next(list)) {
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

static bool is_characteristic(struct btd_attribute *attr)
{
	if (attr->type.value.u16 == GATT_CHARAC_UUID)
		return true;
	else
		return false;
}

GSList *btd_gatt_get_chars_decl(GList *database, struct btd_attribute *service,
							bt_uuid_t *type)
{
	GList *list = g_list_find_custom(database, service, attribute_cmp);
	GSList *chars = NULL;

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

struct btd_attribute *btd_gatt_get_char_desc(GList *database,
						struct btd_attribute *chr,
						bt_uuid_t *type)
{
	GList *list = g_list_find_custom(database, chr, attribute_cmp);

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

struct btd_attribute *btd_gatt_get_char_value(GList *database,
						struct btd_attribute *chr)
{
	GList *list = g_list_find_custom(database, chr, attribute_cmp);

	if (!list)
		return NULL;

	list = g_list_next(list);
	return list->data;
}

static struct characteristic *new_characteristic(const char *path,
							const char *uuid)
{
	struct characteristic *chr;

	chr = g_new0(struct characteristic, 1);

	chr->path = g_strdup(path);
	chr->uuid = g_strdup(uuid);

	return chr;
}

static void destroy_char(void *user_data)
{
	struct characteristic *chr = user_data;

	g_free(chr->path);
	g_free(chr->uuid);
	g_free(chr);
}

static void destroy_service(void *data)
{
	struct service *srv = data;

	g_free(srv->path);
	g_free(srv->uuid);

	g_dbus_client_unref(srv->client);

	g_free(srv);
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	struct service *srv = user_data;
	DBusMessageIter iter;
	const char *interface;
	const char *path;
	const char *uuid;

	interface = g_dbus_proxy_get_interface(proxy);

	DBG("iface %s", interface);

	if (g_strcmp0(interface, CHARACTERISTIC_INTERFACE) == 0) {
		struct characteristic *chr;

		path = g_dbus_proxy_get_path(proxy);

		if (!g_dbus_proxy_get_property(proxy, "UUID", &iter))
			return;

		dbus_message_iter_get_basic(&iter, &uuid);

		chr = new_characteristic(path, uuid);

		srv->chrs = g_slist_append(srv->chrs, chr);

		DBG("new char %s uuid %s", path, uuid);
	} else if (g_strcmp0(interface, SERVICE_INTERFACE) == 0) {
		if (srv->uuid != NULL)
			return;

		g_dbus_proxy_get_property(proxy, "UUID", &iter);

		dbus_message_iter_get_basic(&iter, &uuid);

		srv->uuid = g_strdup(uuid);

		DBG("uuid %s", uuid);
	}
}

static int char_by_path(const void *a, const void *b)
{
	const struct characteristic *chr = a;
	const char *path = b;

	return g_strcmp0(chr->path, path);
}

static void proxy_removed(GDBusProxy *proxy, void *user_data)
{
	GSList *l;
	struct service *srv = user_data;
	struct characteristic *chr;
	const char *interface;
	const char *path;

	interface = g_dbus_proxy_get_interface(proxy);

	DBG("iface %s", interface);

	if (g_strcmp0(interface, CHARACTERISTIC_INTERFACE) != 0)
		return;

	path = g_dbus_proxy_get_path(proxy);

	l = g_slist_find_custom(srv->chrs, path, char_by_path);
	if (l == NULL)
		return;

	chr = l->data;

	srv->chrs = g_slist_remove(srv->chrs, chr);

	destroy_char(chr);
}

static void property_changed(GDBusProxy *proxy, const char *name,
					DBusMessageIter *iter, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	DBG("iface %s", interface);
}

static struct service *new_service(const char *sender, const char *path)
{
	struct service *srv;

	srv = g_new0(struct service, 1);

	srv->path = g_strdup(path);
	srv->client = g_dbus_client_new(btd_get_dbus_connection(),
							sender, path);
	if (srv->client == NULL) {
		destroy_service(srv);
		return NULL;
	}

	g_dbus_client_set_proxy_handlers(srv->client, proxy_added,
					proxy_removed, property_changed, srv);

	return srv;
}

static void destroy_application(void *data)
{
	struct application *app = data;

	DBG("app %p", app);

	g_free(app->owner);
	g_slist_free_full(app->services, destroy_service);

	if (app->watch > 0)
		g_dbus_remove_watch(btd_get_dbus_connection(), app->watch);

	applications = g_slist_remove(applications, app);

	g_free(app);
}

static void application_disconnected(DBusConnection *conn, void *user_data)
{
	destroy_application(user_data);
}

static struct application *new_application(const char *sender)
{
	struct application *app;

	app = g_new0(struct application, 1);

	app->watch = g_dbus_add_disconnect_watch(btd_get_dbus_connection(),
				sender, application_disconnected, app, NULL);
	if (app->watch == 0) {
		g_free(app);
		return NULL;
	}

	app->owner = g_strdup(sender);

	applications = g_slist_prepend(applications, app);

	return app;
}

static DBusMessage *register_services(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct application *app;
	DBusMessageIter args, iter;

	DBG("Registering GATT Service");

	if (dbus_message_iter_init(msg, &args) == false)
		goto invalid;

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY)
		goto invalid;

	app = new_application(dbus_message_get_sender(msg));
	if (app == NULL)
		return btd_error_failed(msg, "Not enough resources");

	DBG("new app %p", app);

	dbus_message_iter_recurse(&args, &iter);

	while (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_OBJECT_PATH) {
		const char *path;

		dbus_message_iter_get_basic(&iter, &path);

		app->services = g_slist_append(app->services,
						new_service(app->owner, path));

		DBG("path %s", path);

		dbus_message_iter_next(&iter);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

invalid:
	return btd_error_invalid_args(msg);
}

static DBusMessage *unregister_services(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable methods[] = {
	{ GDBUS_EXPERIMENTAL_METHOD("RegisterServices",
				GDBUS_ARGS({ "services", "ao"}), NULL,
				register_services) },
	{ GDBUS_EXPERIMENTAL_METHOD("UnregisterServices", NULL, NULL,
				unregister_services) },
	{ }
};

static gboolean service_property_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct attribute_iface *iface = data;
	struct btd_attribute *attr = iface->attr;
	bt_uuid_t uuid, uuid128;
	char uuidstr[MAX_LEN_UUID_STR];
	const char *str = uuidstr;

	if (attr->value_len == 2) {
		uuid = att_get_uuid16(attr->value);
		bt_uuid_to_uuid128(&uuid, &uuid128);
	} else
		uuid128 = att_get_uuid128(attr->value);

	bt_uuid_to_string(&uuid128, uuidstr, sizeof(uuidstr));

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &str);

	return TRUE;
}

static gboolean service_property_get_includes(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	return TRUE;
}

static gboolean service_property_exists_includes(
					const GDBusPropertyTable *property,
					void *data)
{
	return FALSE;
}

static const GDBusPropertyTable service_properties[] = {
	{ "UUID", "s", service_property_get_uuid },
	{ "Includes", "as", service_property_get_includes, NULL,
					service_property_exists_includes },
	{ }
};


static DBusMessage *chr_read_value(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	return dbus_message_new_method_return(msg);
}

static DBusMessage *chr_write_value(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable chr_methods[] = {
	{ GDBUS_EXPERIMENTAL_METHOD("ReadValue", GDBUS_ARGS({"offset", "q"}),
				GDBUS_ARGS({"value", "ay"}),
				chr_read_value) },
	{ GDBUS_EXPERIMENTAL_METHOD("WriteValue",
				GDBUS_ARGS({"offset", "q"}, {"value", "ay"}),
				NULL, chr_write_value) },
	{ }
};

static gboolean chr_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct attribute_iface *iface = data;
	struct btd_attribute *attr = iface->attr;
	bt_uuid_t uuid, uuid128;
	char uuidstr[MAX_LEN_UUID_STR];
	const char *str = uuidstr;

	if (attr->value_len - 3 == 2) {
		uuid = att_get_uuid16(&attr->value[3]);
		bt_uuid_to_uuid128(&uuid, &uuid128);
	} else if (attr->value_len - 3 == 16)
		uuid128 = att_get_uuid128(&attr->value[3]);

	bt_uuid_to_string(&uuid128, uuidstr, sizeof(uuidstr));

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &str);

	return TRUE;
}

static gboolean chr_get_value(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	return TRUE;
}

static void chr_set_value(const GDBusPropertyTable *property,
				DBusMessageIter *iter,
				GDBusPendingPropertySet id, void *user_data)
{
	g_dbus_pending_property_error(id, ERROR_INTERFACE ".Failed",
							"Not Supported");
}

static gboolean chr_exist_value(const GDBusPropertyTable *property,
								void *data)
{
	return FALSE;
}

static gboolean chr_get_perms(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	return TRUE;
}

static gboolean chr_exist_perms(const GDBusPropertyTable *property,
								void *data)
{
	return FALSE;
}

static gboolean chr_get_auth(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	return TRUE;
}

static gboolean chr_exist_auth(const GDBusPropertyTable *property, void *data)
{
	return FALSE;
}

static gboolean chr_get_props(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	return TRUE;
}

static gboolean chr_exist_props(const GDBusPropertyTable *property,
								void *data)
{
	return FALSE;
}

static gboolean chr_get_descriptors(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	return TRUE;
}

static void chr_set_descriptors(const GDBusPropertyTable *property,
				DBusMessageIter *iter,
				GDBusPendingPropertySet id, void *user_data)
{
	g_dbus_pending_property_success(id);
}

static gboolean chr_exist_descriptors(const GDBusPropertyTable *property,
								void *data)
{
	return FALSE;
}

static const GDBusPropertyTable chr_properties[] = {
	{ "UUID", "s", chr_get_uuid, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Value", "ay", chr_get_value, chr_set_value, chr_exist_value,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Permissions", "y", chr_get_perms, NULL, chr_exist_perms,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Authenticate", "b", chr_get_auth, NULL, chr_exist_auth,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Properties", "y", chr_get_props, NULL, chr_exist_props,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Descriptors", "a{a{sv}}", chr_get_descriptors, chr_set_descriptors,
		chr_exist_descriptors, G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ }
};

static void insert_primary_service(uint8_t status, uint16_t handle,
					uint8_t *value, size_t vlen,
					void *user_data)
{
	struct device_root *root = user_data;
	struct attribute_iface *iface;
	struct btd_attribute *attr;
	bt_uuid_t uuid;

	DBG("status %d handle %#4x", status, handle);

	bt_uuid16_create(&uuid, GATT_PRIM_SVC_UUID);

	attr = new_const_attribute(&uuid, value, vlen);
	attr->handle = handle;

	root->database = insert_attribute(root->database, attr);

	iface = g_new0(struct attribute_iface, 1);
	iface->attr = attr;
	iface->path = g_strdup_printf("%s/service%d", root->path, handle);

	/* FIXME: free how? */
	if (g_dbus_register_interface(btd_get_dbus_connection(),
					iface->path, SERVICE_INTERFACE,
					NULL, NULL, service_properties, iface,
					NULL) == FALSE)
		error("Unable to register service interface for %s",
							iface->path);
}

static void insert_secondary_service(uint8_t status, uint16_t handle,
					uint8_t *value, size_t vlen,
					void *user_data)
{
	struct device_root *root = user_data;
	struct btd_attribute *attr;
	bt_uuid_t uuid;

	DBG("status %d handle %#4x", status, handle);

	bt_uuid16_create(&uuid, GATT_SND_SVC_UUID);

	attr = new_const_attribute(&uuid, value, vlen);
	attr->handle = handle;

	root->database = insert_attribute(root->database, attr);
}

static struct btd_attribute *find_parent_service(GList *database,
						struct btd_attribute *attr)
{
	GList *l;

	l = g_list_find(database, attr);
	if (l == NULL)
		return NULL;

	for (; l; l = g_list_previous(l)) {
		struct btd_attribute *a = l->data;

		if (is_service(a))
			return a;
	}

	return NULL;
}

static void insert_char_declaration(uint8_t status, uint16_t handle,
					uint8_t *value, size_t vlen,
					void *user_data)
{
	struct device_root *root = user_data;
	struct attribute_iface *iface;
	struct btd_attribute *attr, *parent;
	bt_uuid_t uuid, value_uuid;
	uint16_t value_handle;

	DBG("status %d handle %#4x", status, handle);

	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);

	attr = new_const_attribute(&uuid, value, vlen);
	attr->handle = handle;

	iface = g_new0(struct attribute_iface, 1);
	iface->attr = attr;

	root->database = insert_attribute(root->database, attr);
	parent = find_parent_service(root->database, attr);

	iface->path = g_strdup_printf("%s/service%d/characteristics%d",
					root->path, parent->handle, handle);

	value_handle = att_get_u16(&value[1]);

	vlen -= 3; /* Discarding 2 (handle) + 1 (properties) bytes */

	if (vlen == 2)
		value_uuid = att_get_uuid16(&value[3]);
	else if (vlen == 16)
		value_uuid = att_get_uuid128(&value[3]);

	/* FIXME: missing callbacks */
	attr = new_attribute(&value_uuid, NULL, NULL);
	attr->handle = value_handle;

	root->database = insert_attribute(root->database, attr);

	if (g_dbus_register_interface(btd_get_dbus_connection(), iface->path,
					CHARACTERISTIC_INTERFACE,
					chr_methods, NULL, chr_properties,
					iface, NULL) == FALSE)
		error("Couldn't register characteristic interface");
}

static void insert_include(uint8_t status, uint16_t handle,
					uint8_t *value, size_t vlen,
					void *user_data)
{
	struct device_root *root = user_data;
	struct btd_attribute *attr;
	bt_uuid_t uuid;

	DBG("status %d handle %#4x", status, handle);

	bt_uuid16_create(&uuid, GATT_INCLUDE_UUID);

	attr = new_const_attribute(&uuid, value, vlen);
	attr->handle = handle;

	root->database = insert_attribute(root->database, attr);
}

static void insert_char_descriptor(uint8_t status, uint16_t handle,
					bt_uuid_t *type, void *user_data)
{
	struct device_root *root = user_data;
	struct btd_attribute *attr;
	GList *l;

	DBG("status %d handle %#4x", status, handle);

	attr = new_attribute(type, NULL, NULL);
	attr->handle = handle;

	l = g_list_find_custom(root->database, attr, attribute_cmp);
	if (l != NULL) {
		g_free(attr);
		return;
	}

	root->database = insert_attribute(root->database, attr);
}

void gatt_discover_attributes(struct btd_device *device)
{
	GAttrib *attrib;
	bt_uuid_t uuid;
	struct device_root root;

	attrib = device_get_attrib(device);
	if (attrib == NULL)
		return;

	root.database = device_get_attribute_database(device);
	root.path = device_get_path(device);

	DBG("device %p", device);

	bt_uuid16_create(&uuid, GATT_PRIM_SVC_UUID);
	gatt_foreach_by_type(attrib, 0x0001, 0xffff, &uuid,
					insert_primary_service, &root);

	bt_uuid16_create(&uuid, GATT_SND_SVC_UUID);
	gatt_foreach_by_type(attrib, 0x0001, 0xffff, &uuid,
					insert_secondary_service, &root);

	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	gatt_foreach_by_type(attrib, 0x0001, 0xffff, &uuid,
					insert_char_declaration, &root);

	bt_uuid16_create(&uuid, GATT_INCLUDE_UUID);
	gatt_foreach_by_type(attrib, 0x0001, 0xffff, &uuid,
					insert_include, &root);

	gatt_foreach_by_info(attrib, 0x0001, 0xffff, insert_char_descriptor,
					&root);
}

void btd_gatt_service_manager_init(void)
{
	g_dbus_register_interface(btd_get_dbus_connection(),
			"/org/bluez", "org.bluez.gatt.ServiceManager1",
			methods, NULL, NULL, NULL, NULL);
}

void btd_gatt_service_manager_cleanup(void)
{
	g_dbus_unregister_interface(btd_get_dbus_connection(),
			"/org/bluez", "org.bluez.gatt.ServiceManager1");
}
