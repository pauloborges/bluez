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
	{ GDBUS_METHOD("RegisterServices",
				GDBUS_ARGS({ "services", "ao"}), NULL,
				register_services) },
	{ GDBUS_METHOD("UnregisterServices", NULL, NULL, unregister_services) },
	{ }
};

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
