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

#include <errno.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "adapter.h"
#include "device.h"

#include "lib/uuid.h"

#include "dbus-common.h"
#include "log.h"

#include "attrib/att.h"

#include "error.h"
#include "gatt.h"
#include "gatt-dbus.h"

#define SERVICE_INTERFACE "org.bluez.gatt.Service1"
#define CHARACTERISTIC_INTERFACE "org.bluez.gatt.Characteristic1"

#define REGISTER_TIMER         1

struct external_characteristic {
	char *path;
	bt_uuid_t uuid;
	uint8_t properties;
	int read_sec;
	int write_sec;
	int key_size;
	GDBusProxy *proxy;
};

struct external_service {
	char *path;
	bt_uuid_t uuid;
};

struct external_app {
	char *owner;
	GSList *services;
	GSList *prim_services;
	GSList *chrs;
	GDBusClient *client;
	unsigned int watch;
	guint register_timer;
};

struct service_iface {
	struct btd_device *device;
	struct btd_attribute *attr;
	char *uuid;
};

struct char_iface {
	struct btd_device *device;
	struct btd_attribute *attr;
	char *uuid;
	char *path;			/* Object path */
	uint8_t *value;			/* Cached value */
	size_t vlen;			/* Value length */
	uint8_t properties;		/* Bit field. See Core page 1898 */
	unsigned int watch;		/* Tracks value changed */
};

struct external_read_data {
	btd_attr_read_result_t func;
	void *user_data;
};

struct external_write_data {
	btd_attr_write_result_t func;
	uint8_t *value;
	size_t vlen;
	uint16_t offset;
	void *user_data;
};

static GSList *external_apps = NULL;
static GHashTable *proxy_hash = NULL;

static void char_iface_destroy(gpointer user_data)
{
	struct char_iface *iface = user_data;

	if (proxy_hash)
		g_hash_table_remove(proxy_hash, iface->attr);

	if (iface->watch)
		btd_gatt_remove_notifier(iface->attr, iface->watch);

	g_free(iface->uuid);
	g_free(iface->path);
	g_free(iface->value);
	g_free(iface);
}

static void service_iface_destroy(gpointer user_data)
{
	struct service_iface *iface = user_data;

	g_free(iface->uuid);
	g_free(iface);
}


static int seclevel_string2int(const char *level)
{
	if (strcmp("high", level) == 0)
		return BT_SECURITY_HIGH;
	else if (strcmp("medium", level) == 0)
		return BT_SECURITY_MEDIUM;
	else
		return BT_SECURITY_LOW;
}

static void destroy_char(void *user_data)
{
	struct external_characteristic *echr = user_data;

	g_free(echr->path);
	g_dbus_proxy_unref(echr->proxy);
	g_free(echr);
}

static void remove_local_service(void *data)
{
	struct btd_attribute *attr = data;

	btd_gatt_remove_service(attr);
}

static void destroy_service(void *data)
{
	struct external_service *srv = data;

	g_free(srv->path);
	g_free(srv);
}

static void read_char_setup(DBusMessageIter *iter, void *user_data)
{
	uint16_t value[] = { 0x0000 };

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, value);
}

static void read_char_reply(DBusMessage *msg, void *user_data)
{
	struct external_read_data *rdata = user_data;
	DBusMessageIter args, iter;
	const uint8_t *value;
	int len;

	if (dbus_message_iter_init(msg, &args) == false)
		goto invalid;

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY)
		goto invalid;

	dbus_message_iter_recurse(&args, &iter);
	dbus_message_iter_get_fixed_array(&iter, &value, &len);

	rdata->func(0, (uint8_t *) value, len, rdata->user_data);

	return;

invalid:
	rdata->func(ATT_ECODE_IO, NULL, 0, rdata->user_data);
	DBG("Invalid parameters");
}

static void read_char_destroy(void *user_data)
{
	g_free(user_data);
}

static void read_external_char_cb(struct btd_device *device,
				struct btd_attribute *attr,
				btd_attr_read_result_t result, void *user_data)
{
	GDBusProxy *proxy;
	struct external_read_data *rdata;

	rdata = g_new0(struct external_read_data, 1);
	rdata->func = result;
	rdata->user_data = user_data;

	proxy = g_hash_table_lookup(proxy_hash, attr);

	if (!g_dbus_proxy_method_call(proxy, "ReadValue",
						read_char_setup,
						read_char_reply,
						rdata,
						read_char_destroy)) {
		error("Could not call ReadValue dbus method");
		result(ATT_ECODE_IO, NULL, 0, user_data);
		read_char_destroy(rdata);
		return;
	}

	DBG("Server: Read characteristic callback %s",
					g_dbus_proxy_get_path(proxy));
}

static void write_char_setup(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter array;
	struct external_write_data *wdata = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &wdata->offset);

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING,
					&array);

	if (!dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
					&wdata->value, wdata->vlen))
		DBG("Could not append value to D-Bus message");

	dbus_message_iter_close_container(iter, &array);
}

static void write_char_reply(DBusMessage *msg, void *user_data)
{
	struct external_write_data *wdata = user_data;

	if (!wdata->func)
		return;

	wdata->func(0, wdata->user_data);
}

static void write_char_destroy(void *user_data)
{
	g_free(user_data);
}

static void write_external_char_cb(struct btd_device *device,
			struct btd_attribute *attr,
			uint8_t *value, size_t len, uint16_t offset,
			btd_attr_write_result_t result, void *user_data)
{
	GDBusProxy *proxy;
	struct external_write_data *wdata;

	wdata = g_new0(struct external_write_data, 1);
	wdata->func = result;
	wdata->value = value;
	wdata->vlen = len;
	wdata->offset = offset;
	wdata->user_data = user_data;

	proxy = g_hash_table_lookup(proxy_hash, attr);

	if (!g_dbus_proxy_method_call(proxy, "WriteValue",
					write_char_setup,
					write_char_reply,
					wdata,
					write_char_destroy)) {
		error("Could not call WriteValue D-Bus method");
		result(ATT_ECODE_IO, user_data);
		write_char_destroy(wdata);
		return;
	}

	DBG("Server: Write characteristic callback %s",
					g_dbus_proxy_get_path(proxy));
}

static int service_path_cmp(gconstpointer a, gconstpointer b)
{
	const struct external_service *esrv = a;
	const char *path = b;

	return strcmp(esrv->path, path);
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	struct external_app *eapp = user_data;
	DBusMessageIter iter;
	const char *interface;
	const char *path;
	const char *uuid;

	interface = g_dbus_proxy_get_interface(proxy);
	path = g_dbus_proxy_get_path(proxy);

	DBG("path %s iface %s", path, interface);

	if (g_strcmp0(interface, CHARACTERISTIC_INTERFACE) == 0) {
		struct external_characteristic *echr;
		const char *security;
		int read_sec = BT_SECURITY_LOW, write_sec = BT_SECURITY_LOW;
		uint8_t properties, key_size = 0;
		gboolean ret;

		if (!g_dbus_proxy_get_property(proxy, "UUID", &iter))
			return;

		dbus_message_iter_get_basic(&iter, &uuid);

		ret = g_dbus_proxy_get_property(proxy, "ReadSecurity", &iter);
		if (ret && dbus_message_iter_get_arg_type(&iter)
						== DBUS_TYPE_STRING) {
			dbus_message_iter_get_basic(&iter, &security);
			DBG("ReadSecurity: %s", security);
			read_sec = seclevel_string2int(security);
		}

		ret = g_dbus_proxy_get_property(proxy, "WriteSecurity", &iter);
		if (ret && dbus_message_iter_get_arg_type(&iter)
						== DBUS_TYPE_STRING) {
			dbus_message_iter_get_basic(&iter, &security);
			DBG("WriteSecurity: %s", security);
			write_sec = seclevel_string2int(security);
		}

		if ((read_sec != BT_SECURITY_LOW ||
			write_sec != BT_SECURITY_LOW) &&
			g_dbus_proxy_get_property(proxy, "KeySize", &iter)) {
			dbus_message_iter_get_basic(&iter, &key_size);
			DBG("KeySize: %d", key_size);
		}

		if (!g_dbus_proxy_get_property(proxy, "Properties", &iter)) {
			error("Could not get Properties");
			return;
		}

		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BYTE) {
			error("Invalid type for Properties");
			return;
		}

		dbus_message_iter_get_basic(&iter, &properties);

		echr = g_new0(struct external_characteristic, 1);
		echr->path = g_strdup(path);
		bt_string_to_uuid(&echr->uuid, uuid);
		echr->properties = properties;
		echr->read_sec = read_sec;
		echr->write_sec = write_sec;
		echr->key_size = key_size;
		echr->proxy = g_dbus_proxy_ref(proxy);

		eapp->chrs = g_slist_append(eapp->chrs, echr);
	} else if (g_strcmp0(interface, SERVICE_INTERFACE) == 0) {
		struct external_service *esrv;
		GSList *l;

		l = g_slist_find_custom(eapp->services, path, service_path_cmp);
		if (l == NULL) {
			DBG("Ignoring service not registered: %s", path);
			return;
		}

		if (!g_dbus_proxy_get_property(proxy, "UUID", &iter)) {
			error("Could not get UUID");
			return;
		}

		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
			error("Invalid type for UUID");
			return;
		}

		dbus_message_iter_get_basic(&iter, &uuid);

		esrv = l->data;
		bt_string_to_uuid(&esrv->uuid, uuid);
	}
}

static void proxy_removed(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	DBG("iface %s", interface);
}

static void property_changed(GDBusProxy *proxy, const char *name,
					DBusMessageIter *iter, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	DBG("iface %s", interface);
}

static void destroy_external_app(void *data)
{
	struct external_app *eapp = data;

	DBG("app %p", eapp);

	if (eapp->register_timer > 0)
		g_source_remove(eapp->register_timer);

	g_free(eapp->owner);

	g_slist_free_full(eapp->prim_services, remove_local_service);
	g_slist_free_full(eapp->services, destroy_service);
	g_slist_free_full(eapp->chrs, destroy_char);

	if (eapp->watch > 0)
		g_dbus_remove_watch(btd_get_dbus_connection(), eapp->watch);

	g_dbus_client_unref(eapp->client);

	external_apps = g_slist_remove(external_apps, eapp);

	g_free(eapp);
}

static void external_app_disconnected(DBusConnection *conn, void *user_data)
{
	destroy_external_app(user_data);
}

static struct external_app *new_external_app(DBusConnection *conn,
							const char *sender)
{
	struct external_app *eapp;
	GDBusClient *client;

	client = g_dbus_client_new(conn, sender, "/");
	if (client == NULL)
		return NULL;

	eapp = g_new0(struct external_app, 1);

	eapp->watch = g_dbus_add_disconnect_watch(btd_get_dbus_connection(),
				sender, external_app_disconnected, eapp, NULL);
	if (eapp->watch == 0) {
		g_dbus_client_unref(client);
		g_free(eapp);
		return NULL;
	}

	eapp->owner = g_strdup(sender);
	eapp->client = client;

	g_dbus_client_set_proxy_handlers(client, proxy_added,
				proxy_removed, property_changed, eapp);

	external_apps = g_slist_prepend(external_apps, eapp);

	return eapp;
}

static void register_external_chars(gpointer a, gpointer b)
{
	struct external_characteristic *echr = a;
	struct btd_attribute *attr;
	const char *path = b;

	if (!g_str_has_prefix(echr->path, path))
		return;

	attr = btd_gatt_add_char(&echr->uuid, echr->properties,
					read_external_char_cb,
					write_external_char_cb, echr->read_sec,
					echr->write_sec, echr->key_size);

	g_hash_table_insert(proxy_hash, attr, g_dbus_proxy_ref(echr->proxy));

	DBG("new char %s", echr->path);
}

static gboolean finish_register(gpointer user_data)
{
	struct external_app *eapp = user_data;
	GSList *list;

	eapp->register_timer = 0;

	for (list = eapp->services; list; list = g_slist_next(list)) {
		struct external_service *esrv = list->data;
		struct btd_attribute *attr;

		attr = btd_gatt_add_service(&esrv->uuid, true);
		eapp->prim_services = g_slist_append(eapp->prim_services,
								attr);
		DBG("new service %s", esrv->path);

		g_slist_foreach(eapp->chrs, register_external_chars,
							esrv->path);
	}

	g_slist_free_full(eapp->services, destroy_service);
	eapp->services = NULL;

	g_slist_free_full(eapp->chrs, destroy_char);
	eapp->chrs = NULL;

	return FALSE;
}

static DBusMessage *register_services(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct external_app *eapp;
	DBusMessageIter args, iter;

	DBG("Registering GATT Service");

	if (dbus_message_iter_init(msg, &args) == false)
		goto invalid;

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY)
		goto invalid;

	eapp = new_external_app(conn, dbus_message_get_sender(msg));
	if (eapp == NULL)
		return btd_error_failed(msg, "Not enough resources");

	DBG("new app %p", eapp);

	dbus_message_iter_recurse(&args, &iter);

	while (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_OBJECT_PATH) {
		struct external_service *esrv;
		const char *path;

		dbus_message_iter_get_basic(&iter, &path);

		esrv = g_new0(struct external_service, 1);
		esrv->path = g_strdup(path);

		eapp->services = g_slist_append(eapp->services, esrv);

		DBG("path %s", path);

		dbus_message_iter_next(&iter);
	}

	eapp->register_timer = g_timeout_add_seconds(REGISTER_TIMER,
							finish_register, eapp);

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
	struct service_iface *iface = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &iface->uuid);

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
	{ "UUID", "s", service_property_get_uuid, NULL, NULL,
				G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Includes", "as", service_property_get_includes, NULL,
				service_property_exists_includes,
				G_DBUS_PROPERTY_FLAG_EXPERIMENTAL},
	{ }
};

static void read_value_response(int err, uint8_t *value, size_t len,
					void *user_data)
{
	DBusMessage *reply, *msg = user_data;
	DBusMessageIter iter, array;

	if (err) {
		switch (err) {
		case ECOMM:
			reply = btd_error_not_connected(msg);
			break;
		default:
			reply = btd_error_failed(msg, strerror(err));
		}

		goto done;
	}

	reply = dbus_message_new_method_return(msg);

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &array);
	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
						&value, len);

	dbus_message_iter_close_container(&iter, &array);

done:
	g_dbus_send_message(btd_get_dbus_connection(), reply);
}

static DBusMessage *remote_chr_read_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct char_iface *iface = user_data;

	btd_gatt_read_attribute(iface->device, iface->attr,
				read_value_response, dbus_message_ref(msg));

	return NULL;
}

static void write_value_response(int err, void *user_data)
{
	DBusMessage *reply, *msg = user_data;

	if (err) {
		switch (err) {
		case ECOMM:
			reply = btd_error_not_connected(msg);
			break;
		default:
			reply = btd_error_failed(msg, strerror(err));
		}

		goto done;
	}

	reply = dbus_message_new_method_return(msg);

done:
	g_dbus_send_message(btd_get_dbus_connection(), reply);
}

static DBusMessage *remote_chr_write_value(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct char_iface *iface = user_data;
	DBusMessageIter args, iter;
	const uint8_t *value;
	uint16_t offset;
	int len;

	if (dbus_message_iter_init(msg, &args) == false)
		goto invalid;

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_UINT16)
		goto invalid;

	dbus_message_iter_get_basic(&args, &offset);

	dbus_message_iter_next(&args);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY)
		goto invalid;

	dbus_message_iter_recurse(&args, &iter);

	dbus_message_iter_get_fixed_array(&iter, &value, &len);

	btd_gatt_write_attribute(iface->device, iface->attr,
					(uint8_t *) value, len,
					offset, write_value_response,
					dbus_message_ref(msg));

	return NULL;

invalid:
	return btd_error_invalid_args(msg);
}

static const GDBusMethodTable chr_methods[] = {
	{ GDBUS_EXPERIMENTAL_ASYNC_METHOD("ReadValue",
				GDBUS_ARGS({"offset", "q"}),
				GDBUS_ARGS({"value", "ay"}),
				remote_chr_read_value) },
	{ GDBUS_EXPERIMENTAL_ASYNC_METHOD("WriteValue",
				GDBUS_ARGS({"offset", "q"}, {"value", "ay"}),
				NULL, remote_chr_write_value) },
};

static gboolean chr_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct char_iface *iface = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &iface->uuid);

	return TRUE;
}

static gboolean chr_get_value(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct char_iface *iface = data;
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &array);

	if (iface->value)
		dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
						&iface->value, iface->vlen);

	dbus_message_iter_close_container(iter, &array);

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
	return TRUE;
}

static gboolean chr_get_props(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct char_iface *iface = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE,
						&iface->properties);

	return TRUE;
}

static gboolean chr_exist_props(const GDBusPropertyTable *property,
								void *data)
{
	return TRUE;
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
	{ "Properties", "y", chr_get_props, NULL, chr_exist_props,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Descriptors", "a{a{sv}}", chr_get_descriptors, chr_set_descriptors,
		chr_exist_descriptors, G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ }
};

char *gatt_dbus_service_register(struct btd_device *device, uint16_t handle,
				const char *uuid128, struct btd_attribute *attr)
{
	struct service_iface *iface;
	char *path;
	gboolean ret;

	path = g_strdup_printf("%s/service%04X", device_get_path(device),
								handle);

	iface = g_new0(struct service_iface, 1);
	iface->attr = attr;
	iface->device = device;
	iface->uuid = g_strdup(uuid128);

	ret = g_dbus_register_interface(btd_get_dbus_connection(),
					path, SERVICE_INTERFACE,
					NULL, NULL, service_properties, iface,
					service_iface_destroy);

	if (ret == TRUE)
		return path;

	error("Unable to register service interface for %s", path);

	g_free(path);
	service_iface_destroy(iface);

	return NULL;
}

void gatt_dbus_service_unregister(const char *path)
{
	g_dbus_unregister_interface(btd_get_dbus_connection(),
					path, SERVICE_INTERFACE);
}

static bool chr_value_changed(uint8_t *value, size_t len, void *user_data)
{
	struct char_iface *iface = user_data;

	if (iface->value)
		g_free(iface->value);

	iface->value = g_memdup(value, len);
	iface->vlen = len;

	g_dbus_emit_property_changed(btd_get_dbus_connection(), iface->path,
					CHARACTERISTIC_INTERFACE, "Value");

	return true;
}

char *gatt_dbus_characteristic_register(struct btd_device *device,
				const char *service_path,
				uint16_t handle, const char *uuid128,
				uint8_t properties,
				struct btd_attribute *attr)
{
	struct char_iface *iface;
	char *path;
	gboolean ret;

	path = g_strdup_printf("%s/characteristics%04X", service_path, handle);

	iface = g_new0(struct char_iface, 1);
	iface->attr = attr;
	iface->device = device;
	iface->uuid = g_strdup(uuid128);
	iface->path = g_strdup(path);
	iface->properties = properties;

	ret = g_dbus_register_interface(btd_get_dbus_connection(), path,
					CHARACTERISTIC_INTERFACE,
					chr_methods, NULL, chr_properties,
					iface, char_iface_destroy);

	if (ret == FALSE) {
		error("Unable to register Characteristic interface for %s",
									path);
		g_free(path);
		char_iface_destroy(iface);
		return NULL;
	}

	iface->watch = btd_gatt_add_notifier(attr, chr_value_changed, iface);

	return path;
}

void gatt_dbus_characteristic_unregister(const char *path)
{
	g_dbus_unregister_interface(btd_get_dbus_connection(),
			path, CHARACTERISTIC_INTERFACE);
}

gboolean gatt_dbus_manager_register(void)
{

	proxy_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
				NULL, (GDestroyNotify) g_dbus_proxy_unref);

	return g_dbus_register_interface(btd_get_dbus_connection(),
			"/org/bluez", "org.bluez.gatt.ServiceManager1",
			methods, NULL, NULL, NULL, NULL);
}

void gatt_dbus_manager_unregister(void)
{
	g_hash_table_destroy(proxy_hash);
	proxy_hash = NULL;

	g_dbus_unregister_interface(btd_get_dbus_connection(),
			"/org/bluez", "org.bluez.gatt.ServiceManager1");

}
