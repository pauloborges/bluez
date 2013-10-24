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

#define SERVICE_INTERFACE "org.bluez.Service1"
#define CHARACTERISTIC_INTERFACE "org.bluez.Characteristic1"

#define REGISTER_TIMER         1

struct external_app {
	char *gid;
	char *owner;
	GSList *prim_services;
	GDBusClient *client;
	GSList *proxies;
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

struct external_write_data {
	btd_attr_write_result_t func;
	void *user_data;
};

static GSList *external_apps = NULL;

/*
 * Attribute to Proxy hash table. Used to map incomming
 * ATT operations to its external characteristic proxy.
 */
static GHashTable *proxy_hash = NULL;

/*
 * Proxy to attribute hash table. Used to track Proxy PropertiesChanged, map
 * to its attribute and when necessary emit ATT notification or indication.
 */
static GHashTable *object_hash = NULL;

static void char_iface_destroy(gpointer user_data)
{
	struct char_iface *iface = user_data;

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

static void remove_local_service(void *data)
{
	struct btd_attribute *attr = data;

	btd_gatt_remove_service(attr);
}

static int external_app_gid_cmp(gconstpointer a, gconstpointer b)
{
	const struct external_app *eapp = a;
	const char *gid = b;

	return g_strcmp0(eapp->gid, gid);
}

static uint32_t property_string2bit(const char *proper)
{
	/* Regular Properties: See core spec page 1898 */
	if (strcmp("broadcast", proper) == 0)
		return 1 << 0;
	else if (strcmp("read", proper) == 0)
		return 1 << 1;
	else if (strcmp("write-without-response", proper) == 0)
		return 1 << 2;
	else if (strcmp("write", proper) == 0)
		return 1 << 3;
	else if (strcmp("notify", proper) == 0)
		return 1 << 4;
	else if (strcmp("indicate", proper) == 0)
		return 1 << 5;
	else if (strcmp("authenticated-signed-writes", proper) == 0)
		return 1 << 6;

	/* Extended Properties section. See core spec page 1900 */
	else if (strcmp("reliable-write", proper) == 0)
		return 1 << 8;
	else if (strcmp("writable-auxiliaries", proper) == 0)
		return 1 << 9;
	else
		return 0;
}

static uint32_t flags_get_value(DBusMessageIter *iter)
{
	DBusMessageIter istr;
	uint32_t proper_bitmask = 0;
	const char *proper;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY) {
		error("Invalid type for Properties");
		return 0;
	}

	dbus_message_iter_recurse(iter, &istr);

	do {
		if (dbus_message_iter_get_arg_type(&istr) !=
				DBUS_TYPE_STRING)
			break;

		dbus_message_iter_get_basic(&istr, &proper);
		proper_bitmask |= property_string2bit(proper);
	} while (dbus_message_iter_next(&istr));

	return proper_bitmask;
}

static void read_external_char_cb(struct btd_device *device,
				struct btd_attribute *attr,
				btd_attr_read_result_t result, void *user_data)
{
	DBusMessageIter iter, array;
	GDBusProxy *proxy;
	uint8_t *value;
	int len;

	/*
	 * Remote device is trying to read the informed attribute,
	 * "Value" should be read from the proxy. GDBusProxy tracks
	 * properties changes automatically, it is not necessary to
	 * get the value directly from the GATT server.
	 */
	proxy = g_hash_table_lookup(proxy_hash, attr);
	if (proxy == NULL) {
		result(EPERM, NULL, 0, user_data);
		return;
	}

	if (!g_dbus_proxy_get_property(proxy, "Value", &iter)) {
		result(EPERM, NULL, 0, user_data);
		return;
	}

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
		DBG("External service inconsistent!");
		result(EPERM, NULL, 0, user_data);
		return;
	}

	dbus_message_iter_recurse(&iter, &array);
	dbus_message_iter_get_fixed_array(&array, &value, &len);

	DBG("attribute: %p read %d bytes", attr, len);

	result(0, (uint8_t *) value, len, user_data);
}

static void read_extended_properties_cb(struct btd_device *device,
				struct btd_attribute *attr,
				btd_attr_read_result_t result, void *user_data)
{
	DBusMessageIter iter;
	GDBusProxy *proxy;
	uint32_t proper_bitmask;

	proxy = g_hash_table_lookup(proxy_hash, attr);
	if (proxy == NULL) {
		result(EPERM, NULL, 0, user_data);
		return;
	}

	if (!g_dbus_proxy_get_property(proxy, "Flags", &iter)) {
		result(EPERM, NULL, 0, user_data);
		return;
	}

	proper_bitmask = flags_get_value(&iter);

	/*
	 * Remove Properties bit field (8-bits) and leave
	 * Extended Properties bit field (16-bits). For API
	 * simplification "Flags" DBus Property represents
	 * both values.
	 */

	proper_bitmask = proper_bitmask >> 8;

	result(0, (uint8_t *) &proper_bitmask, sizeof(proper_bitmask),
								user_data);
}

static void write_char_reply(const DBusError *error, void *user_data)
{
	struct external_write_data *wdata = user_data;

	if (!wdata->func)
		return;

	wdata->func(0, wdata->user_data);
}

static void write_external_char_cb(struct btd_device *device,
			struct btd_attribute *attr,
			uint8_t *value, size_t len, uint16_t offset,
			btd_attr_write_result_t result, void *user_data)
{
	GDBusProxy *proxy;
	struct external_write_data *wdata;

	proxy = g_hash_table_lookup(proxy_hash, attr);
	if (proxy == NULL) {
		result(EPERM, user_data);
		return;
	}

	wdata = g_new0(struct external_write_data, 1);
	wdata->func = result;
	wdata->user_data = user_data;

	g_dbus_proxy_set_property_array(proxy, "Value", DBUS_TYPE_BYTE,
						value, len, write_char_reply,
						wdata, g_free);

	DBG("Server: Write characteristic callback %s",
					g_dbus_proxy_get_path(proxy));
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	struct external_app *eapp = user_data;
	const char *interface, *path;

	interface = g_dbus_proxy_get_interface(proxy);
	path = g_dbus_proxy_get_path(proxy);

	DBG("path %s iface %s", path, interface);

	if ((g_strcmp0(interface, CHARACTERISTIC_INTERFACE) != 0) &&
		(g_strcmp0(interface, SERVICE_INTERFACE) != 0))
		return;

	eapp->proxies = g_slist_append(eapp->proxies, proxy);
}

static void proxy_removed(GDBusProxy *proxy, void *user_data)
{
	struct external_app *eapp = user_data;
	struct btd_attribute *attr;
	const char *interface, *path;

	interface = g_dbus_proxy_get_interface(proxy);
	path = g_dbus_proxy_get_path(proxy);

	DBG("path %s iface %s", path, interface);

	eapp->proxies = g_slist_remove(eapp->proxies, proxy);

	/*
	 * When the external application leaves the bus or unregister a given
	 * object (service or characteristic) its proxy object needs  to be
	 * removed from the hash tables. Further incomming ATT requests will
	 * get permission denied if the Proxy object is not found.
	 */
	attr = g_hash_table_lookup(object_hash, proxy);
	if (attr)
		g_hash_table_remove(proxy_hash, attr);

	g_hash_table_remove(object_hash, proxy);
}

static void property_changed(GDBusProxy *proxy, const char *name,
					DBusMessageIter *iter, void *user_data)
{
	struct btd_attribute *attr;
	DBusMessageIter array;
	const char *interface;
	uint8_t *value;
	int len;

	attr = g_hash_table_lookup(object_hash, proxy);
	if (attr == NULL)
		return;

	interface = g_dbus_proxy_get_interface(proxy);

	if (g_strcmp0(interface, CHARACTERISTIC_INTERFACE) != 0)
		return;

	if (!g_dbus_proxy_get_property(proxy, "Value", iter))
		return;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(iter, &array);
	dbus_message_iter_get_fixed_array(&array, &value, &len);

	/*
	 * Let the core to manage notifications and indications
	 * for offline and connected devices.
	 */
	btd_gatt_write_attribute(NULL, attr, (uint8_t *) value, len,
							0, NULL, NULL);
}

static void external_app_disconnected(DBusConnection *conn, void *user_data)
{
	struct external_app *eapp = user_data;

	DBG("app %p", eapp);

	if (eapp->register_timer > 0)
		g_source_remove(eapp->register_timer);

	g_free(eapp->gid);
	g_free(eapp->owner);

	g_slist_free_full(eapp->prim_services, remove_local_service);

	if (eapp->watch > 0)
		g_dbus_remove_watch(btd_get_dbus_connection(), eapp->watch);

	g_dbus_client_unref(eapp->client);

	external_apps = g_slist_remove(external_apps, eapp);

	g_free(eapp);
}

static struct external_app *new_external_app(DBusConnection *conn,
					const char *sender, const char *gid)
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
	eapp->gid = g_strdup(gid);

	g_dbus_client_set_proxy_handlers(client, proxy_added,
				proxy_removed, property_changed, eapp);

	return eapp;
}

static int register_external_characteristic(GDBusProxy *proxy)
{
	DBusMessageIter iter;
	const char *uuid, *path;
	bt_uuid_t btuuid;
	struct btd_attribute *attr;
	uint32_t proper_bitmask;
	bool has_extended = false;

	if (!g_dbus_proxy_get_property(proxy, "UUID", &iter))
		return -EINVAL;

	dbus_message_iter_get_basic(&iter, &uuid);

	if (!g_dbus_proxy_get_property(proxy, "Flags", &iter))
		return -EINVAL;

	proper_bitmask = flags_get_value(&iter);

	/* Set Extended Properties bit if necessary */
	if (proper_bitmask >> 8) {
		proper_bitmask |= 1 << 7;
		has_extended = true;
	}

	if (bt_string_to_uuid(&btuuid, uuid) < 0)
		return -EINVAL;

	attr = btd_gatt_add_char(&btuuid, proper_bitmask,
					read_external_char_cb,
					write_external_char_cb);
	if (attr == NULL)
		return -EINVAL;

	/* Attribute to Proxy hash table */
	g_hash_table_insert(proxy_hash, attr, proxy);

	/* Proxy to attribute hash table */
	g_hash_table_insert(object_hash, proxy, attr);

	/* Extended Properties bit set? */
	if (has_extended) {
		bt_uuid16_create(&btuuid, GATT_CHARAC_EXT_PROPER_UUID);
		attr = btd_gatt_add_char_desc(&btuuid,
					read_extended_properties_cb, NULL);
		if (attr != NULL)
			g_hash_table_insert(proxy_hash, attr, proxy);
	}

	path = g_dbus_proxy_get_path(proxy);
	DBG("External characteristic: %s Property: 0x%08x", path,
							proper_bitmask);

	return 0;
}

static int register_external_service(GDBusProxy *proxy, const char *gid)
{
	DBusMessageIter iter;
	const char *uuid, *path;
	bt_uuid_t btuuid;

	if (!g_dbus_proxy_get_property(proxy, "UUID", &iter))
		return -EINVAL;

	dbus_message_iter_get_basic(&iter, &uuid);

	if (bt_string_to_uuid(&btuuid, uuid) < 0)
		return -EINVAL;

	if (btd_gatt_add_service(gid, &btuuid, true) == NULL)
		return -EINVAL;

	path = g_dbus_proxy_get_path(proxy);
	DBG("External service: %s", path);

	return 0;
}

static gboolean finish_register(gpointer user_data)
{
	struct external_app *eapp = user_data;
	GSList *list1, *list2, *services = NULL, *chars = NULL;
	const char *spath, *cpath, *interface;
	GDBusProxy *proxy;

	eapp->register_timer = 0;

	/* Split services and characteristics */
	for (list1 = eapp->proxies; list1; list1 = g_slist_next(list1)) {
		proxy = list1->data;

		interface = g_dbus_proxy_get_interface(proxy);

		if (g_strcmp0(CHARACTERISTIC_INTERFACE, interface) == 0)
			chars = g_slist_append(chars, proxy);
		else
			services = g_slist_append(services, proxy);
	}

	/* For each service register its characteristics */
	for (list1 = services; list1; list1 = g_slist_next(list1)) {
		proxy = list1->data;

		spath = g_dbus_proxy_get_path(proxy);

		if (register_external_service(proxy, eapp->gid) < 0) {
			DBG("Inconsistent external service: %s", spath);
			continue;
		}

		for (list2 = chars; list2; list2 = g_slist_next(list2)) {
			proxy = list2->data;

			cpath = g_dbus_proxy_get_path(proxy);

			if (!g_str_has_prefix(cpath, spath))
				continue;

			if (register_external_characteristic(proxy) < 0) {
				DBG("Inconsistent external characteristic: %s",
									cpath);
				continue;
			}
		}
	}

	g_slist_free(services);
	g_slist_free(chars);

	return FALSE;
}

static inline int is_uuid128(const char *string)
{
	return (strlen(string) == 36 &&
			string[8] == '-' &&
			string[13] == '-' &&
			string[18] == '-' &&
			string[23] == '-');
}

static DBusMessage *register_services(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct external_app *eapp;
	DBusMessageIter args;
	const char *gid;

	DBG("Registering GATT Service");

	if (dbus_message_iter_init(msg, &args) == false)
		goto invalid;

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING)
		goto invalid;

	dbus_message_iter_get_basic(&args, &gid);

	if (!is_uuid128(gid)) {
		DBG("Application ID: invalid argument");
		goto invalid;
	}

	dbus_message_iter_next(&args);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY)
		goto invalid;

	if (g_slist_find_custom(external_apps, gid, external_app_gid_cmp))
		return btd_error_already_exists(msg);

	eapp = new_external_app(conn, dbus_message_get_sender(msg), gid);
	if (eapp == NULL)
		return btd_error_failed(msg, "Not enough resources");

	external_apps = g_slist_prepend(external_apps, eapp);

	DBG("new app %p", eapp);

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
				GDBUS_ARGS({ "services", "sao"}), NULL,
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
	struct char_iface *iface = user_data;

	if (err) {
		DBG("Read remote failed: %s(%d)", strerror(err), err);
		return;
	}

	if (iface->value)
		g_free(iface->value);

	iface->value = g_memdup(value, len);
	iface->vlen = len;

	g_dbus_emit_property_changed(btd_get_dbus_connection(), iface->path,
					CHARACTERISTIC_INTERFACE, "Value");
}

static void write_value_response(int err, void *user_data)
{
	GDBusPendingPropertySet id = GPOINTER_TO_UINT(user_data);

	if (err == 0) {
		g_dbus_pending_property_success(id);
		return;
	}

	switch (err) {
	case ECOMM:
		g_dbus_pending_property_error(id,
				ERROR_INTERFACE ".NotConnected",
				"Not Connected");
		break;
	default:
		g_dbus_pending_property_error(id,
				ERROR_INTERFACE ".Failed",
				strerror(err));
		break;
	}
}

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

	/*
	 * Limitation: Returns empty array if value was never read.
	 * Get method call can't be asynchronous. PropertiesChanged
	 * will be sent later when the read operation returns.
	 */
	if (iface->value)
		dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
						&iface->value, iface->vlen);
	else
		btd_gatt_read_attribute(iface->device, iface->attr,
						read_value_response, iface);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static void chr_set_value(const GDBusPropertyTable *property,
				DBusMessageIter *iter,
				GDBusPendingPropertySet id, void *user_data)
{
	struct char_iface *iface = user_data;
	DBusMessageIter array;
	const uint8_t *value;
	int len;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		goto invalid;

	dbus_message_iter_recurse(iter, &array);

	dbus_message_iter_get_fixed_array(&array, &value, &len);

	btd_gatt_write_attribute(iface->device, iface->attr,
					(uint8_t *) value, len,
					0, write_value_response,
					GUINT_TO_POINTER(id));

	return;

invalid:
	g_dbus_pending_property_error(id,
				ERROR_INTERFACE ".InvalidArguments",
				"Invalid arguments in method call");
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
	{ "Flags", "y", chr_get_props, NULL, chr_exist_props,
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
					NULL, NULL, chr_properties,
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

	proxy_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
	object_hash = g_hash_table_new(g_direct_hash, g_direct_equal);

	return g_dbus_register_interface(btd_get_dbus_connection(),
			"/org/bluez", "org.bluez.ServiceManager1",
			methods, NULL, NULL, NULL, NULL);
}

void gatt_dbus_manager_unregister(void)
{
	g_hash_table_destroy(proxy_hash);
	proxy_hash = NULL;

	g_hash_table_destroy(object_hash);
	object_hash = NULL;

	g_dbus_unregister_interface(btd_get_dbus_connection(),
			"/org/bluez", "org.bluez.ServiceManager1");

}
