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
#include <stdio.h>
#include <stdbool.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#define SERVICE_MANAGER_INTERFACE "org.bluez.gatt.ServiceManager1"

#define SERVICE_INTERFACE "org.bluez.gatt.Service1"
#define CHARACTERISTIC_INTERFACE "org.bluez.gatt.Characteristic1"
#define ERROR_INTERFACE "org.bluez.Error"

#define SERVICE_PATH "/service%d"
#define CHARACTERISTIC_PATH "/characteristic%d"

#define IMMEDIATE_ALERT_UUID16 "1802"
#define ALERT_LEVEL_CHR_UUID16 "2a06"

static GMainLoop *main_loop;
static DBusConnection *dbus_conn;

struct service {
	char *uuid;
	GSList *includes;
};

enum char_features_t {
	CHAR_FEATURE_PROP_VALUE = (1 << 0),
	CHAR_FEATURE_HAS_PERMS = (1 << 1),
	CHAR_FEATURE_HAS_AUTH = (1 << 2),
};

struct characteristic {
	char *uuid;
	uint8_t *value;
	int vlen;
	int features;
	uint8_t perms;
	bool auth;
	uint8_t props;
	GSList *descriptors;
};

static gboolean service_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct service *service = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &service->uuid);

	return TRUE;
}

static gboolean service_get_includes(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	return TRUE;
}

static gboolean service_exist_includes(const GDBusPropertyTable *property,
								void *data)
{
	struct service *service = data;

	return service->includes != NULL;
}

static const GDBusPropertyTable service_properties[] = {
	{ "UUID", "s", service_get_uuid },
	{ "Includes", "ao", service_get_includes, NULL,
					service_exist_includes },
	{ }
};

static gboolean chr_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct characteristic *chr = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &chr->uuid);

	return TRUE;
}

static gboolean chr_get_value(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct characteristic *chr = data;
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &array);

	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
						&chr->value, chr->vlen);

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
	struct characteristic *chr = data;

	return !!(chr->features & CHAR_FEATURE_PROP_VALUE);
}

static gboolean chr_get_perms(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct characteristic *chr = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE, &chr->perms);

	return TRUE;
}

static gboolean chr_exist_perms(const GDBusPropertyTable *property,
								void *data)
{
	struct characteristic *chr = data;

	return !!(chr->features & CHAR_FEATURE_HAS_PERMS);
}


static gboolean chr_get_props(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct characteristic *chr = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE, &chr->props);

	return TRUE;
}

static gboolean chr_exist_props(const GDBusPropertyTable *property,
								void *data)
{
	return TRUE;
}

static gboolean chr_get_auth(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct characteristic *chr = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE, &chr->auth);

	return TRUE;
}

static gboolean chr_exist_auth(const GDBusPropertyTable *property, void *data)
{
	struct characteristic *chr = data;

	return !!(chr->features & CHAR_FEATURE_HAS_AUTH);
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
	struct characteristic *chr = data;

	return chr->descriptors != NULL;
}

static const GDBusPropertyTable chr_properties[] = {
	{ "UUID", "s", chr_get_uuid },
	{ "Value", "ay", chr_get_value, chr_set_value, chr_exist_value },
	{ "Permissions", "y", chr_get_perms, NULL, chr_exist_perms },
	{ "Authenticate", "b", chr_get_auth, NULL, chr_exist_auth },
	{ "Properties", "y", chr_get_props, NULL, chr_exist_props },
	{ "Descriptors", "a{a{sv}}", chr_get_descriptors, chr_set_descriptors,
						chr_exist_descriptors },
	{ }
};

static DBusMessage *chr_read_value(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct characteristic *chr = user_data;
	DBusMessageIter iter, array;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);

	dbus_message_iter_init(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &array);

	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
						&chr->value, chr->vlen);

	dbus_message_iter_close_container(&iter, &array);

	return reply;
}

static DBusMessage *chr_write_value(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable chr_methods[] = {
	{ GDBUS_METHOD("ReadValue", GDBUS_ARGS({"offset", "q"}),
				GDBUS_ARGS({"value", "ay"}),
				chr_read_value) },
	{ GDBUS_METHOD("WriteValue",
				GDBUS_ARGS({"offset", "q"}, {"value", "ay"}),
				NULL, chr_write_value) },
	{ }
};

static bool register_services(DBusConnection *conn, const char *path)
{
	DBusMessage *msg;
	DBusMessageIter iter, array;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
				SERVICE_MANAGER_INTERFACE, "RegisterServices");
	if (msg == NULL) {
		fprintf(stderr, "Couldn't allocate D-Bus message\n");
		return false;
	}

	dbus_message_iter_init_append(msg, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &array);

	dbus_message_iter_append_basic(&array, DBUS_TYPE_OBJECT_PATH, &path);

	dbus_message_iter_close_container(&iter, &array);

	return g_dbus_send_message(conn, msg);

}

static void populate_service(DBusConnection *conn)
{
	struct characteristic *chr;
	struct service *service;
	static int id = 1;
	char service_path[64], chr_path[64];

	snprintf(service_path, sizeof(service_path), SERVICE_PATH, id++);

	service = g_new0(struct service, 1);

	service->uuid = g_strdup(IMMEDIATE_ALERT_UUID16);

	if (g_dbus_register_interface(conn, service_path, SERVICE_INTERFACE,
					NULL, NULL, service_properties,
					service, NULL) == FALSE) {
		fprintf(stderr, "Couldn't register service interface\n");
		return;
	}

	snprintf(chr_path, sizeof(chr_path), "%s" CHARACTERISTIC_PATH,
							service_path, id++);

	chr = g_new0(struct characteristic, 1);

	chr->uuid = g_strdup(ALERT_LEVEL_CHR_UUID16);

	chr->value = g_new0(uint8_t, 1);
	chr->vlen = sizeof(uint8_t);

	chr->features = CHAR_FEATURE_PROP_VALUE;

	if (g_dbus_register_interface(conn, chr_path,
					CHARACTERISTIC_INTERFACE,
					chr_methods, NULL, chr_properties,
					chr, NULL) == FALSE) {
		fprintf(stderr, "Couldn't register service interface\n");
		return;
	}

	if (register_services(conn, service_path) == false)
		fprintf(stderr, "Could not send RegisterServices\n");
}

static void connect_handler(DBusConnection *connection, void *user_data)
{
	populate_service(dbus_conn);
}

int main(int argc, char *argv[])
{
	GDBusClient *client;

	main_loop = g_main_loop_new(NULL, FALSE);
	dbus_conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, NULL);

	client = g_dbus_client_new(dbus_conn, "org.bluez", "/org/bluez");

	g_dbus_client_set_connect_watch(client, connect_handler, NULL);

	g_dbus_attach_object_manager(dbus_conn);

	g_main_loop_run(main_loop);

	g_dbus_client_unref(client);

	dbus_connection_unref(dbus_conn);
	g_main_loop_unref(main_loop);

	return 0;
}
