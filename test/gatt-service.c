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

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#define SERVICE_INTERFACE "org.bluez.gatt.Service1"
#define CHARACTERISTIC_INTERFACE "org.bluez.gatt.Characteristic1"

#define SERVICE_PATH "/service%d"
#define CHARACTERISTIC_PATH "/characteristic%d"

static GMainLoop *main_loop;
static DBusConnection *dbus_conn;

static void connect_handler(DBusConnection *connection, void *user_data)
{

}

static gboolean service_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
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
	return TRUE;
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
	g_dbus_pending_property_success(id);
}

static gboolean chr_exist_value(const GDBusPropertyTable *property,
								void *data)
{
	return TRUE;
}

static gboolean chr_get_perms(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	return TRUE;
}

static gboolean chr_exist_perms(const GDBusPropertyTable *property,
								void *data)
{
	return TRUE;
}

static gboolean chr_get_auth(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	return TRUE;
}

static gboolean chr_exist_auth(const GDBusPropertyTable *property, void *data)
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
	return TRUE;
}

static const GDBusPropertyTable chr_properties[] = {
	{ "UUID", "s", chr_get_uuid },
	{ "Value", "ay", chr_get_value, chr_set_value, chr_exist_value },
	{ "Permissions", "y", chr_get_perms, NULL, chr_exist_perms },
	{ "Authenticate", "b", chr_get_auth, NULL, chr_exist_auth },
	{ "Properties", "y", chr_get_perms, NULL, chr_exist_perms },
	{ "Descriptors", "a{a{sv}}", chr_get_descriptors, chr_set_descriptors,
						chr_exist_descriptors },
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
	{ GDBUS_METHOD("ReadValue", GDBUS_ARGS({"offset", "q"}),
				GDBUS_ARGS({"value", "ay"}),
				chr_read_value) },
	{ GDBUS_METHOD("WriteValue",
				GDBUS_ARGS({"offset", "q"}, {"value", "ay"}),
				NULL, chr_write_value) },
	{ }
};

static void populate_service(DBusConnection *conn)
{
	static int id = 1;
	char service_path[64], chr_path[64];

	snprintf(service_path, sizeof(service_path), SERVICE_PATH, id++);

	if (g_dbus_register_interface(conn, service_path, SERVICE_INTERFACE,
					NULL, NULL, service_properties,
					NULL, NULL) == FALSE) {
		fprintf(stderr, "Couldn't register service interface\n");
		return;
	}

	snprintf(chr_path, sizeof(chr_path), "%s/" CHARACTERISTIC_PATH,
							service_path, id++);

	if (g_dbus_register_interface(conn, chr_path,
					CHARACTERISTIC_INTERFACE,
					chr_methods, NULL, chr_properties,
					NULL, NULL) == FALSE) {
		fprintf(stderr, "Couldn't register service interface\n");
		return;
	}
}

int main(int argc, char *argv[])
{
	GDBusClient *client;

	main_loop = g_main_loop_new(NULL, FALSE);
	dbus_conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, NULL);

	client = g_dbus_client_new(dbus_conn, "org.bluez", "/org/bluez");

	g_dbus_client_set_connect_watch(client, connect_handler, NULL);

	g_dbus_attach_object_manager(dbus_conn);

	populate_service(dbus_conn);

	g_main_loop_run(main_loop);

	g_dbus_client_unref(client);

	dbus_connection_unref(dbus_conn);
	g_main_loop_unref(main_loop);

	return 0;
}
