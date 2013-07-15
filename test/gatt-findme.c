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

#include <stdlib.h>
#include <stdbool.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "uuid.h"

#define SERVICE_INTERFACE "org.bluez.gatt.Service1"
#define CHARACTERISTIC_INTERFACE "org.bluez.gatt.Characteristic1"
#define ALERT_LEVEL_CHR_UUID	"00002a06-0000-1000-8000-00805f9b34fb"

static GMainLoop *main_loop;
static DBusConnection *dbus_conn;
static char *opt_src = NULL;
static char *opt_dst = NULL;
static char *opt_alert_level = NULL;
static GDBusProxy *adapter = NULL;
static char *ias_path = NULL;
static guint timer;
static GSList *characteristics = NULL;

struct characteristic {
	char *path;
	GDBusProxy *proxy;
};

static void start_discovery_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message)) {
		g_printerr("Failed to Start Discovery: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	g_printerr("Discovery started successfully\n");
}

static void stop_discovery_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message)) {
		g_printerr("Failed to Stop Discovery: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	g_printerr("Discovery stopped successfully\n");
}

static void connect_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message)) {
		g_printerr("Failed to Connect: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	g_printerr("Connected successfully\n");
}

static uint8_t alert_level_to_uint(char *level)
{
	if (g_str_equal(level, "mild"))
		return 0x01;
	else if (g_str_equal(level, "high"))
		return 0x02;

	return 0x00;
}

static void write_char_setup(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter array;
	uint8_t *value;
	uint16_t offset;

	value = g_new0(uint8_t, 1);
	*value = alert_level_to_uint(opt_alert_level);
	offset = 0;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &offset);

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
						DBUS_TYPE_BYTE_AS_STRING,
						&array);

	if (!dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
							&value, sizeof(*value)))
		g_printerr("Could not append value to D-Bus message\n");

	dbus_message_iter_close_container(iter, &array);

	g_free(value);
}

static void write_char_reply(DBusMessage *msg, void *user_data)
{
	g_printerr("Immediate Alert Level set to %s\n", opt_alert_level);
	g_main_loop_quit(main_loop);
}

static void change_alert_level(gpointer data, gpointer user_data)
{
	struct characteristic *chr = data;
	const char *uuid;
	DBusMessageIter iter;

	if (!g_str_has_prefix(chr->path, ias_path))
		return;

	if (!g_dbus_proxy_get_property(chr->proxy, "UUID", &iter))
		return;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
		g_printerr("Invalid type for Service UUID\n");
		return;
	}

	dbus_message_iter_get_basic(&iter, &uuid);

	if (!g_str_equal(uuid, ALERT_LEVEL_CHR_UUID))
		return;

	g_printerr("Found IAS Alert Level characteristic: %s\n", chr->path);

	if (!g_dbus_proxy_method_call(chr->proxy, "WriteValue",
					write_char_setup, write_char_reply,
					NULL, NULL)) {
		g_printerr("Could not call WriteValue D-Bus method\n");
	}
}

static gboolean timeout(gpointer user_data)
{
	if (adapter == NULL) {
		if (opt_src == NULL)
			g_printerr("No adapter found\n");
		else
			g_printerr("Adapter %s not found\n", opt_src);

		g_main_loop_quit(main_loop);
	}

	if (ias_path == NULL) {
		g_printerr("Immediate Alert Service not found on %s\n",
								opt_dst);
		g_main_loop_quit(main_loop);

		return FALSE;
	}

	g_slist_foreach(characteristics, change_alert_level, NULL);

	return FALSE;
}

static bool get_bool_property(GDBusProxy *proxy, const char *name)
{
	DBusMessageIter iter;
	dbus_bool_t value;

	if (!g_dbus_proxy_get_property(proxy, name, &iter)) {
		g_printerr("Could not read property %s\n", name);
		g_main_loop_quit(main_loop);
		return false;
	}

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BOOLEAN) {
		g_printerr("Invalid type for %s\n", name);
		g_main_loop_quit(main_loop);
		return false;
	}

	dbus_message_iter_get_basic(&iter, &value);

	return value;
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	const char *interface, *path;
	DBusMessageIter iter;

	interface = g_dbus_proxy_get_interface(proxy);
	path = g_dbus_proxy_get_path(proxy);

	if (g_str_equal(interface, "org.bluez.Adapter1")) {
		/* Use either the first adapter found or the one given by -i
		 * option */
		if (adapter != NULL)
			return;

		/* The adapter name (hciX) does not match the one given by -i */
		if (opt_src != NULL && !g_str_has_suffix(path, opt_src))
			return;

		adapter = g_dbus_proxy_ref(proxy);

		if (get_bool_property(proxy, "Discovering"))
			return;

		if (!g_dbus_proxy_method_call(proxy, "StartDiscovery",
						NULL, start_discovery_reply,
						NULL, NULL)) {
			g_printerr("Could not call StartDiscovery()\n");
			return;
		}
	} else if (g_str_equal(interface, "org.bluez.Device1")) {
		const char *addr;

		if (!g_dbus_proxy_get_property(proxy, "Address", &iter))
			return;

		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
			g_printerr("Invalid type for Address");
			return;
		}

		dbus_message_iter_get_basic(&iter, &addr);

		if (!g_str_equal(opt_dst, addr))
			return;

		if (!get_bool_property(proxy, "Connected")) {
			if (!g_dbus_proxy_method_call(proxy, "Connect",
							NULL, connect_reply,
							NULL, NULL)) {
				g_printerr("Could not call Connect()\n");
				return;
			}
		}

		if (!g_dbus_proxy_method_call(adapter, "StopDiscovery",
						NULL, stop_discovery_reply,
						NULL, NULL)) {
			g_printerr("Could not call StopDiscovery()\n");
			return;
		}
	} else if (g_str_equal(interface, SERVICE_INTERFACE)) {
		const char *uuid;

		if (!g_dbus_proxy_get_property(proxy, "UUID", &iter))
			return;

		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
			g_printerr("Invalid type for Service UUID\n");
			return;
		}

		dbus_message_iter_get_basic(&iter, &uuid);

		if (!g_str_equal(uuid, IMMEDIATE_ALERT_UUID))
			return;

		g_printerr("Found Immediate Alert Service: %s\n", path);

		ias_path = g_strdup(path);
	} else if (g_str_equal(interface, CHARACTERISTIC_INTERFACE)) {
		struct characteristic *chr = g_new0(struct characteristic, 1);
		chr->path = g_strdup(path);
		chr->proxy = g_dbus_proxy_ref(proxy);

		characteristics = g_slist_append(characteristics, chr);
	}
}

static GOptionEntry options[] = {
	{ "adapter", 'i', 0, G_OPTION_ARG_STRING, &opt_src,
				"Specify local adapter interface", "hciX" },
	{ "device", 'b', 0, G_OPTION_ARG_STRING, &opt_dst,
				"Specify remote Bluetooth address", "MAC" },
	{ "alert-level", 'a', 0, G_OPTION_ARG_STRING, &opt_alert_level,
			"Specify Immediate Alert Level", "none|mild|high" },
	{ NULL },
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	GDBusClient *client;
	int err = 0;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);
	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		g_printerr("%s\n", error->message);
		g_error_free(error);
		err = EXIT_FAILURE;
		goto done;
	}

	if (opt_dst == NULL) {
		g_printerr("Error: remote Bluetooth address not specified\n");
		err = EXIT_FAILURE;
		goto done;
	}

	if (opt_alert_level == NULL) {
		g_printerr("Error: alert level not specified\n");
		err = EXIT_FAILURE;
		goto done;
	}

	if (!g_str_equal(opt_alert_level, "none") &&
					!g_str_equal(opt_alert_level, "mild") &&
					!g_str_equal(opt_alert_level, "high")) {
		g_printerr("Error: invalid alert level\n");
		err = EXIT_FAILURE;
		goto done;
	}

	main_loop = g_main_loop_new(NULL, FALSE);
	dbus_conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, NULL);

	client = g_dbus_client_new(dbus_conn, "org.bluez", "/org/bluez");
	if (client == NULL) {
		g_printerr("Could not create D-Bus client\n");
		err = EXIT_FAILURE;
		goto done;
	}

	g_dbus_client_set_proxy_handlers(client, proxy_added, NULL, NULL, NULL);

	timer = g_timeout_add_seconds(1, timeout, NULL);

	g_main_loop_run(main_loop);

	g_dbus_client_unref(client);

	dbus_connection_unref(dbus_conn);
	g_main_loop_unref(main_loop);

done:
	g_option_context_free(context);
	g_free(opt_src);
	g_free(opt_dst);
	g_free(opt_alert_level);
	g_free(ias_path);
	g_dbus_proxy_unref(adapter);

	return err;
}
