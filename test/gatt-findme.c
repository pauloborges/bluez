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
GDBusProxy *adapter = NULL;
GSList *services = NULL;
guint timer;
GSList *characteristics = NULL;

struct characteristic {
	char *path;
	GDBusProxy *proxy;
};

struct write_data {
	uint8_t *value;
	size_t vlen;
	uint16_t offset;
};

static void start_discovery_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
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

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		g_printerr("Failed to Stop Discovery: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	g_printerr("Discovery stop successfully\n");
}

static void connect_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		g_printerr("Failed to Connect: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	g_printerr("Connect successfully\n");
}

static void write_char_setup(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter array;
	struct write_data *wd = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &wd->offset);

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING,
					&array);

	if (!dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
					&wd->value, wd->vlen))
		g_printerr("Could not append value to D-Bus message\n");

	dbus_message_iter_close_container(iter, &array);
}

static void write_char_reply(DBusMessage *msg, void *user_data)
{
	struct write_data *wd = user_data;

	g_printerr("Alert Level set to 0x0%u\n", wd->value[0]);
}

static void write_char_destroy(void *user_data)
{
	g_free(user_data);
}

static uint8_t alert_level_to_uint(char *al)
{
	if (g_str_equal(al, "mild"))
		return 0x01;
	else if (g_str_equal(al, "high"))
		return 0x02;

	return 0x00;
}

static void change_alert_level(gpointer data, gpointer user_data)
{
	struct characteristic *chr = data;
	const char *srv_path = user_data;
	const char *uuid;
	DBusMessageIter iter;
	struct write_data *wd;

	if (!g_str_has_prefix(chr->path, srv_path))
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

	wd = g_new0(struct write_data, 1);
	wd->value = g_new0(uint8_t, 1);
	wd->value[0] = alert_level_to_uint(opt_alert_level);
	wd->vlen = sizeof(uint8_t);
	wd->offset = 0;

	if (!g_dbus_proxy_method_call(chr->proxy, "WriteValue",
					write_char_setup,
					write_char_reply, wd,
					write_char_destroy)) {
		g_printerr("Could not call WriteValue D-Bus method");
		write_char_destroy(wd);
		return;
	}
}

static gboolean timeout(gpointer user_data)
{
	GSList *list;

	for (list = services; list; list = g_slist_next(list)) {
		char *srv_path = list->data;

		g_slist_foreach(characteristics, change_alert_level, srv_path);
	}

	return FALSE;
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	const char *interface, *path;
	DBusMessageIter iter;

	interface = g_dbus_proxy_get_interface(proxy);
	path = g_dbus_proxy_get_path(proxy);

	g_printerr("interface %s path %s\n", interface, path);

	if (g_str_equal(interface, "org.bluez.Adapter1")) {
		dbus_bool_t discovering;

		adapter = g_dbus_proxy_ref(proxy);

		if (!g_dbus_proxy_get_property(proxy, "Discovering", &iter))
			return;

		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_BOOLEAN) {
			g_printerr("Invalid type for Discovering");
			return;
		}

		dbus_message_iter_get_basic(&iter, &discovering);

		if (discovering)
			return;

		if (!g_dbus_proxy_method_call(proxy, "StartDiscovery",
						NULL, start_discovery_reply,
						NULL, NULL)) {
			g_printerr("Could not call StartDiscovery()\n");
			return;
		}
	} else if (g_str_equal(interface, "org.bluez.Device1")) {
		/* TODO: stop discovery when device is connected */
		/* TODO: create 1 second timer to check for:
		 * - Immediate Alert Service
		 * - Alert Level Characteristic of IAS
		 * - Write requested alert level to characteristic value
		 * - if not found, return error to user
		 */
		const char *addr;
		dbus_bool_t connected;

		if (!g_dbus_proxy_get_property(proxy, "Address", &iter))
			return;

		if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
			g_printerr("Invalid type for Address");
			return;
		}

		dbus_message_iter_get_basic(&iter, &addr);

		if (!g_str_equal(opt_dst, addr))
			return;

		if (!g_dbus_proxy_get_property(proxy, "Connected", &iter))
			return;

		if (dbus_message_iter_get_arg_type(&iter) !=
							DBUS_TYPE_BOOLEAN) {
			g_printerr("Invalid type for Connected");
			return;
		}

		dbus_message_iter_get_basic(&iter, &connected);

		if (!connected) {
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

		g_printerr("uuid: %s\n", uuid);

		if (!g_str_equal(uuid, IMMEDIATE_ALERT_UUID))
			return;

		services = g_slist_append(services, g_strdup(path));

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
	g_dbus_proxy_unref(adapter);

	return err;
}
