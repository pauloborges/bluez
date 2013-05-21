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

#include "dbus-common.h"
#include "log.h"
#include "error.h"

#include "gatt.h"

#define SERVICE_INTERFACE "org.bluez.gatt.Service1"
#define CHARACTERISTIC_INTERFACE "org.bluez.gatt.Characteristic1"

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
