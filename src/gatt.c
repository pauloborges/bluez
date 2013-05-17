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

struct application {
	char *owner;
	GSList *services;
	unsigned int watch;
};

static GSList *applications = NULL;

static void destroy_application(void *data)
{
	struct application *app = data;

	DBG("app %p", app);

	g_free(app->owner);
	g_slist_free_full(app->services, g_free);

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

		app->services = g_slist_append(app->services, g_strdup(path));

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
