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

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "dbus-common.h"

#include "gatt.h"

static DBusMessage *register_services(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	return dbus_message_new_method_return(msg);
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
