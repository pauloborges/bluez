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

struct btd_attribute;

gboolean gatt_dbus_manager_register(void);
void gatt_dbus_manager_unregister(void);

char *gatt_dbus_service_register(struct btd_device *device,
					uint16_t handle, const char *uuid128,
					struct btd_attribute *attr);
void gatt_dbus_service_unregister(const char *path);

char *gatt_dbus_characteristic_register(struct btd_device *device,
					const char *service_path,
					uint16_t handle, const char *uuid128,
					struct btd_attribute *attr);
void gatt_dbus_characteristic_unregister(const char *path);
