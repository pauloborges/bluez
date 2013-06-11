/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Instituto Nokia de Tecnologia - INdT
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

#include "lib/uuid.h"
#include "plugin.h"
#include "adapter.h"
#include "profile.h"
#include "service.h"
#include "log.h"

static int gatt_driver_probe(struct btd_service *service)
{
	DBG("Probing device");

	return 0;
}

static void gatt_driver_remove(struct btd_service *service)
{
	DBG("Removing device");
}

static struct btd_profile gatt_profile = {
	.name		= "gatt-gap-profile",
	.remote_uuid	= GATT_UUID,
	.device_probe	= gatt_driver_probe,
	.device_remove	= gatt_driver_remove
};

static int gatt_init(void)
{
	DBG("Initializing GATT/GAP plugin");

	btd_profile_register(&gatt_profile);

	return 0;
}

static void gatt_exit(void)
{
	DBG("Finishing GATT/GAP plugin");

	btd_profile_unregister(&gatt_profile);
}

BLUETOOTH_PLUGIN_DEFINE(gatt, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
					gatt_init, gatt_exit)