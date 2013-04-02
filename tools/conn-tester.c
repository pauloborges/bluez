/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "monitor/bt.h"

#include "src/shared/tester.h"
#include "src/shared/mgmt.h"
#include "src/shared/hciemu.h"

struct test_data {
	struct mgmt *mgmt;
	uint16_t mgmt_index;
};

#define test_le(name, data, setup, func) \
	do { \
		struct test_data *user; \
		user = malloc(sizeof(struct test_data)); \
		if (!user) \
			break; \
		tester_add_full(name, data, test_pre_setup, setup, func, NULL, \
							NULL, 10, user, free); \
	} while (0)


static void test_pre_setup(const void *test_data)
{
	struct test_data *test = tester_get_data();

	test->mgmt = mgmt_new_default();
	if (!test->mgmt) {
		tester_warn("Failed to setup management interface");
		tester_pre_setup_failed();
		return;
	}

	/* FIXME: Register callbacks to get events when controller was
	 * added/removed */
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	test_le("Single Connection test - Not connected", NULL, NULL, NULL);

	return tester_run();
}
