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

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "monitor/bt.h"

#include "src/shared/tester.h"
#include "src/shared/mgmt.h"
#include "src/shared/hciemu.h"

#define MAX_DEVICES 1

struct remote_hciemu {
	struct hciemu *device;
	uint16_t device_index;
	unsigned int mgmt_id;
	int sk;
};

struct test_data {
	struct mgmt *mgmt;
	uint16_t mgmt_index;
	struct hciemu *adapter;
	struct remote_hciemu devices[MAX_DEVICES];
	int devices_count;
	int current_device_count;
};

#define test_le(name, data, setup, func) \
	do { \
		int i; \
		struct test_data *user; \
		user = malloc(sizeof(struct test_data)); \
		if (!user) \
			break; \
		for (i = 0; i < MAX_DEVICES; i++) { \
			user->devices[i].device = NULL; \
			user->devices[i].sk = -1; \
		} \
		user->devices_count = data; \
		user->current_device_count = 0; \
		tester_add_full(name, NULL, test_pre_setup, setup, func, NULL, \
					test_post_teardown, 10, user, free); \
	} while (0)

static void powered_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_pre_setup_failed();
		return;
	}

	tester_print("Controller powered on");
	tester_pre_setup_complete();
}

static void set_le_powered(uint16_t index, mgmt_request_func_t callback)
{
	struct test_data *test = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on hci%d controller (with LE enabled)", index);

	mgmt_send(test->mgmt, MGMT_OP_SET_LE, index, sizeof(param), param, NULL,
								NULL, NULL);

	mgmt_send(test->mgmt, MGMT_OP_SET_POWERED, index, sizeof(param), param,
							callback, NULL, NULL);
}

static void index_added_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *test = tester_get_data();
	const unsigned int *id = user_data;

	tester_print("Index Added callback");
	tester_print("  Index: 0x%04x", index);

	test->mgmt_index = index;
	mgmt_unregister(test->mgmt, *id);

	set_le_powered(index, powered_callback);
}

static void index_removed_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *test = tester_get_data();

	tester_print("Index Removed callback");
	tester_print("  Index: 0x%04x", index);

	if (index != test->mgmt_index)
		return;

	mgmt_unregister_index(test->mgmt, test->mgmt_index);

	mgmt_unref(test->mgmt);
	test->mgmt = NULL;

	tester_post_teardown_complete();
}

static void read_index_list_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *test = tester_get_data();
	static unsigned int id;

	tester_print("Read Index List callback");
	tester_print("  Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}

	id = mgmt_register(test->mgmt, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
					index_added_callback, &id, NULL);

	mgmt_register(test->mgmt, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
					index_removed_callback, NULL, NULL);

	test->adapter = hciemu_new(HCIEMU_TYPE_LE);
	if (!test->adapter) {
		tester_warn("Failed to setup HCI emulation");
		tester_pre_setup_failed();
	}
}

static void test_pre_setup(const void *test_data)
{
	struct test_data *test = tester_get_data();

	test->mgmt = mgmt_new_default();
	if (!test->mgmt) {
		tester_warn("Failed to setup management interface");
		tester_pre_setup_failed();
		return;
	}

	mgmt_send(test->mgmt, MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, 0, NULL,
					read_index_list_callback, NULL, NULL);
}

static void test_post_teardown(const void *test_data)
{
	struct test_data *test = tester_get_data();
	int i;

	hciemu_unref(test->adapter);
	test->adapter = NULL;

	for (i = 0; i < test->devices_count; i++) {
		hciemu_unref(test->devices[i].device);
		close(test->devices[i].sk);
	}
}

static int pre_connection(int *sk)
{
	struct test_data *test = tester_get_data();
	struct sockaddr_l2 addr;

	/* Create socket */
	*sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_NONBLOCK,
								BTPROTO_L2CAP);
	if (*sk < 0) {
		tester_print("Can't create socket: %s (%d)", strerror(errno),
									errno);
		return -1;
	}

	/* Bind to local address */
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	str2ba(hciemu_get_address(test->adapter), &addr.l2_bdaddr);
	if (bind(*sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		tester_print("Can't bind socket: %s (%d)", strerror(errno),
									errno);
		close(*sk);
		return -1;
	}

	return 0;
}

static void device_powered_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *test = tester_get_data();

	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Device controller powered on");

	test->current_device_count++;
	if (test->current_device_count == test->devices_count)
		tester_setup_complete();
}

static void device_added_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *test = tester_get_data();
	struct remote_hciemu *remote = user_data;

	mgmt_unregister(test->mgmt, remote->mgmt_id);

	tester_print("Device Index Added callback");
	tester_print("  Index: 0x%04x", index);

	remote->device_index = index;
	set_le_powered(index, device_powered_callback);
}

static void setup_device_controller(struct remote_hciemu *remote)
{
	struct test_data *test = tester_get_data();

	remote->mgmt_id = mgmt_register(test->mgmt, MGMT_EV_INDEX_ADDED,
					MGMT_INDEX_NONE, device_added_callback,
					remote, NULL);

	remote->device = hciemu_new(HCIEMU_TYPE_LE);
	if (!remote->device) {
		tester_warn("Failed to setup HCI emulation for device");
		tester_setup_failed();
	}
}

static void setup_connection(const void *test_data)
{
	struct test_data *test = tester_get_data();
	int i;

	if (test->devices_count > MAX_DEVICES) {
		tester_warn("Exceed maximum number od devices");
		tester_setup_failed();
		return;
	}

	for (i = 0; i < test->devices_count; i++) {
		setup_device_controller(&test->devices[i]);

		if (pre_connection(&test->devices[i].sk) < 0) {
			tester_warn("Error on setup connection");
			tester_setup_failed();
			return;
		}
	}
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	test_le("Single Connection test - Not connected", 1, setup_connection,
									NULL);

	return tester_run();
}
