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

#define MAX_DEVICES 3

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
	int unmet_conditions;
};

#define CID 4

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
		user->unmet_conditions = 0; \
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

static void test_add_condition(struct test_data *test)
{
	test->unmet_conditions++;

	tester_print("Test condition added, total %d", test->unmet_conditions);
}

static void test_condition_complete(struct test_data *test)
{
	test->unmet_conditions--;

	tester_print("Test condition complete, %d left",
							test->unmet_conditions);

	if (test->unmet_conditions > 0)
		return;

	tester_test_passed();
}

static gboolean received_hci_event(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *test = tester_get_data();
	char buf[1 + HCI_EVENT_HDR_SIZE + EVT_CMD_COMPLETE_SIZE + 1], *ptr;
	evt_cmd_complete *cc;
	hci_event_hdr *hdr;
	uint8_t status;
	gsize len;

	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL))
		goto failed;

	if (g_io_channel_read_chars(io, (gchar *) buf, sizeof(buf), &len,
						NULL) != G_IO_STATUS_NORMAL)
		goto failed;

	if (len != sizeof(buf))
		goto failed;

	ptr = buf + 1;
	hdr = (void *) ptr;
	if (hdr->evt != EVT_CMD_COMPLETE ||
					hdr->plen != EVT_CMD_COMPLETE_SIZE + 1)
		goto failed;

	ptr += HCI_EVENT_HDR_SIZE;
	cc = (void *) ptr;
	if (btohs(cc->opcode) != cmd_opcode_pack(OGF_LE_CTL,
						OCF_LE_SET_ADVERTISE_ENABLE))
		goto failed;

	ptr += EVT_CMD_COMPLETE_SIZE;
	status = *ptr;
	if (status != 0)
		goto failed;

	test_condition_complete(test);

	return FALSE;

failed:
	tester_test_failed();

	return FALSE;
}

static int enable_le_advertising(int hdev)
{
	le_set_advertise_enable_cp adv_cp;
	struct hci_filter nf;
	GIOChannel *channel;
	uint16_t opcode;
	int dd;

	dd = hci_open_dev(hdev);
	if (dd < 0) {
		tester_warn("Could not open device");
		return -1;
	}

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_CMD_COMPLETE, &nf);
	opcode = htobs(cmd_opcode_pack(OGF_LE_CTL,
						OCF_LE_SET_ADVERTISE_ENABLE));
	hci_filter_set_opcode(opcode, &nf);
	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
		tester_warn("Error setting the socket filter");
		return -1;
	}

	channel = g_io_channel_unix_new(dd);
	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	g_io_add_watch_full(channel, G_PRIORITY_DEFAULT,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				received_hci_event, NULL, NULL);

	g_io_channel_unref(channel);

	adv_cp.enable = 0x01;
	if (hci_send_cmd(dd, OGF_LE_CTL, OCF_LE_SET_ADVERTISE_ENABLE,
						sizeof(adv_cp), &adv_cp) < 0) {
		tester_warn("Error sending LE ADV Enable command");
		return -1;
	}

	return 0;
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

static gboolean test_timeout(gpointer user_data)
{
	struct remote_hciemu *remote = user_data;

	tester_print("Close socket");

	close(remote->sk);

	return FALSE;
}

static void close_socket(struct remote_hciemu *remote)
{
	g_timeout_add_seconds(2, test_timeout, remote);
}

static bool command_hci_callback(uint16_t opcode, const void *param,
						uint8_t length, void *user_data)
{
	struct test_data *test = tester_get_data();
	const uint8_t *p = param;

	tester_print("HCI Command 0x%04x length %u", opcode, length);

	if (opcode != BT_HCI_CMD_LE_SET_SCAN_ENABLE)
		return true;

	if (length != sizeof(struct bt_hci_cmd_le_set_scan_enable)) {
		tester_warn("Invalid parameter size for HCI command");
		goto error;
	}

	switch (p[0]) {
	case 0x00:
		test_condition_complete(test);
		return true;
	case 0x01:
		test_add_condition(test);
		return true;
	default:
		tester_warn("Unexpected HCI cmd parameter");
		goto error;
	}

error:
	tester_test_failed();
	return false;
}

static gboolean no_connect_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *test = tester_get_data();

	tester_print("Checking connect result...");

	if (cond & G_IO_OUT)
		tester_test_failed();
	else
		test_condition_complete(test);

	g_io_channel_unref(io);

	return FALSE;
}

static int create_connection(struct remote_hciemu *remote, GIOFunc conn_cb)
{
	struct test_data *test = tester_get_data();
	const char *remote_addr;
	struct sockaddr_l2 addr;
	GIOCondition cond;
	GIOChannel *channel;
	int err;

	remote_addr = hciemu_get_address(remote->device);

	/* Connect to remote device */
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	str2ba(remote_addr, &addr.l2_bdaddr);
	addr.l2_bdaddr_type = BDADDR_LE_PUBLIC;
	addr.l2_cid = htobs(CID);

	channel = g_io_channel_unix_new(remote->sk);
	cond = G_IO_OUT | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	g_io_add_watch_full(channel, G_PRIORITY_DEFAULT, cond, conn_cb,
								NULL, NULL);

	/* Add condition for connection result */
	test_add_condition(test);

	err = connect(remote->sk, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0 && errno != EINPROGRESS) {
		tester_warn("Can't connect: %s (%d)", strerror(errno), errno);
		close(remote->sk);
		return -1;
	}

	return 0;
}

static void test_command_connect(const void *test_data)
{
	struct test_data *test = tester_get_data();
	int i;

	hciemu_add_master_post_command_hook(test->adapter, command_hci_callback,
									NULL);

	for (i = 0; i < test->devices_count; i++) {

		if (create_connection(&test->devices[i], no_connect_cb) < 0) {
			tester_test_failed();
			return;
		}

		close_socket(&test->devices[i]);
	}
}

static gboolean connect_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *test = tester_get_data();

	tester_print("Checking connect result...");

	if (cond & G_IO_OUT)
		test_condition_complete(test);
	else
		tester_test_failed();

	g_io_channel_unref(io);

	return FALSE;
}

static void test_success_connect_1(const void *test_data)
{
	struct test_data *test = tester_get_data();
	int i;

	for (i = 0; i < test->devices_count; i++) {

		/* Add conditions for LE advertising */
		test_add_condition(test);

		if (enable_le_advertising(test->devices[i].device_index) < 0)
			tester_test_failed();

		if (create_connection(&test->devices[i], connect_cb) < 0)
			tester_test_failed();
	}
}

static gboolean enable_later_adv(gpointer user_data)
{
	struct remote_hciemu *remote = user_data;

	if (enable_le_advertising(remote->device_index) < 0)
		tester_test_failed();

	return FALSE;
}

static void test_success_connect_2(const void *test_data)
{
	struct test_data *test = tester_get_data();
	int i;

	for (i = 0; i < test->devices_count; i++) {

		if (create_connection(&test->devices[i], connect_cb) < 0)
			tester_test_failed();

		/* Add conditions for LE advertising */
		test_add_condition(test);

		g_timeout_add_seconds(2, enable_later_adv, &test->devices[i]);
	}
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	test_le("Single Connection test - Not connected", 1, setup_connection,
							test_command_connect);
	test_le("Single Connection test - Success 1", 1, setup_connection,
							test_success_connect_1);
	test_le("Single Connection test - Success 2", 1, setup_connection,
							test_success_connect_2);

	test_le("Multiple Connection test - Not connected", 3, setup_connection,
							test_command_connect);

	return tester_run();
}
