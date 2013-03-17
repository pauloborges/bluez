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
#include "config.h"
#endif

#include <glib.h>
#include <unistd.h>
#include <stdbool.h>

#include "lib/uuid.h"
#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "attrib/gatt.h"
#include "btio/btio.h"
#include "log.h"
#include "src/shared/util.h"

struct context {
	GMainLoop *main_loop;
	guint server_source;
	GAttrib *attrib;
	struct gatt_primary prim;
};

void btd_debug(const char *format, ...)
{
}

gboolean bt_io_get(GIOChannel *io, GError **err, BtIOOption opt1, ...)
{
	va_list args;
	BtIOOption opt = opt1;

	va_start(args, opt1);
	while (opt != BT_IO_OPT_INVALID) {
		switch (opt) {
		case BT_IO_OPT_SEC_LEVEL:
			*(va_arg(args, int *)) = BT_SECURITY_HIGH;
			break;
		case BT_IO_OPT_IMTU:
			*(va_arg(args, uint16_t *)) = 512;
			break;
		case BT_IO_OPT_CID:
			*(va_arg(args, uint16_t *)) = ATT_CID;
			break;
		default:
			if (g_test_verbose() == TRUE)
				printf("Unknown option %d\n", opt);

			return FALSE;
		}

		opt = va_arg(args, int);
	}
	va_end(args);

	return TRUE;
}

static gboolean handle_mtu_exchange(int fd)
{
	uint8_t pdu[ATT_DEFAULT_LE_MTU];
	uint16_t mtu, pdu_len;
	ssize_t len;

	len = recv(fd, pdu, sizeof(pdu), 0);
	g_assert(len > 0);

	pdu_len = dec_mtu_req(pdu, len, &mtu);
	g_assert(pdu_len == 1 + sizeof(uint16_t));

	if (g_test_verbose() == TRUE)
		printf("Received Exchange MTU Request: Client Rx MTU 0x%04x\n",
									mtu);

	/* Just reply with same MTU as client */
	pdu_len = enc_mtu_resp(mtu, pdu, len);
	g_assert(pdu_len == 1 + sizeof(uint16_t));

	len = write(fd, pdu, pdu_len);
	g_assert(len == pdu_len);

	return TRUE;
}

static gboolean handle_read_by_group(int fd, struct context *context)
{
	uint8_t pdu[ATT_DEFAULT_LE_MTU];
	uint16_t pdu_len, start, end;
	struct att_data_list *adl;
	bt_uuid_t uuid, prim;
	uint8_t *value;
	ssize_t len;

	len = recv(fd, pdu, sizeof(pdu), 0);
	g_assert(len > 0);

	pdu_len = dec_read_by_grp_req(pdu, len, &start, &end, &uuid);
	g_assert(pdu_len == len);

	bt_uuid16_create(&prim, GATT_PRIM_SVC_UUID);
	g_assert(bt_uuid_cmp(&uuid, &prim) == 0);

	adl = att_data_list_alloc(1, sizeof(uint16_t) * 3);
	g_assert(adl != NULL);

	value = adl->data[0];

	if (start == 0x0001 && end == 0xffff) {
		att_put_u16(0x0001, &value[0]);
		att_put_u16(0x000f, &value[2]);
		att_put_u16(0xaaaa, &value[4]);

		context->prim.range.start = 0x0001;
		context->prim.range.end = 0x000f;
		strcpy(context->prim.uuid,
					"0000aaaa-0000-1000-8000-00805f9b34fb");
	} else if (start == 0x0010 && end == 0xffff) {
		att_put_u16(0x0010, &value[0]);
		att_put_u16(0x001f, &value[2]);
		att_put_u16(0xbbbb, &value[4]);

		context->prim.range.start = 0x0010;
		context->prim.range.end = 0x001f;
		strcpy(context->prim.uuid,
					"0000bbbb-0000-1000-8000-00805f9b34fb");
	} else if (start == 0x0020 && end == 0xffff) {
		att_put_u16(0x0020, &value[0]);
		/* Test "optimization" permitted by Core spec Erratum 4063. */
		att_put_u16(0xffff, &value[2]);
		att_put_u16(0xcccc, &value[4]);

		context->prim.range.start = 0x0020;
		context->prim.range.end = 0xffff;
		strcpy(context->prim.uuid,
					"0000cccc-0000-1000-8000-00805f9b34fb");
	} else {
		/* Signal end of attribute group (primary service) */
		pdu_len = enc_error_resp(pdu[0], start,
						ATT_ECODE_ATTR_NOT_FOUND,
						pdu, sizeof(pdu));
		g_assert(pdu_len == 5);

		memset(&context->prim, 0, sizeof(context->prim));

		goto done;
	}

	pdu_len = enc_read_by_grp_resp(adl, pdu, sizeof(pdu));
	g_assert(pdu_len == sizeof(uint16_t) * 3 + 2);

done:
	att_data_list_free(adl);

	len = write(fd, pdu, pdu_len);
	g_assert(len == pdu_len);

	return TRUE;
}

static gboolean server_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct context *context = user_data;
	uint8_t opcode;
	ssize_t len;
	int fd;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);
	len = recv(fd, &opcode, sizeof(opcode), MSG_PEEK);
	g_assert(len == sizeof(opcode));

	if (g_test_verbose() == TRUE)
		printf("ATT request received (opcode 0x%02x)\n", opcode);

	switch (opcode) {
	case ATT_OP_MTU_REQ:
		return handle_mtu_exchange(fd);
	case ATT_OP_READ_BY_GROUP_REQ:
		return handle_read_by_group(fd, context);
	default:
		g_assert_not_reached();
	}

	return FALSE;
}

static struct context *create_context(void)
{
	struct context *context = g_new0(struct context, 1);
	GIOChannel *channel;
	int err, sv[2];

	context->main_loop = g_main_loop_new(NULL, FALSE);
	g_assert(context->main_loop);

	err = socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv);
	g_assert(err == 0);

	channel = g_io_channel_unix_new(sv[0]);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	context->server_source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				server_handler, context);
	g_assert(context->server_source > 0);

	g_io_channel_unref(channel);

	channel = g_io_channel_unix_new(sv[1]);
	g_io_channel_set_close_on_unref(channel, TRUE);
	context->attrib = g_attrib_new(channel);
	g_io_channel_unref(channel);

	return context;
}

static void execute_context(struct context *context)
{
	g_main_loop_run(context->main_loop);

	g_source_remove(context->server_source);
	g_main_loop_unref(context->main_loop);
	g_attrib_unref(context->attrib);

	g_free(context);
}

static void exchange_mtu_cb(uint8_t status, uint16_t mtu, void *user_data)
{
	struct context *context = user_data;

	g_assert(status == 0);

	if (g_test_verbose() == TRUE)
		printf("Received Exchange MTU Response: Server Rx MTU 0x%04x\n",
									mtu);

	g_assert(mtu == ATT_DEFAULT_LE_MTU);

	g_main_loop_quit(context->main_loop);
}

static void test_gatt_exchange_mtu(void)
{
	struct context *context = create_context();

	gatt_exchange_mtu(context->attrib, ATT_DEFAULT_LE_MTU, exchange_mtu_cb,
								context);

	execute_context(context);
}

static bool discover_primary_cb(uint8_t status, GSList *services,
								void *user_data)
{
	struct context *context = user_data;
	struct gatt_primary *prim;

	if (status == ATT_ECODE_ATTR_NOT_FOUND) {
		g_main_loop_quit(context->main_loop);
		return false;
	}

	g_assert_cmpuint(status, ==, 0);
	g_assert_cmpuint(g_slist_length(services), ==, 1);

	prim = g_slist_nth_data(services, 0);

	if (g_test_verbose() == TRUE)
		printf("Got handle range 0x%04x-0x%04x\n", prim->range.start,
							prim->range.end);

	g_assert(memcmp(prim, &context->prim, sizeof(context->prim)) == 0);

	return true;
}

static void test_gatt_discover_primary(void)
{
	struct context *context = create_context();

	gatt_discover_primary(context->attrib, NULL, discover_primary_cb,
								context);

	execute_context(context);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/gatt/gatt_exchange_mtu", test_gatt_exchange_mtu);
	g_test_add_func("/gatt/gatt_discover_primary",
						test_gatt_discover_primary);

	return g_test_run();
}
