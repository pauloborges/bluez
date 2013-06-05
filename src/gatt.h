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

typedef void (*btd_attr_read_result_t) (int err, uint8_t *value, size_t len,
					void *user_data);
typedef void (*btd_attr_read_t) (struct btd_device *device,
					btd_attr_read_result_t result,
					void *user_data);

typedef void (*btd_attr_write_result_t) (int err, void *user_data);
typedef void (*btd_attr_write_t) (struct btd_device *device, uint8_t *value,
					size_t len, uint16_t offset,
					btd_attr_write_result_t result,
					void *user_data);

typedef void (*btd_attr_value_t) (uint8_t *value, size_t len, void *user_data);

void btd_gatt_service_manager_init(void);

void btd_gatt_service_manager_cleanup(void);

void gatt_discover_attributes(struct btd_device *device);

/* btd_gatt_add_service - Add a service declaration to local attribute database.
 * @uuid:	Service UUID.
 * @primary:	Set to 'true' if this is a primary services. Otherwise, it will
 *		be declared as a secondary service.
 *
 *
 * Returns a reference to service declaration attribute. In case of error,
 * NULL is returned.
 */
struct btd_attribute *btd_gatt_add_service(bt_uuid_t *uuid, bool primary);

/* btd_gatt_remove_service - Remove a service (along with all its
 * characteristics) from the local attribute database.
 * @service:	Service declaration attribute.
 */
void btd_gatt_remove_service(struct btd_attribute *service);

/* btd_gatt_add_char- Add a characteristic (declaration and value attributes)
 * to local attribute database.
 * @uuid:	Characteristic UUID.
 * @properties:	Characteristic properties.
 * @read_cb:	Callback that should be called once the characteristic value
 *		attribute is read.
 * @write_cb:	Callback that should be called once the characteristic value
 *		attribute is written.
 *
 * Returns a reference to characteristic value attribute. In case of error,
 * NULL is returned.
 */
struct btd_attribute *btd_gatt_add_char(bt_uuid_t *uuid, uint8_t properties,
					btd_attr_read_t read_cb,
					btd_attr_write_t write_cb);

/* btd_gatt_add_char_desc - Add a characteristic descriptor to local attribute
 * database.
 * @uuid:	Characteristic UUID.
 * @read_cb:	Callback that should be called once the characteristic
 *		descriptor attribute is read.
 * @write_cb:	Callback that should be called once the characteristic
 *		descriptor attribute is written.
 */
void btd_gatt_add_char_desc(bt_uuid_t *uuid, btd_attr_read_t read_cb,
				btd_attr_write_t write_cb);
