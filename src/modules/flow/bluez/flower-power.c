/*
 * This file is part of the Soletta Project
 *
 * Copyright (C) 2015 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "sol-flow/bluez.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <systemd/sd-bus.h>

#include "sol-bus.h"
#include "sol-flow.h"
#include "sol-mainloop.h"
#include "sol-types.h"
#include "sol-util.h"
#include "sol-str-table.h"
#include "sol-flower-power.h"

#include "bluez.h"

#define GATT_SERVICES_CHANGED_WATCH "sender='org.freedesktop.DBus',"    \
    "type='signal',"                                                    \
    "interface='org.freedesktop.DBus.Properties',"                      \
    "member='PropertiesChnaged',"                                       \
    "path='%s',"                                                        \
    "arg0='org.bluez.Device1',"

enum characteristic_types {
    CHAR_TYPE_LIGHT_SENSOR_VALUE,
    CHAR_TYPE_SOIL_EC,
    CHAR_TYPE_SOIL_TEMP,
    CHAR_TYPE_AIR_TEMP,
    CHAR_TYPE_SOIL_VWC,
    CHAR_TYPE_LIVE_MEASURE_PERIOD,
    CHAR_TYPE_LED_STATE,
    CHAR_TYPE_SIZE,
};

static const struct sol_str_table characteristic_uuid_to_type[] = {
    SOL_STR_TABLE_ITEM("39E1FA01-84A8-11E2-AFBA-0002A5D5C51B", CHAR_TYPE_LIGHT_SENSOR_VALUE),
    SOL_STR_TABLE_ITEM("39E1FA02-84A8-11E2-AFBA-0002A5D5C51B", CHAR_TYPE_SOIL_EC),
    SOL_STR_TABLE_ITEM("39E1FA03-84A8-11E2-AFBA-0002A5D5C51B", CHAR_TYPE_SOIL_TEMP),
    SOL_STR_TABLE_ITEM("39E1FA04-84A8-11E2-AFBA-0002A5D5C51B", CHAR_TYPE_AIR_TEMP),
    SOL_STR_TABLE_ITEM("39E1FA05-84A8-11E2-AFBA-0002A5D5C51B", CHAR_TYPE_SOIL_VWC),
    SOL_STR_TABLE_ITEM("39E1FA06-84A8-11E2-AFBA-0002A5D5C51B", CHAR_TYPE_LIVE_MEASURE_PERIOD),
    SOL_STR_TABLE_ITEM("39E1FA07-84A8-11E2-AFBA-0002A5D5C51B", CHAR_TYPE_LED_STATE),
};

struct service {
    char *uuid;
    char *path;
};

struct flower_power_data {
    struct sol_bus_client *client;
    const char *uuid;
    char *address;
    char *device;
    char *service;
    char *chr_path[CHAR_TYPE_SIZE];
    struct sol_flow_node *node;
    struct sol_flower_power_data value;
};

struct pending_device {
    char *remote;
    char *path;
    struct sol_vector services;
    struct flower_power_data *flower;
};

static struct context {
    struct sol_bus_client *client;
    struct sol_vector pending_devices; /* Devices without complete information */
    struct sol_ptr_vector flowers;
} context =  {
    .pending_devices = SOL_VECTOR_INIT(struct pending_device),
    .flowers = SOL_PTR_VECTOR_INIT,
};

enum {
    BLUEZ_DEVICE_INTERFACE,
    BLUEZ_GATT_SERVICE_INTERFACE,
};

enum {
    BLUEZ_DEVICE_ADDRESS_PROPERTY,
    BLUEZ_DEVICE_GATT_SERVICES_PROPERTY,
};

enum {
    BLUEZ_SERVICE_UUID_PROPERTY,
    BLUEZ_SERVICE_CHARACTERISTICS_PROPERTY,
};

enum {
    BLUEZ_CHARACTERISTIC_UUID_PROPERTY,
    BLUEZ_CHARACTERISTIC_VALUE_PROPERTY,
};

#define LIVE_MEASURE_PERIOD 5

static void bluez_device_appeared(void *data, const char *path);
static void bluez_gatt_service_appeared(void *data, const char *path);
static bool bluez_device_address_property_set(void *data, const char *path, sd_bus_message *m);
static bool bluez_device_gatt_services_property_set(void *data, const char *path, sd_bus_message *m);
static bool bluez_service_uuid_property_set(void *data, const char *path, sd_bus_message *m);
static bool bluez_service_characteristics_property_set(void *data, const char *path, sd_bus_message *m);
static bool bluez_characteristic_uuid_property_set(void *data, const char *path, sd_bus_message *m);
static bool bluez_characteristic_value_property_set(void *data, const char *path, sd_bus_message *m);

static const struct sol_bus_interfaces bluez_interfaces[] = {
    [BLUEZ_DEVICE_INTERFACE] = {
        .name = "org.bluez.Device1",
        .appeared = bluez_device_appeared,
    },
    [BLUEZ_GATT_SERVICE_INTERFACE] = {
        .name = "org.bluez.GattService1",
        .appeared = bluez_gatt_service_appeared,
    },
    { }
};

static const struct sol_bus_properties device_properties[] = {
    [BLUEZ_DEVICE_ADDRESS_PROPERTY] = {
        .member = "Address",
        .set = bluez_device_address_property_set,
    },
    [BLUEZ_DEVICE_GATT_SERVICES_PROPERTY] = {
        .member = "GattServices",
        .set = bluez_device_gatt_services_property_set,
    },
    { }
};

static const struct sol_bus_properties service_properties[] = {
    [BLUEZ_SERVICE_UUID_PROPERTY] = {
        .member = "UUID",
        .set = bluez_service_uuid_property_set,
    },
    [BLUEZ_SERVICE_CHARACTERISTICS_PROPERTY] = {
        .member = "Characteristics",
        .set = bluez_service_characteristics_property_set,
    },
    { }
};

static const struct sol_bus_properties characteristic_properties[] = {
    [BLUEZ_CHARACTERISTIC_UUID_PROPERTY] = {
        .member = "UUID",
        .set = bluez_characteristic_uuid_property_set,
    },
    [BLUEZ_CHARACTERISTIC_VALUE_PROPERTY] = {
        .member = "Value",
        .set = bluez_characteristic_value_property_set,
    },
    { }
};

static void
bluez_gatt_service_property_changed(void *data, const char *path, uint64_t mask)
{

}

static void
bluez_characteristic_property_changed(void *data, const char *path,
    uint64_t mask)
{
    struct flower_power_data *f = data;

    sol_flower_power_send_packet(f->node,
        SOL_FLOW_NODE_TYPE_BLUEZ_FLOWER_POWER_SENSOR__OUT__OUT, &f->value);
}

static void
bluez_device_property_changed(void *data, const char *path, uint64_t mask)
{
    struct context *c = data;
    struct pending_device *p;
    uint16_t i;

    if (!(mask & (1 << BLUEZ_DEVICE_GATT_SERVICES_PROPERTY)))
        return;

    SOL_VECTOR_FOREACH_IDX (&c->pending_devices, p, i) {
        struct service *s;
        uint16_t j;

        if (p->services.len == 0)
            continue;

        SOL_VECTOR_FOREACH_IDX (&p->services, s, j) {
            sol_bus_map_cached_properties(c->client, s->path,
                "org.bluez.GattService1", service_properties,
                bluez_gatt_service_property_changed, p);
        }
    }
}

static void
bluez_device_appeared(void *data, const char *path)
{
    struct context *c = data;

    SOL_DBG("context %p path %s", c, path);

    sol_bus_map_cached_properties(c->client, path, "org.bluez.Device1",
        device_properties, bluez_device_property_changed, c);
}

static void
bluez_gatt_service_appeared(void *data, const char *path)
{

}

static struct pending_device *
find_pending_device_by_path(struct context *c, const char *path)
{
    struct pending_device *p;
    uint16_t i;

    SOL_VECTOR_FOREACH_IDX (&c->pending_devices, p, i) {
        if (streq(p->path, path))
            return p;
    }
    return NULL;
}

static struct flower_power_data *
find_flower_by_address(struct context *c, const char *address)
{
    struct flower_power_data *f;
    uint16_t i;

    SOL_PTR_VECTOR_FOREACH_IDX (&c->flowers, f, i) {
        if (streq(f->address, address))
            return f;
    }
    return NULL;
}

static bool
bluez_device_address_property_set(void *data, const char *path, sd_bus_message *m)
{
    struct context *c = data;
    struct pending_device *p;
    struct flower_power_data *f;
    const char *address;
    int r;

    r = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, "s");
    SOL_INT_CHECK_GOTO(r, < 0, error);

    r = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &address);
    SOL_INT_CHECK_GOTO(r, < 0, error);

    f = find_flower_by_address(c, address);
    if (!f)
        goto error;

    if (!f->device) {
        f->device = strdup(path);
        SOL_NULL_CHECK_GOTO(f->device, error);
    }

    p = find_pending_device_by_path(c, path);
    if (p)
        goto error;

    SOL_DBG("pending path %s address %s", path, address);

    p = sol_vector_append(&c->pending_devices);
    SOL_NULL_CHECK_GOTO(p, error);

    p->flower = f;

    sol_vector_init(&p->services, sizeof(struct service));

    p->remote = strdup(address);
    SOL_NULL_CHECK_GOTO(p->remote, error_alloc);

    p->path = strdup(path);
    SOL_NULL_CHECK_GOTO(p->path, error_alloc);

    sd_bus_message_exit_container(m);

    return true;

error_alloc:
    free(p->remote);
    free(p->path);

    sol_vector_del(&c->pending_devices, c->pending_devices.len - 1);

error:
    sd_bus_message_exit_container(m);

    return false;
}

static bool
bluez_device_gatt_services_property_set(void *data, const char *path, sd_bus_message *m)
{
    struct context *c = data;
    struct pending_device *p;
    int r;

    p = find_pending_device_by_path(c, path);
    if (!p)
        goto end;

    r = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, "ao");
    SOL_INT_CHECK_GOTO(r, < 0, end);

    r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "o");
    SOL_INT_CHECK_GOTO(r, < 0, end);

    while (sd_bus_message_read_basic(m, SD_BUS_TYPE_OBJECT_PATH, &path) >= 0) {
        struct service *s = sol_vector_append(&p->services);
        SOL_NULL_CHECK_GOTO(s, end);

        s->path = strdup(path);
        if (!s->path) {
            sol_vector_del(&p->services, p->services.len - 1);
            goto end;
        }
    }

    r = sd_bus_message_exit_container(m);
    SOL_INT_CHECK(r, < 0, false);

    r = sd_bus_message_exit_container(m);
    SOL_INT_CHECK(r, < 0, false);

    return true;

end:
    sd_bus_message_exit_container(m);
    return false;
}

static bool
bluez_service_uuid_property_set(void *data, const char *path, sd_bus_message *m)
{
    struct pending_device *p = data;
    struct flower_power_data *f = p->flower;
    const char *uuid;
    int r;

    r = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, "s");
    SOL_INT_CHECK_GOTO(r, < 0, end);

    r = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &uuid);
    SOL_INT_CHECK_GOTO(r, < 0, end);

    if (!streq(f->uuid, uuid))
        return false;

    f->service = strdup(path);
    SOL_NULL_CHECK_GOTO(f->service, end);

    return true;

end:
    sd_bus_message_exit_container(m);

    return false;
}

static bool
bluez_service_characteristics_property_set(void *data, const char *path, sd_bus_message *m)
{
    struct pending_device *p = data;
    struct flower_power_data *f = p->flower;
    const char *chr_path;
    int r;

    if (!streq(f->service, path))
        return false;

    r = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, "ao");
    SOL_INT_CHECK_GOTO(r, < 0, end);

    r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "o");
    SOL_INT_CHECK_GOTO(r, < 0, end);

    while (sd_bus_message_read_basic(m, SD_BUS_TYPE_OBJECT_PATH, &chr_path) >= 0) {
        sol_bus_map_cached_properties(f->client, chr_path, "org.bluez.GattCharacteristic1",
            characteristic_properties, bluez_characteristic_property_changed, f);
    }

    r = sd_bus_message_exit_container(m);
    SOL_INT_CHECK(r, < 0, false);

    r = sd_bus_message_exit_container(m);
    SOL_INT_CHECK(r, < 0, false);

    return true;

end:
    sd_bus_message_exit_container(m);
    return false;
}

static bool
bluez_characteristic_uuid_property_set(void *data, const char *path, sd_bus_message *m)
{
    struct flower_power_data *f = data;
    const char *uuid;
    struct sol_str_slice key;
    enum characteristic_types type;
    int r;

    r = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, "s");
    SOL_INT_CHECK_GOTO(r, < 0, error);

    r = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &uuid);
    SOL_INT_CHECK_GOTO(r, < 0, error);

    key = sol_str_slice_from_str(uuid);

    type = sol_str_table_lookup_fallback(characteristic_uuid_to_type, key, CHAR_TYPE_SIZE);
    if (type == CHAR_TYPE_SIZE)
        return false;

    f->chr_path[type] = strdup(path);
    SOL_NULL_CHECK_GOTO(f->chr_path[type], error);

    return true;

error:
    sd_bus_message_exit_container(m);

    return false;
}

static bool packet_set_value(struct sol_flower_power_data *packet,
    enum characteristic_types type, const uint8_t value[], size_t len)
{
    uint16_t d;
    double info;

    if (type == CHAR_TYPE_SIZE ||
        type == CHAR_TYPE_LED_STATE ||
        type == CHAR_TYPE_LIVE_MEASURE_PERIOD)
        return false;

    if (len < 2)
        return false;

    d = (uint16_t) value[0] << 8 || value[1];
    info = (double) (d * 3.3) / ((1 << 11) - 1);

    switch (type) {
    case CHAR_TYPE_LIGHT_SENSOR_VALUE:
        packet->light.val = info;
        return true;
    case CHAR_TYPE_SOIL_EC:
        /* FIXME: what does this represent? */
        return false;
    case CHAR_TYPE_SOIL_TEMP:
        packet->temperature.val = info;
        return true;
    case CHAR_TYPE_AIR_TEMP:
        return false;
    case CHAR_TYPE_SOIL_VWC:
        packet->water.val = info;
        return true;
    case CHAR_TYPE_LIVE_MEASURE_PERIOD:
    case CHAR_TYPE_LED_STATE:
    case CHAR_TYPE_SIZE:
        return false;
    }
    return false;
}

static bool
enable_characteristic_notification(struct sol_bus_client *client, const char *path)
{
    sd_bus_message *m;
    int r;

    r = sd_bus_message_new_method_call(sol_bus_client_get_bus(client), &m,
        sol_bus_client_get_service(client), path,
        "org.bluez.GattCharacteristic1", "StartNotify");
    SOL_INT_CHECK(r, < 0, false);

    r = sd_bus_call_async(sol_bus_client_get_bus(client), NULL, m, NULL, NULL, 0);
    SOL_INT_CHECK(r, < 0, false);

    return true;
}

static bool
write_live_measure_period(struct sol_bus_client *client, const char *path, uint8_t period)
{
    sd_bus_message *m;
    int r;

    r = sd_bus_message_new_method_call(sol_bus_client_get_bus(client), &m,
        sol_bus_client_get_service(client), path,
        "org.bluez.GattCharacteristic1",
        "WriteValue");
    SOL_INT_CHECK(r, < 0, false);

    r = sd_bus_message_append_array(m, 'y', &period, sizeof(period));
    SOL_INT_CHECK(r, < 0, false);

    r = sd_bus_call_async(sol_bus_client_get_bus(client), NULL, m, NULL, NULL, 0);
    SOL_INT_CHECK(r, < 0, false);

    return true;
}

static bool
bluez_characteristic_value_property_set(void *data, const char *path, sd_bus_message *m)
{
    struct flower_power_data *f = data;
    uint8_t *value;
    size_t len;
    int type, r;
    bool found = false;

    r = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, "ay");
    SOL_INT_CHECK_GOTO(r, < 0, end);

    for (type = 0; type < CHAR_TYPE_SIZE; type++) {
        if (streq(path, f->chr_path[type])) {
            found = true;
            break;
        }
    }

    if (!found)
        goto end;

    r = sd_bus_message_read_array(m, 'y', (const void **) &value, &len);
    SOL_INT_CHECK_GOTO(r, < 0, end);

    enable_characteristic_notification(f->client, path);

    if (type == CHAR_TYPE_LIVE_MEASURE_PERIOD && len == 1 && value[0] != LIVE_MEASURE_PERIOD) {
        write_live_measure_period(f->client, path, LIVE_MEASURE_PERIOD);
    }

    if (!packet_set_value(&f->value, type, value, len))
        goto end;

    return true;

end:
    sd_bus_message_exit_container(m);
    return false;
}

static int
flower_power_sensor_open(struct sol_flow_node *node, void *data,
    const struct sol_flow_node_options *options)
{
    static const char *uuid = "39E1FA00-84A8-11E2-AFBA-0002A5D5C51B";
    struct flower_power_data *flower = data;
    struct sol_flow_node_type_bluez_flower_power_sensor_options *opts =
        (struct sol_flow_node_type_bluez_flower_power_sensor_options *) options;
    int r;

    flower->address = strdup(opts->address);
    flower->uuid = uuid;
    flower->node = node;

    SOL_DBG("flower %p address %s", flower,  flower->address);

    if (!context.client) {
        context.client = sol_bus_client_new(sol_bus_get(NULL), "org.bluez");
        SOL_NULL_CHECK(context.client, -ENOMEM);
    }

    flower->client = context.client;

    r = sol_ptr_vector_append(&context.flowers, flower);
    SOL_INT_CHECK(r, < 0, -ENOMEM);

    r = sol_bus_watch_interfaces(context.client, bluez_interfaces, &context);
    SOL_INT_CHECK_GOTO(r, < 0, error_watch);

    return 0;

error_watch:
    sol_ptr_vector_del(&context.flowers,
        sol_ptr_vector_get_len(&context.flowers) - 1);

    return -EINVAL;
}

static void
flower_power_sensor_close(struct sol_flow_node *node, void *data)
{
    struct flower_power_data *flower = data;
    int i;

    free(flower->address);
    free(flower->device);
    free(flower->service);

    for (i = 0; i < CHAR_TYPE_SIZE; i++) {
        free(flower->chr_path[i]);
    }

    sol_bus_client_free(flower->client);
}

static int
flower_power_led_in_process(struct sol_flow_node *node,
    void *data,
    uint16_t port,
    uint16_t conn_id,
    const struct sol_flow_packet *packet)
{
    return -ENOSYS;
}

#include "bluez-gen.c"
