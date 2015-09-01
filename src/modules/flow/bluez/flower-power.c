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

#include "bluez-gen.h"

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

#include "bluez.h"

#define GATT_SERVICES_CHANGED_WATCH "sender='org.freedesktop.DBus',"    \
    "type='signal',"                                                    \
    "interface='org.freedesktop.DBus.Properties',"                      \
    "member='PropertiesChnaged',"                                       \
    "path='%s',"                                                        \
    "arg0='org.bluez.Device1',"

struct sensor_data {
    char *remote;
};

struct led_data {
    char *remote;
};

static struct context {
    struct sol_bus_client *client;
    struct sol_ptr_vector sensors;
    struct sol_ptr_vector leds;
} context =  {
    .sensors = SOL_PTR_VECTOR_INIT,
    .leds = SOL_PTR_VECTOR_INIT,
};

enum {
    BLUEZ_DEVICE_INTERFACE,
    BLUEZ_GATT_SERVICE_INTERFACE,
};

static void
bluez_device_property_changed(void *data, uint64_t mask)
{

}

static void
bluez_device_appeared(void *data, const char *path)
{
    struct context *c = data;
    int r;

    r = sol_bus_map_cached_properties(c->client, path, "org.bluez.Device1", device_properties,

}

static void
bluez_gatt_service_appeared(void *data, const char *path)
{

}

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

enum {
    BLUEZ_DEVICE_ADDRESS_PROPERTY,
    BLUEZ_DEVICE_GATT_SERVICES_PROPERTY,
};

static bool
bluez_device_address_property_set(void *data, sd_bus_message *m)
{
    return false;
}

static bool
bluez_device_gatt_services_property_set(void *data, sd_bus_message *m)
{
    return false;
}

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

enum {
    BLUEZ_SERVICE_UUID_PROPERTY,
    BLUEZ_SERVICE_CHARACTERISTICS_PROPERTY,
};

static bool
bluez_service_uuid_property_set(void *data, sd_bus_message *m)
{
    return false;
}

static bool
bluez_service_characteristics_property_set(void *data, sd_bus_message *m)
{
    return false;
}

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

static int
flower_power_sensor_open(struct sol_flow_node *node, void *data,
    const struct sol_flow_node_options *options)
{
    return -ENOSYS;
}

static void
flower_power_sensor_close(struct sol_flow_node *node, void *data)
{

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

static int
flower_power_led_open(struct sol_flow_node *node, void *data,
    const struct sol_flow_node_options *options)
{
    struct led_data *led = data;
    struct sol_flow_node_type_bluez_flower_power_sensor_options *opts =
        (struct sol_flow_node_type_bluez_flower_power_sensor_options *) options;
    int r;

    led->remote = strdup(opts->address);

    if (!context.client) {
        context.client = sol_bus_client_new(sol_bus_get(NULL), "org.bluez");
        SOL_NULL_CHECK(context.client, -ENOMEM);
    }

    r = sol_ptr_vector_append(&context.leds, led);
    SOL_INT_CHECK(r, < 0, -ENOMEM);

    r = sol_bus_watch_interfaces(context.client, bluez_interfaces, &context);
    SOL_INT_CHECK_GOTO(r, < 0, error_watch);

    return 0;

error_watch:
    sol_ptr_vector_del(&context.leds,
        sol_ptr_vector_get_len(&context.leds) - 1);

    return -EINVAL;
}

static void
flower_power_led_close(struct sol_flow_node *node, void *data)
{

}

#include "bluez-gen.c"
