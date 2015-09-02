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

struct service {
    char *uuid;
    char *path;
};

struct pending_device {
    char *remote;
    char *path;
    struct sol_vector services;
};

struct sensor_data {
    char *address;
};

struct led_data {
    char *address;
};

static struct context {
    struct sol_bus_client *client;
    struct sol_vector pending_devices; /* Devices without complete information */
    struct sol_ptr_vector leds;
    struct sol_ptr_vector sensors;
} context =  {
    .pending_devices = SOL_VECTOR_INIT(struct pending_device),
    .leds = SOL_PTR_VECTOR_INIT,
    .sensors = SOL_PTR_VECTOR_INIT,
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

static void bluez_device_appeared(void *data, const char *path);
static void bluez_gatt_service_appeared(void *data, const char *path);
static bool bluez_device_address_property_set(void *data, sd_bus_message *m);
static bool bluez_device_gatt_services_property_set(void *data, sd_bus_message *m);
static bool bluez_service_uuid_property_set(void *data, sd_bus_message *m);
static bool bluez_service_characteristics_property_set(void *data, sd_bus_message *m);

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

static void
bluez_device_property_changed(void *data, const char *path, uint64_t mask)
{
    if (mask & (1 << BLUEZ_DEVICE_ADDRESS_PROPERTY)) {

    }

    if (mask & (1 << BLUEZ_DEVICE_GATT_SERVICES_PROPERTY)) {

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
find_pending_device_by_address(struct context *c, const char *address)
{
    struct pending_device *p;
    uint16_t i;

    SOL_VECTOR_FOREACH_IDX (&c->pending_devices, p, i) {
        if (streq(p->remote, address))
            return p;
    }
    return NULL;
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

static struct led_data *
find_led_by_address(struct context *c, const char *address)
{
    struct led_data *l;
    uint16_t i;

    SOL_PTR_VECTOR_FOREACH_IDX (&c->leds, l, i) {
        if (streq(l->address, address))
            return l;
    }
    return NULL;
}

static struct sensor_data *
find_sensor_by_address(struct context *c, const char *address)
{
    struct sensor_data *s;
    uint16_t i;

    SOL_PTR_VECTOR_FOREACH_IDX (&c->sensors, s, i) {
        if (streq(s->address, address))
            return s;
    }
    return NULL;
}

static bool
bluez_device_address_property_set(void *data, sd_bus_message *m)
{
    struct context *c = data;
    struct pending_device *p;
    struct sensor_data *s;
    struct led_data *l;
    const char *address, *path;
    int r;

    r = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, "s");
    SOL_INT_CHECK_GOTO(r, < 0, error);

    r = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &address);
    SOL_INT_CHECK_GOTO(r, < 0, error);

    SOL_DBG("context %p address %s", c, address);

    s = find_sensor_by_address(c, address);
    l = find_led_by_address(c, address);

    SOL_DBG("led %p sensor %p", l, s);

    if (!l && !s)
        goto error;

    path = sd_bus_message_get_path(m);

    p = find_pending_device_by_path(c, path);

    SOL_DBG("pending %p path %s", p, path);

    if (p)
        goto error;

    sol_vector_init(&p->services, sizeof(struct service));

    p = sol_vector_append(&c->pending_devices);
    SOL_NULL_CHECK_GOTO(p, error);

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
bluez_device_gatt_services_property_set(void *data, sd_bus_message *m)
{
    struct context *c = data;
    struct pending_device *p;
    const char *path;
    int r;

    path = sd_bus_message_get_path(m);

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
bluez_service_uuid_property_set(void *data, sd_bus_message *m)
{
    return false;
}

static bool
bluez_service_characteristics_property_set(void *data, sd_bus_message *m)
{
    return false;
}

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

    led->address = strdup(opts->address);

    SOL_DBG("led %p address %s", led,  led->address);

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
