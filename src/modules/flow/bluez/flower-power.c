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

struct sensor_data {
    char *remote;
};

struct led_data {
    char *remote;
    unsigned int watch;
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

static void
found_device_cb(const char *path, void *user_data)
{
    struct led_data *led = user_data;


}

static int
flower_power_led_open(struct sol_flow_node *node, void *data,
    const struct sol_flow_node_options *options)
{
    struct led_data *led = data;
    struct sol_flow_node_type_bluez_flower_power_sensor_options *opts =
        (struct sol_flow_node_type_bluez_flower_power_sensor_options *) options;

    led->remote = strdup(opts->address);

    led->watch = bluez_match_device_by_address(led->remote, found_device_cb, led);
    if (!led) {
        free(led->remote);
        return -EINVAL;
    }

    return 0;
}

static void
flower_power_led_close(struct sol_flow_node *node, void *data)
{

}

#include "bluez-gen.c"
