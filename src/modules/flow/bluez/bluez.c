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

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <systemd/sd-bus.h>
#include <systemd/sd-bus-vtable.h>

#include "sol-bus.h"
#include "sol-flow.h"
#include "sol-log.h"
#include "sol-mainloop.h"
#include "sol-types.h"
#include "sol-util.h"

#include "bluez.h"

static struct agent {
    struct sol_bus_client *client;
    sd_bus_slot *register_slot;
    sd_bus_slot *request_default_slot;
} bluez_agent;

static sd_bus *agent_bus;
struct sol_bus_client *bluez_client;

static int agent_release(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
    return -ENOSYS;
}

static int agent_request_pincode(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
    return -ENOSYS;
}

static int agent_display_pincode(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
    return -ENOSYS;
}

static int agent_request_passkey(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
    return -ENOSYS;
}

static int agent_display_passkey(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
    return -ENOSYS;
}

static int agent_request_confirmation(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
    return -ENOSYS;
}

static int agent_request_authorization(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
    return -ENOSYS;
}

static int agent_authorize_service(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
    return -ENOSYS;
}

static int agent_cancel(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
    return -ENOSYS;
}

sd_bus_vtable agent_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("Release", NULL, NULL, agent_release,
        SD_BUS_VTABLE_UNPRIVILEGED | SD_BUS_VTABLE_METHOD_NO_REPLY),
    SD_BUS_METHOD("RequestPinCode", "o", "s", agent_request_pincode,
        SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("DisplayPinCode", "os", NULL, agent_display_pincode,
        SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("RequestPasskey", "o", "u", agent_request_passkey,
        SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("DisplayPasskey", "ouq", NULL, agent_display_passkey,
        SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("RequestConfirmation", "ou", NULL, agent_request_confirmation,
        SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("RequestAuthorization", "o", NULL, agent_request_authorization,
        SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("AuthorizeService", "os", NULL, agent_authorize_service,
        SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("Cancel", NULL, NULL, agent_cancel,
        SD_BUS_VTABLE_UNPRIVILEGED)
};

static int
register_agent_reply_cb(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    return -ENOSYS;
}

int
bluez_register_default_agent(void)
{
    sd_bus_message *m;
    int r;

    if (!agent_bus) {
        r = sd_bus_default(&agent_bus);
        SOL_INT_CHECK(r, < 0, -ENOMEM);
    }

    r = sd_bus_add_object_vtable(agent_bus, &bluez_agent.register_slot,
        "/soletta/agent1", "org.bluez.Agent1", agent_vtable, &bluez_agent);

    bluez_client = sol_bus_client_new(sol_bus_get(NULL), "org.bluez");
    SOL_NULL_CHECK_GOTO(bluez_client, error_client);

    bluez_agent.client = bluez_client;

    r = sd_bus_message_new_method_call(sol_bus_client_get_bus(bluez_agent.client), &m,
        sol_bus_client_get_service(bluez_agent.client),
        "/org/bluez", "org.bluez.AgentManager1", "RegisterAgent");
    SOL_INT_CHECK_GOTO(r, < 0, error_new_call);

    r = sd_bus_message_append(m, "os", "/soletta/agent1", "NoInputNoOutput");
    SOL_INT_CHECK_GOTO(r, < 0, error_append);

    r = sd_bus_call_async(sol_bus_client_get_bus(bluez_agent.client),
        &bluez_agent.register_slot, m, register_agent_reply_cb, &bluez_agent, 0);
    SOL_INT_CHECK_GOTO(r, < 0, error_call);



    return 0;

error_call:
error_append:
    sd_bus_message_unref(m);

error_new_call:
    sol_bus_client_free(bluez_agent.client);

error_client:
    sd_bus_slot_unref(bluez_agent.register_slot);

    return -EINVAL;
}
