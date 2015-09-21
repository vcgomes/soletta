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
#include <stdbool.h>
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

#include "agent.h"

struct device {
    char *path;
    char *address;
    int rssi;
    bool paired;
    uint16_t flags;
};

static struct agent {
    struct sol_bus_client *client;
    struct sol_ptr_vector devices;
    struct sol_timeout *start_pairing;
    struct sol_timeout *cancel_timeout;
    char *discovering_adapter;
    uint16_t nearest_id;
    sd_bus_slot *register_slot;
    sd_bus_slot *request_default_slot;
    sd_bus_slot *start_discovery_slot;
    sd_bus_slot *pair_slot;
    void (*finish)(void *data, bool success, const struct bluez_device *device);
    void *user_data;
    bool default_agent;
} bluez_agent = {
    .nearest_id = UINT16_MAX,
    .devices = SOL_PTR_VECTOR_INIT,
};

#define PAIRING_TIMEOUT 5000
#define CANCEL_TIMEOUT 30000

enum {
    DEVICE_FLAG_HAS_ADDRESS = (1 << 0),
    DEVICE_FLAG_HAS_RSSI = (1 << 1),
    DEVICE_FLAG_HAS_PAIRED = (1 << 2),
    DEVICE_FLAG_HAS_ALL = (DEVICE_FLAG_HAS_ADDRESS | DEVICE_FLAG_HAS_RSSI | DEVICE_FLAG_HAS_PAIRED),
};

enum {
    BLUEZ_DEVICE_INTERFACE,
};

enum {
    BLUEZ_DEVICE_ADDRESS_PROPERTY,
    BLUEZ_DEVICE_RSSI_PROPERTY,
    BLUEZ_DEVICE_PAIRED_PROPERTY,
};

enum {
    BLUEZ_ADAPTER_POWERED_PROPERTY,
};

enum {
    BLUEZ_INTERFACE_ADAPTER,
    BLUEZ_INTERFACE_DEVICE,
};

static const int16_t rssi_threshold = -64;

static const sd_bus_error error_rejected = {
    .name = "org.bluez.Error.Rejected",
    .message = "Not implemented",
};

static bool bluez_device_address_property_set(void *data, const char *path, sd_bus_message *m);
static bool bluez_device_rssi_property_set(void *data, const char *path, sd_bus_message *m);
static bool bluez_device_paired_property_set(void *data, const char *path, sd_bus_message *m);
static void bluez_adapter_interface_appeared(void *data, const char *path);
static bool bluez_adapter_powered_property_set(void *data, const char *path, sd_bus_message *m);
static void bluez_device_interface_appeared(void *data, const char *path);

static const struct sol_bus_properties device_properties[] = {
    [BLUEZ_DEVICE_ADDRESS_PROPERTY] = {
        .member = "Address",
        .set = bluez_device_address_property_set,
    },
    [BLUEZ_DEVICE_RSSI_PROPERTY] = {
        .member = "RSSI",
        .set = bluez_device_rssi_property_set,
    },
    [BLUEZ_DEVICE_PAIRED_PROPERTY] = {
        .member = "Paired",
        .set = bluez_device_paired_property_set,
    },
    { }
};

static const struct sol_bus_properties adapter_properties[] = {
    [BLUEZ_ADAPTER_POWERED_PROPERTY] = {
        .member = "Powered",
        .set = bluez_adapter_powered_property_set,
    },
    { }
};

struct sol_bus_interfaces discovery_interfaces[] = {
    [BLUEZ_INTERFACE_ADAPTER] = {
        .name = "org.bluez.Adapter1",
        .appeared = bluez_adapter_interface_appeared,
    },
    [BLUEZ_INTERFACE_DEVICE] = {
        .name = "org.bluez.Device1",
        .appeared = bluez_device_interface_appeared,
    },
    { },
};

static void
destroy_pairing(struct agent *agent)
{
    struct device *d;
    uint16_t i;

    if (agent->discovering_adapter) {
        sd_bus_call_method_async(sol_bus_client_get_bus(agent->client),
            NULL, sol_bus_client_get_service(agent->client),
            agent->discovering_adapter, "org.bluez.Adapter1", "StopDiscovery",
            sol_bus_log_callback, NULL, NULL);
        free(agent->discovering_adapter);
        agent->discovering_adapter = NULL;
    }

    if (agent->start_pairing) {
        sol_timeout_del(agent->start_pairing);
        agent->start_pairing = NULL;
    }

    if (agent->cancel_timeout) {
        sol_timeout_del(agent->cancel_timeout);
        agent->cancel_timeout = NULL;
    }

    agent->start_discovery_slot = sd_bus_slot_unref(agent->start_discovery_slot);
    agent->pair_slot = sd_bus_slot_unref(agent->pair_slot);

    SOL_PTR_VECTOR_FOREACH_IDX (&agent->devices, d, i) {
        free(d->path);
        free(d->address);
        free(d);
    }
    sol_ptr_vector_clear(&agent->devices);

    sol_bus_remove_interfaces_watch(agent->client, discovery_interfaces, agent);

    agent->finish = NULL;
    agent->user_data = NULL;
}

static int agent_release(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
    return sd_bus_reply_method_return(m, NULL);
}

static int agent_request_pincode(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
    return sd_bus_reply_method_error(m, &error_rejected);
}

static int agent_display_pincode(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
    return sd_bus_reply_method_error(m, &error_rejected);
}

static int agent_request_passkey(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
    return sd_bus_reply_method_error(m, &error_rejected);
}

static int agent_display_passkey(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
    return sd_bus_reply_method_error(m, &error_rejected);
}

static int agent_request_confirmation(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
    return sd_bus_reply_method_error(m, &error_rejected);
}

static int agent_request_authorization(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
    struct agent *agent = userdata;
    struct device *nearest;
    const char *path;
    int r;

    r = sd_bus_message_read_basic(m, SD_BUS_TYPE_OBJECT_PATH, &path);
    SOL_INT_CHECK_GOTO(r, < 0, rejected);

    nearest = sol_ptr_vector_get(&agent->devices, agent->nearest_id);
    SOL_NULL_CHECK_GOTO(nearest, rejected);

    if (streq(nearest->path, path))
        return sd_bus_reply_method_return(m, NULL);

rejected:
    return sd_bus_reply_method_error(m, &error_rejected);
}

static int agent_authorize_service(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
    return sd_bus_reply_method_error(m, &error_rejected);
}

static int agent_cancel(sd_bus_message *m, void *userdata, sd_bus_error *error)
{
    struct agent *agent = userdata;

    if (agent->finish)
        agent->finish(agent->user_data, false, NULL);

    destroy_pairing(agent);

    return sd_bus_reply_method_return(m, NULL);
}

static const sd_bus_vtable agent_vtable[] = {
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("Release", "", "", agent_release,
        SD_BUS_VTABLE_UNPRIVILEGED | SD_BUS_VTABLE_METHOD_NO_REPLY),
    SD_BUS_METHOD("RequestPinCode", "o", "s", agent_request_pincode,
        SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("DisplayPinCode", "os", "", agent_display_pincode,
        SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("RequestPasskey", "o", "u", agent_request_passkey,
        SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("DisplayPasskey", "ouq", "", agent_display_passkey,
        SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("RequestConfirmation", "ou", "", agent_request_confirmation,
        SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("RequestAuthorization", "o", "", agent_request_authorization,
        SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("AuthorizeService", "os", "", agent_authorize_service,
        SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_METHOD("Cancel", "", "", agent_cancel,
        SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_VTABLE_END
};

static struct device *
find_device(const struct agent *agent, const char *path)
{
    struct device *d;
    uint16_t i;

    SOL_PTR_VECTOR_FOREACH_IDX (&agent->devices, d, i) {
        if (streq(d->path, path))
            return d;
    }

    return NULL;
}

static bool
bluez_device_address_property_set(void *data, const char *path, sd_bus_message *m)
{
    struct agent *agent = data;
    struct device *d;
    const char *address;
    int r;

    r = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, "s");
    SOL_INT_CHECK(r, < 0, false);

    r = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &address);
    SOL_INT_CHECK_GOTO(r, < 0, error);

    d = find_device(agent, path);
    if (!d || d->address)
        goto error;

    d->address = strdup(address);
    SOL_NULL_CHECK_GOTO(d->address, error);

    d->flags |= DEVICE_FLAG_HAS_ADDRESS;

    sd_bus_message_exit_container(m);

    return (d->flags & DEVICE_FLAG_HAS_ALL) == DEVICE_FLAG_HAS_ALL;

error:
    sd_bus_message_exit_container(m);

    return false;
}

static bool
bluez_device_rssi_property_set(void *data, const char *path, sd_bus_message *m)
{
    struct agent *agent = data;
    struct device *d;
    int16_t rssi;
    int r;

    r = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, "n");
    SOL_INT_CHECK_GOTO(r, < 0, error);

    r = sd_bus_message_read_basic(m, SD_BUS_TYPE_INT16, &rssi);
    SOL_INT_CHECK_GOTO(r, < 0, error);

    d = find_device(agent, path);
    if (!d)
        goto error;

    d->rssi = rssi;
    d->flags |= DEVICE_FLAG_HAS_RSSI;

    sd_bus_message_exit_container(m);

    return (d->flags & DEVICE_FLAG_HAS_ALL) == DEVICE_FLAG_HAS_ALL;

error:
    sd_bus_message_exit_container(m);

    return false;
}

static bool
bluez_device_paired_property_set(void *data, const char *path, sd_bus_message *m)
{
    struct agent *agent = data;
    struct device *d;
    bool paired;
    int r;

    r = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, "b");
    SOL_INT_CHECK_GOTO(r, < 0, error);

    r = sd_bus_message_read_basic(m, SD_BUS_TYPE_BOOLEAN, &paired);
    SOL_INT_CHECK_GOTO(r, < 0, error);

    d = find_device(agent, path);
    if (!d)
        goto error;

    d->paired = paired;
    d->flags |= DEVICE_FLAG_HAS_PAIRED;

    sd_bus_message_exit_container(m);

    return true;

error:
    sd_bus_message_exit_container(m);

    return false;
}

static int
default_agent_reply_cb(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    struct agent *agent = userdata;

    if (sol_bus_log_callback(m, userdata, ret_error))
        goto error;

    agent->default_agent = true;

    return 0;

error:
    if (agent->finish) {
        agent->finish(agent->user_data, false, NULL);
    }
    destroy_pairing(agent);

    return -EINVAL;
}

static int
register_agent_reply_cb(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    struct agent *agent = userdata;
    struct sol_bus_client *client = agent->client;
    int r;

    if (sol_bus_log_callback(m, userdata, ret_error))
        return -EINVAL;

    r = sd_bus_call_method_async(sol_bus_client_get_bus(client),
        &agent->request_default_slot, sol_bus_client_get_service(client),
        "/org/bluez", "org.bluez.AgentManager1", "RequestDefaultAgent",
        default_agent_reply_cb, agent, "o", "/soletta/agent1");
    SOL_INT_CHECK_GOTO(r, < 0, error);

    return 0;

error:
    sd_bus_message_unref(m);
    return -EINVAL;
}

static int
pair_reply_cb(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    struct agent *agent = userdata;
    struct device *nearest = sol_ptr_vector_get(&agent->devices, agent->nearest_id);
    struct bluez_device d, *result = NULL;

    SOL_NULL_CHECK(nearest, -EINVAL);

    if (sd_bus_message_is_method_error(m, NULL)) {
        const sd_bus_error *error = sd_bus_message_get_error(m);
        SOL_INF("Failed method call: %s: %s", error->name, error->message);
        goto end;
    }

    d.path = nearest->path;
    d.address = nearest->address;

    result = &d;

end:
    if (agent->finish)
        agent->finish(agent->user_data, !!result, result);

    destroy_pairing(agent);

    return sd_bus_reply_method_return(m, NULL);
}

static bool
start_pairing_cb(void *data)
{
    struct agent *agent = data;
    struct sol_bus_client *client = agent->client;
    struct device *nearest;
    int r;

    if (agent->pair_slot) {
        SOL_WRN("Pairing already in progress.");
        goto end;
    }

    if (agent->nearest_id == UINT16_MAX)
        goto end;

    nearest = sol_ptr_vector_get(&agent->devices, agent->nearest_id);

    r = sd_bus_call_method_async(sol_bus_client_get_bus(client),
        &agent->pair_slot, sol_bus_client_get_service(client),
        nearest->path, "org.bluez.Device1", "Pair",
        pair_reply_cb, agent, NULL);
    SOL_INT_CHECK_GOTO(r, < 0, end);

end:
    agent->start_pairing = NULL;
    return false;
}

static void
device_properties_changed(void *data, const char *path, uint64_t mask)
{
    struct agent *agent = data;
    struct device *d, *nearest = NULL;
    int16_t max_rssi = INT16_MIN;
    uint16_t i, nearest_id = UINT16_MAX;

    d = find_device(agent, path);
    if (!d) {
        SOL_WRN("Could not find device for path '%s'.\n", path);
        return;
    }

    SOL_PTR_VECTOR_FOREACH_IDX (&agent->devices, d, i) {
        if ((d->flags & DEVICE_FLAG_HAS_ALL) != DEVICE_FLAG_HAS_ALL)
            continue;

        if (!d->paired && max_rssi < d->rssi && d->rssi > rssi_threshold) {
            nearest = d;
            nearest_id = i;
            max_rssi = d->rssi;
        }
    }

    if (!nearest)
        return;

    if (nearest_id == agent->nearest_id)
        return;

    agent->nearest_id = nearest_id;

    if (agent->start_pairing)
        sol_timeout_del(agent->start_pairing);

    agent->start_pairing = sol_timeout_add(PAIRING_TIMEOUT, start_pairing_cb, agent);
    if (!agent->start_pairing)
        agent->nearest_id = UINT16_MAX;
}

static void bluez_device_interface_appeared(void *data, const char *path)
{
    struct agent *agent = data;
    struct device *d;
    int r;

    d = calloc(1, sizeof(struct device));
    if (!d)
        return;

    d->rssi = INT16_MIN;

    d->path = strdup(path);
    SOL_NULL_CHECK_GOTO(d->path, error_dup);

    r = sol_bus_map_cached_properties(agent->client, path, "org.bluez.Device1",
        device_properties, device_properties_changed, agent);
    SOL_INT_CHECK_GOTO(r, < 0, error_map);

    r = sol_ptr_vector_append(&agent->devices, d);
    SOL_INT_CHECK_GOTO(r, < 0, error_append);

    return;

error_append:
    sol_bus_unmap_cached_properties(agent->client, device_properties, agent);
error_map:
    free(d->path);
error_dup:
    free(d);
}

static int
start_discovery_reply_cb(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    struct agent *agent = userdata;

    if (sol_bus_log_callback(m, userdata, ret_error))
        goto error;

    return 0;

error:
    if (agent->finish) {
        agent->finish(agent->user_data, false, NULL);
    }
    destroy_pairing(agent);

    return -EINVAL;
}

static void
adapter_properties_changed(void *data, const char *path, uint64_t mask)
{
    struct agent *agent = data;

    sd_bus_call_method_async(sol_bus_client_get_bus(agent->client),
        &agent->start_discovery_slot, sol_bus_client_get_service(agent->client),
        path, "org.bluez.Adapter1", "StartDiscovery",
        start_discovery_reply_cb, agent, NULL);
}

static bool
bluez_adapter_powered_property_set(void *data, const char *path, sd_bus_message *m)
{
    struct agent *agent = data;
    bool powered;
    int r;

    r = sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, "b");
    SOL_INT_CHECK(r, < 0, false);

    r = sd_bus_message_read_basic(m, SD_BUS_TYPE_BOOLEAN, &powered);
    SOL_INT_CHECK_GOTO(r, < 0, end);

    if (!powered)
        goto end;

    if (agent->discovering_adapter)
        goto end;

    agent->discovering_adapter = strdup(path);

    r = sd_bus_message_exit_container(m);
    SOL_INT_CHECK_GOTO(r, < 0, end);

    return true;

end:
    sd_bus_message_exit_container(m);
    return false;
}

static void bluez_adapter_interface_appeared(void *data, const char *path)
{
    struct agent *agent = data;

    sol_bus_map_cached_properties(agent->client, path, "org.bluez.Adapter1",
        adapter_properties, adapter_properties_changed, agent);
}

static int
cancel_pairing_reply_cb(sd_bus_message *m, void *userdata, sd_bus_error *ret_error)
{
    struct agent *agent = userdata;

    sol_bus_log_callback(m, userdata, ret_error);

    if (agent->finish) {
        agent->finish(agent->user_data, false, NULL);
    }
    destroy_pairing(agent);

    return 0;
}

static bool
cancel_pairing_cb(void *data)
{
    struct agent *agent = data;
    struct sol_bus_client *client = agent->client;
    struct device *nearest;

    if (agent->nearest_id == UINT16_MAX)
        goto end;

    nearest = sol_ptr_vector_get(&agent->devices, agent->nearest_id);

    sd_bus_call_method_async(sol_bus_client_get_bus(client),
        NULL, sol_bus_client_get_service(client),
        nearest->path, "org.bluez.Device1", "CancelPairing",
        cancel_pairing_reply_cb, agent, NULL);

end:
    agent->cancel_timeout = NULL;
    return false;
}

static void
bluez_connected(void *data, const char *unique)
{
    struct agent *agent = data;
    int r;

    if (!agent->request_default_slot)
        r = sd_bus_call_method_async(sol_bus_client_get_bus(agent->client),
            &agent->request_default_slot, sol_bus_client_get_service(agent->client),
            "/org/bluez", "org.bluez.AgentManager1", "RegisterAgent",
            register_agent_reply_cb, agent, "os", "/soletta/agent1", "NoInputNoOutput");

    if (!agent->finish)
        return;

    r = sol_bus_watch_interfaces(agent->client, discovery_interfaces, agent);
    if (!r)
        return;

    agent->cancel_timeout = sol_timeout_add(CANCEL_TIMEOUT, cancel_pairing_cb, agent);
}

int
bluez_register_default_agent(void)
{
    int r;

    bluez_agent.client = sol_bus_client_new(sol_bus_get(NULL), "org.bluez");
    SOL_NULL_CHECK(bluez_agent.client, -ENOMEM);

    r = sd_bus_add_object_vtable(sol_bus_client_get_bus(bluez_agent.client),
        &bluez_agent.register_slot,
        "/soletta/agent1", "org.bluez.Agent1", agent_vtable, &bluez_agent);
    SOL_INT_CHECK_GOTO(r, < 0, error_table);

    if (sol_bus_client_set_connect_handler(bluez_agent.client,
            bluez_connected, &bluez_agent) < 0)
        return -EINVAL;

    return 0;

error_table:
    sol_bus_client_free(bluez_agent.client);

    return -EINVAL;
}

int bluez_start_simple_pair(
    void (*finish)(void *data, bool success, const struct bluez_device *device), void *user_data)
{
    SOL_NULL_CHECK(bluez_agent.client, -EINVAL);

    if (bluez_agent.finish)
        return -EALREADY;

    bluez_agent.finish = finish;
    bluez_agent.user_data = user_data;

    if (sol_bus_client_set_connect_handler(bluez_agent.client,
            bluez_connected, &bluez_agent) < 0)
        return -EINVAL;

    return 0;
}
