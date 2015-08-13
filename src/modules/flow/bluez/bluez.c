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

#include "sol-bus.h"
#include "sol-flow.h"
#include "sol-log.h"
#include "sol-mainloop.h"
#include "sol-types.h"
#include "sol-util.h"
#include "sol-vector.h"

#include "bluez.h"

#define BLUEZ_NAME_OWNER_MATCH "sender='org.freedesktop.DBus'," \
	"type='signal',"                                            \
	"interface='org.freedesktop.DBus',"                         \
	"member='NameOwnerChanged',"                                \
	"path='/org/freedesktop/DBus',"                             \
	"arg0='org.bluez'"

#define BLUEZ_INTERFACES_ADDED_MATCH "sender='org.bluez',"  \
	"type='signal',"                                        \
	"interface='org.freedesktop.DBus',"                     \
	"member='InterfacesAdded'"

#define BLUEZ_DEVICE_PROPERTIES_CHANGED_MATCH "sender='org.bluez'," \
	"type='signal',"                                                \
	"interface='org.freedesktop.DBus',"                             \
	"member='PropertiesChanged',"                                   \
    "arg0='org.bluez.Device1'"

struct match {
	char *address;
	void (*cb)(const char *path, void *user_data);
	void *user_data;
	unsigned int id;
};

struct service {
    char *path;
    char *uuid;
};

struct device {
	char *address;
	char *path;
    struct sol_vector services;
    sd_bus_slot *prop_changed;
};

static struct sol_vector matches = SOL_VECTOR_INIT(struct match);
static struct sol_vector devices = SOL_VECTOR_INIT(struct device);

static sd_bus *system_bus;
static sd_bus_slot *name_owner_slot;
static sd_bus_slot *managed_objects_slot;
static sd_bus_slot *interfaces_added_slot;

static bool track_bluez_devices(void);

static int device_properties_changed(sd_bus_message *m, void *userdata,
    sd_bus_error *ret_error);

sd_bus *
bluez_get_bus(void)
{
    if (system_bus)
        return system_bus;

    return system_bus = sol_bus_get(NULL);
}

static void
match_free(struct match *m)
{
	free(m->address);
}

static void
free_service(struct service *s)
{
    free(s->path);
    free(s->uuid);
}

static void
device_free(struct device *d)
{
    struct service *s;
    unsigned int i;

    SOL_VECTOR_FOREACH_IDX (&d->services, s, i) {
        free_service(s);
    }
    sol_vector_clear(&d->services);

	free(d->address);
	free(d->path);
}

static struct match *
find_match(const char *address)
{
	struct match *m;
	unsigned int i;

	SOL_VECTOR_FOREACH_IDX(&matches, m, i) {
		if (streq(m->address, address))
			return m;
	}

	return NULL;
}

static struct device *
find_device(const char *address)
{
	struct device *d;
	unsigned int i;

	SOL_VECTOR_FOREACH_IDX(&devices, d, i) {
		if (streq(d->address, address))
			return d;
	}

	return NULL;
}

static void
stop_tracking_bluez_devices(void)
{
	struct device *d;
	unsigned int i;

	name_owner_slot = sd_bus_slot_unref(name_owner_slot);
	interfaces_added_slot = sd_bus_slot_unref(interfaces_added_slot);
	managed_objects_slot = sd_bus_slot_unref(managed_objects_slot);

	SOL_VECTOR_FOREACH_IDX (&devices, d, i) {
		device_free(d);
	}
	sol_vector_clear(&devices);
}

static int
name_owner_changed(sd_bus_message *m, void *userdata,
    sd_bus_error *ret_error)
{
    const char *name, *old, *new;

	if (sd_bus_message_read(m, "sss", &name, &old, &new) < 0)
		return 0;

	if (!old || !strlen(old)) {
		/* 'org.bluez' appeared. */
		track_bluez_devices();
		return 0;
	}

	if (!new || !strlen(new)) {
		stop_tracking_bluez_devices();
		return 0;
	}

	return 0;
}

static bool
device_add_service(struct device *d, const char *path, const char *uuid)
{
    unsigned int i;
    struct service *s;

    SOL_NULL_CHECK(d, false);
    SOL_NULL_CHECK(path, false);

    SOL_VECTOR_FOREACH_IDX (&d->services, s, i) {
        if (streq(s->path, path)) {
            if (!s->uuid && uuid)
                s->uuid = strdup(uuid);

            return true;
        }
    }

    s = sol_vector_append(&d->services);
    SOL_NULL_CHECK(s, false);

    s->uuid = uuid ? strdup(uuid) : NULL;
    if (uuid && !s->uuid)
        goto error;

    s->path = strdup(path);
    SOL_NULL_CHECK_GOTO(s->path, error);

    return true;

error:
    free(s->path);
    free(s->uuid);

    sol_vector_del(&d->services, d->services.len - 1);

    return false;
}

static void
filter_device_properties(sd_bus_message *m, const char *path)
{
    if (sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{sv}") < 0)
        return;

    do {
        struct device *device;
        struct match *match;
        const char *property;
        const char *value;

        if (sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, "sv") < 0)
            break;

        if (sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &property) < 0)
            return;

        if (streq(property, "Address")) {

            if (sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, "s") < 0)
                return;

            if (sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &value) < 0)
                return;

            device = find_device(value);
            if (!device) {
                device = sol_vector_append(&devices);
                if (!device) {
                    SOL_WRN("Could not allocate 'device'");
                    return;
                }

                device->address = strdup(value);
                if (!device->address) {
                    sol_vector_del(&devices, devices.len - 1);
                    return;
                }

                device->path = strdup(path);
                if (!device->path) {
                    free(device->address);
                    sol_vector_del(&devices, devices.len - 1);
                    return;
                }

                if (sd_bus_add_match(bluez_get_bus(),
                        &device->prop_changed,
                        BLUEZ_DEVICE_PROPERTIES_CHANGED_MATCH,
                        device_properties_changed, device) < 0)
                    return;
            }

            match = find_match(value);
            if (!match)
                continue;

            match->cb(path, match->user_data);
        }

        if (streq(property, "GattServices")) {
            const char *service_path;

            if (!device) {
                SOL_DBG("Got 'GattServices' but no associated device");
                continue;
            }

            if (sd_bus_message_enter_container(m, SD_BUS_TYPE_VARIANT, "ao") < 0)
                continue;

            if (sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "o") < 0)
                continue;

            while (sd_bus_message_read_basic(m, SD_BUS_TYPE_OBJECT_PATH,
                    &service_path) > 0) {
                device_add_service(device, service_path, NULL);
            }
        }

    } while (1);
}

static int
device_properties_changed(sd_bus_message *m, void *userdata,
    sd_bus_error *ret_error)
{
    struct device *d = userdata;

    if (ret_error)
        return -EINVAL;

    filter_device_properties(m, d->path);

    return 0;
}

static void
filter_interfaces(sd_bus_message *m)
{
	const char *path;

	if (sd_bus_message_read(m, "o", &path) < 0)
		return;

	if (sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{sa{sv}}") < 0)
		return;

	do {
		const char *iface;

		if (sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, "sa{sv}") < 0)
			break;

		if (sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &iface) < 0)
			return;

		if (!streq(iface, BLUEZ_DEVICE_IFACE))
			continue;

        filter_device_properties(m, path);

	} while (1);
}

static int
interfaces_added(sd_bus_message *m, void *userdata,
    sd_bus_error *ret_error)
{
	if (ret_error)
		return -EINVAL;

	filter_interfaces(m);

	return 0;
}

static int
managed_objects_reply(sd_bus_message *m, void *userdata,
    sd_bus_error *ret_error)
{
    if (sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{oa{sa{sv}}}") < 0)
        return -EINVAL;

    while (sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY, "oa{sa{sv}}") > 0) {
        filter_interfaces(m);
    }

	return 0;
}

static bool
track_bluez_devices(void)
{
	int r;

	if (!name_owner_slot) {
		r = sd_bus_add_match(bluez_get_bus(), &name_owner_slot, BLUEZ_NAME_OWNER_MATCH,
            name_owner_changed, NULL);
		SOL_INT_CHECK(r, < 0, false);
	}

	if (!interfaces_added_slot) {
		r = sd_bus_add_match(bluez_get_bus(), &name_owner_slot, BLUEZ_INTERFACES_ADDED_MATCH,
            interfaces_added, NULL);
		SOL_INT_CHECK(r, < 0, false);
	}

	if (!managed_objects_slot) {
		sd_bus_message *msg;
		r = sd_bus_message_new_method_call(bluez_get_bus(), &msg,
            "org.bluez",
            "/",
            "org.freedesktop.DBus.ObjectManager",
            "GetManagedObjects");
		SOL_INT_CHECK(r, < 0, false);

		r = sd_bus_call_async(bluez_get_bus(), &managed_objects_slot, msg,
            managed_objects_reply, NULL, 0);
		SOL_INT_CHECK(r, < 0, false);
	}

	return true;
}

int
bluez_match_device_by_address(const char* address,
    void (*cb)(const char *path, void *user_data),
    void *user_data)
{
	static unsigned int id;
	struct match *m;
	struct device *d;
	int r;

	if (find_match(address))
		return 0;

	m = sol_vector_append(&matches);
	SOL_NULL_CHECK(m, 0);

	m->address = strdup(address);
	SOL_NULL_CHECK_GOTO(m->address, error);

	m->cb = cb;
	m->user_data = user_data;
	m->id = ++id;

	d = find_device(address);
	if (d) {
		m->cb(d->path, user_data);
	}

	/* The watches were already added */
	if (matches.len > 1)
		return m->id;

	r = track_bluez_devices();
	SOL_INT_CHECK_GOTO(r, != 0, error);

	return m->id;

error:
	sol_vector_del(&matches, matches.len - 1);
	return 0;
}

void bluez_remove_match(unsigned int id)
{
	struct match *m;
	unsigned int i;

	SOL_VECTOR_FOREACH_REVERSE_IDX(&matches, m, i) {
		if (m->id == id) {
			match_free(m);
			sol_vector_del(&matches, id);
		}
	}

	if (matches.len == 0)
		stop_tracking_bluez_devices();
}
