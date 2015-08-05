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

#include "sol-flow.h"
#include "sol-mainloop.h"
#include "sol-types.h"
#include "sol-util.h"
#include "sol-vector.h"

struct match {
    unsigned int id;
    char *address;
    void (*cb)(const char *path, void *user_data);
    void *user_data;
};

static sol_vector matches = SOL_VECTOR_INIT(struct match);

static sd_bus *system_bus;

static void match_free(struct match *m)
{
    free(m->address);
}

static bool
find_match(const char *address) {
    struct match *m;
    unsigned int i;

    SOL_VECTOR_FOREACH_IDX(&matches, m, i) {
        if (streq(m->address, address))
            return true;
    }

    return false;
}

int
bluez_match_device_by_address(const char* address,
    void (*cb)(const char *path, void *user_data),
    void *user_data)
{
    static unsigned int id;
    struct match *m;

    if (find_match(address))
        return 0;

    m = sol_vector_append(&matches);
    SOL_NULL_CHECK(m, 0);

    m->address = strdup(address);
    SOL_NULL_CHECK_GOTO(m->address, error);

    m->cb = cb;
    m->user_data = user_data;
    m->id = ++id;

    /* The watches were already added */
    if (matches.len > 1)
        return m->id;

    return 0;

error:
    sol_vector_del(&matches, matches.len - 1);
    return 0;
}

void bluez_remove_watch(unsigned int id)
{
    struct match *m;
    unsigned int i;

    SOL_VECTOR_FOREACH_REVERSE_IDX(&matches, m, i) {
        if (m->id == id) {
            match_free(m);
            sol_vector_del(&matches, id);
        }
    }
}
