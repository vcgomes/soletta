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

#include <ctype.h>
#include <float.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "sol-flow-internal.h"
#include "sol-str-slice.h"
#include "sol-util.h"

#ifdef SOL_FLOW_NODE_TYPE_DESCRIPTION_ENABLED

static const char SUBOPTION_SEPARATOR = '|';

static void *
get_member_memory(const struct sol_flow_node_options_member_description *member, struct sol_flow_node_options *opts)
{
    return (uint8_t *)opts + member->offset;
}

#define STRTOL_DECIMAL(_ptr, _endptr) strtol(_ptr, _endptr, 0)

#define KEY_VALUES_RECAP(_max_val, _min_val)    \
    do {                                        \
        if (keys_schema) {                      \
            if (!min_done) ret->min = _min_val; \
            if (!max_done) ret->max = _max_val; \
            if (!step_done) ret->step = 1;      \
            if (!val_done) ret->val = 0;        \
        }                                       \
    } while (0)                                 \

#define LINEAR_VALUES_RECAP(_max_val, _min_val) \
    do {                                        \
        switch (field_cnt) {                    \
        case 1:                                 \
            ret->min = _min_val;                \
        case 2:                                 \
            ret->max = _max_val;                \
        case 3:                                 \
            ret->step = 1;                      \
        default:                                \
            break;                              \
        }                                       \
    } while (0)                                 \

#define ASSIGN_LINEAR_VALUES(_parse_func, \
                             _max_val, _max_str, _max_str_len,          \
                             _min_val, _min_str, _min_str_len)          \
    do {                                                                \
        char *start, *end, backup;                                      \
        int field_cnt_max = ARRAY_SIZE(store_vals); \
        if (keys_schema) continue;                                      \
        start = buf;                                                    \
        end = strchr(start, SUBOPTION_SEPARATOR);                       \
        if (!end) end = start + strlen(start);                          \
        backup = *end;                                                  \
        *end = '\0';                                                    \
        for (field_cnt = 0; field_cnt < field_cnt_max;) { \
            bool is_max = false, is_min = false;                        \
            errno = 0;                                                  \
            if (strlen(start) >= _max_str_len                           \
                && (strncmp(start, _max_str,                            \
                        _max_str_len) == 0)) {                      \
                is_max = true;                                          \
            } else if (strlen(start) >= _min_str_len                    \
                       && (strncmp(start, _min_str,                     \
                               _min_str_len) == 0)) {               \
                is_min = true;                                          \
            }                                                           \
            if (is_max) *store_vals[field_cnt] = _max_val;              \
            else if (is_min) *store_vals[field_cnt] = _min_val;         \
            else { \
                char *endptr; \
                *store_vals[field_cnt] = _parse_func(start, &endptr); \
                /* check if no number was parsed, indicates invalid string */ \
                if (start == endptr) \
                    goto err; \
            } \
            if (errno != 0) goto err;                                   \
            field_cnt++;                                                \
            *end = backup;                                              \
            if (backup == '\0') break;                                  \
            start = end + 1;                                            \
            if (!start) break;                                          \
            end = strchr(start, SUBOPTION_SEPARATOR);                   \
            if (!end) end = start + strlen(start);                      \
            backup = *end;                                              \
            *end = '\0';                                                \
        }                                                               \
    } while (0)

#define ASSIGN_KEY_VAL(_type, _key, _parse_func, _only_not_negative, \
                       _max_val, _max_str, _max_str_len,        \
                       _min_val, _min_str, _min_str_len)        \
    do {                                                        \
        bool is_max = false, is_min = false;                    \
        _key = strstr(buf, #_key);                              \
        if (_key) {                                             \
            keys_schema = true;                                 \
            _key = strchr(_key, ':');                           \
        } else continue;                                        \
        if (_key && _key[0] && _key[1]) {                       \
            _key++;                                             \
            while (_key && isspace(*_key)) _key++;              \
        } else goto err;                                        \
        if (!_key)                                              \
            continue;                                           \
        if (strlen(_key) >= _max_str_len                        \
            && (strncmp(_key, _max_str,                         \
                    _max_str_len) == 0)) {                  \
            is_max = true;                                      \
        } else if (strlen(_key) >= _min_str_len                 \
                   && (strncmp(_key, _min_str,                  \
                           _min_str_len) == 0)) {           \
            is_min = true;                                      \
        }                                                       \
        if (is_max)                                             \
            ret->_key = _max_val;                               \
        else if (is_min) { \
            if (_only_not_negative) \
                goto err; \
            ret->_key = _min_val;                               \
        } else { \
            char *_key ## _end = _key;                          \
            char _key ## _backup;                               \
            char *endptr; \
            _type parsed_val; \
            while (_key ## _end                                 \
                   && *_key ## _end != '\0'                     \
                   && *_key ## _end != SUBOPTION_SEPARATOR)     \
                _key ## _end++;                                 \
            if (_key ## _end) {                                 \
                _key ## _backup = *_key ## _end;                \
                *_key ## _end = '\0';                           \
            }                                                   \
            errno = 0;                                          \
            parsed_val = _parse_func(_key, &endptr); \
            if (_key == endptr) \
                goto err; \
            if (errno != 0)                                     \
                goto err;                                       \
            if (_only_not_negative) { \
                if (parsed_val < 0) \
                    goto err; \
            } \
            ret->_key = parsed_val; \
            _key ## _done = true;                               \
            if (_key ## _end)                                   \
                *_key ## _end = _key ## _backup;                \
        }                                                       \
    } while (0)

static int
irange_parse(const struct sol_flow_node_options_member_description *member,
    const char *value,
    struct sol_irange *ret)
{
    char *buf;
    int field_cnt = 0;
    bool keys_schema = false;
    char *min, *max, *step, *val;
    bool min_done = false, max_done = false,
         step_done = false, val_done = false;
    static const char INT_MAX_STR[] = "INT32_MAX";
    static const char INT_MIN_STR[] = "INT32_MIN";
    static const size_t INT_LIMIT_STR_LEN = sizeof(INT_MAX_STR) - 1;
    int32_t *store_vals[] = { &ret->val, &ret->min, &ret->max, &ret->step };

    buf = strdup(value);

    ASSIGN_KEY_VAL(int32_t, min, STRTOL_DECIMAL, false,
        INT32_MAX, INT_MAX_STR, INT_LIMIT_STR_LEN,
        INT32_MIN, INT_MIN_STR, INT_LIMIT_STR_LEN);
    ASSIGN_KEY_VAL(int32_t, max, STRTOL_DECIMAL, false,
        INT32_MAX, INT_MAX_STR, INT_LIMIT_STR_LEN,
        INT32_MIN, INT_MIN_STR, INT_LIMIT_STR_LEN);
    ASSIGN_KEY_VAL(int32_t, step, STRTOL_DECIMAL, false,
        INT32_MAX, INT_MAX_STR, INT_LIMIT_STR_LEN,
        INT32_MIN, INT_MIN_STR, INT_LIMIT_STR_LEN);
    ASSIGN_KEY_VAL(int32_t, val, STRTOL_DECIMAL, false,
        INT32_MAX, INT_MAX_STR, INT_LIMIT_STR_LEN,
        INT32_MIN, INT_MIN_STR, INT_LIMIT_STR_LEN);

    KEY_VALUES_RECAP(INT32_MAX, INT32_MIN);

    ASSIGN_LINEAR_VALUES(STRTOL_DECIMAL,
        INT32_MAX, INT_MAX_STR, INT_LIMIT_STR_LEN,
        INT32_MIN, INT_MIN_STR, INT_LIMIT_STR_LEN);

    LINEAR_VALUES_RECAP(INT32_MAX, INT32_MIN);

    SOL_DBG("irange opt ends up as min=%d, max=%d, step=%d, val=%d\n",
        ret->min, ret->max, ret->step, ret->val);

    free(buf);
    return 0;

err:
    SOL_DBG("Invalid irange value for option name=\"%s\": \"%s\"."
        " Please use the formats"
        " \"<val_value>|<min_value>|<max_value>|<step_value>\","
        " in that order, or \"<key>:<value>|<...>\", for keys in "
        "[val, min, max, step], in any order. Values may be the "
        "special strings INT32_MAX and INT32_MIN.",
        member->name, value);
    free(buf);
    return -EINVAL;
}

static int
drange_parse(const struct sol_flow_node_options_member_description *member,
    const char *value,
    struct sol_drange *ret)
{
    char *buf;
    int field_cnt = 0;
    bool keys_schema = false;
    char *min, *max, *step, *val;
    bool min_done = false, max_done = false,
         step_done = false, val_done = false;
    static const char DBL_MAX_STR[] = "DBL_MAX";
    static const char DBL_MIN_STR[] = "-DBL_MAX";
    static const size_t DBL_MAX_STR_LEN = sizeof(DBL_MAX_STR) - 1;
    static const size_t DBL_MIN_STR_LEN = sizeof(DBL_MIN_STR) - 1;
    double *store_vals[] = { &ret->val, &ret->min, &ret->max, &ret->step };

    buf = strdup(value);

    ASSIGN_KEY_VAL(double, min, strtod, false,
        DBL_MAX, DBL_MAX_STR, DBL_MAX_STR_LEN,
        -DBL_MAX, DBL_MIN_STR, DBL_MIN_STR_LEN);
    ASSIGN_KEY_VAL(double, max, strtod, false,
        DBL_MAX, DBL_MAX_STR, DBL_MAX_STR_LEN,
        -DBL_MAX, DBL_MIN_STR, DBL_MIN_STR_LEN);
    ASSIGN_KEY_VAL(double, step, strtod, false,
        DBL_MAX, DBL_MAX_STR, DBL_MAX_STR_LEN,
        -DBL_MAX, DBL_MIN_STR, DBL_MIN_STR_LEN);
    ASSIGN_KEY_VAL(double, val, strtod, false,
        DBL_MAX, DBL_MAX_STR, DBL_MAX_STR_LEN,
        -DBL_MAX, DBL_MIN_STR, DBL_MIN_STR_LEN);

    KEY_VALUES_RECAP(DBL_MAX, -DBL_MAX);

    ASSIGN_LINEAR_VALUES(strtod,
        DBL_MAX, DBL_MAX_STR, DBL_MAX_STR_LEN,
        -DBL_MAX, DBL_MIN_STR, DBL_MIN_STR_LEN);

    LINEAR_VALUES_RECAP(DBL_MAX, -DBL_MAX);

    SOL_DBG("drange opt ends up as min=%lf, max=%lf, step=%lf, val=%lf\n",
        ret->min, ret->max, ret->step, ret->val);

    free(buf);
    return 0;

err:
    SOL_DBG("Invalid drange value for option name=\"%s\": \"%s\"."
        " Please use the formats"
        " \"<val_value>|<min_value>|<max_value>|<step_value>\","
        " in that order, or \"<key>:<value>|<...>\", for keys in "
        "[val, min, max, step], in any order. Values may be the "
        "special strings DBL_MAX and -DBL_MAX. Don't use commas "
        "on the numbers",
        member->name, value);
    free(buf);
    return -EINVAL;
}

static int
rgb_parse(const struct sol_flow_node_options_member_description *member,
    const char *value, struct sol_rgb *ret)
{
    char *buf;
    int field_cnt = 0;
    bool keys_schema = false;
    char *red, *green, *blue, *red_max, *green_max, *blue_max;
    bool red_done = false, green_done = false, blue_done = false,
         red_max_done = false, green_max_done = false, blue_max_done = false;
    static const char INT_MAX_STR[] = "INT32_MAX";
    static const char INT_MIN_STR[] = "INT32_MIN";
    static const size_t INT_LIMIT_STR_LEN = sizeof(INT_MAX_STR) - 1;
    uint32_t *store_vals[] = { &ret->red, &ret->green, &ret->blue,
                               &ret->red_max, &ret->green_max, &ret->blue_max };

    buf = strdup(value);

    ASSIGN_KEY_VAL(int32_t, red, STRTOL_DECIMAL, true,
        INT32_MAX, INT_MAX_STR, INT_LIMIT_STR_LEN,
        INT32_MIN, INT_MIN_STR, INT_LIMIT_STR_LEN);
    ASSIGN_KEY_VAL(int32_t, green, STRTOL_DECIMAL, true,
        INT32_MAX, INT_MAX_STR, INT_LIMIT_STR_LEN,
        INT32_MIN, INT_MIN_STR, INT_LIMIT_STR_LEN);
    ASSIGN_KEY_VAL(int32_t, blue, STRTOL_DECIMAL, true,
        INT32_MAX, INT_MAX_STR, INT_LIMIT_STR_LEN,
        INT32_MIN, INT_MIN_STR, INT_LIMIT_STR_LEN);
    ASSIGN_KEY_VAL(int32_t, red_max, STRTOL_DECIMAL, true,
        INT32_MAX, INT_MAX_STR, INT_LIMIT_STR_LEN,
        INT32_MIN, INT_MIN_STR, INT_LIMIT_STR_LEN);
    ASSIGN_KEY_VAL(int32_t, green_max, STRTOL_DECIMAL, true,
        INT32_MAX, INT_MAX_STR, INT_LIMIT_STR_LEN,
        INT32_MIN, INT_MIN_STR, INT_LIMIT_STR_LEN);
    ASSIGN_KEY_VAL(int32_t, blue_max, STRTOL_DECIMAL, true,
        INT32_MAX, INT_MAX_STR, INT_LIMIT_STR_LEN,
        INT32_MIN, INT_MIN_STR, INT_LIMIT_STR_LEN);

    if (keys_schema) {
        if (!red_done) ret->red = 0;
        if (!red_max_done) ret->red_max = 255;
        if (!green_done) ret->green = 0;
        if (!green_max_done) ret->green_max = 255;
        if (!blue_done) ret->blue = 0;
        if (!blue_max_done) ret->blue_max = 255;
    }

    ASSIGN_LINEAR_VALUES(STRTOL_DECIMAL,
        INT32_MAX, INT_MAX_STR, INT_LIMIT_STR_LEN,
        INT32_MIN, INT_MIN_STR, INT_LIMIT_STR_LEN);

    /* field_cnt shouldn't start from 0 in switch,
     * since if no value was declared, it doesn't make
     * sense to declare the option. Also, if values were
     * assigned by ASSIGN_KEY_VAL field_cnt would stay 0, and the whole
     * option would be set to default values */
    switch (field_cnt) {
    case 1:
        ret->green = 0;
    case 2:
        ret->blue = 0;
    case 3:
        ret->red_max = 255;
    case 4:
        ret->green_max = 255;
    case 5:
        ret->blue_max = 255;
    default:
        break;
    }

    SOL_DBG("rgb opt ends up as red=%d, green=%d, blue=%d "
        "red_max=%d, green_max=%d, blue_max=%d\n",
        ret->red, ret->green, ret->blue,
        ret->red_max, ret->green_max, ret->blue_max);

    free(buf);
    return 0;

err:
    SOL_DBG("Invalid rgb value for option name=\"%s\": \"%s\"."
        " Please use the formats"
        " \"<red_value>|<green_value>|<blue_value>|"
        "<red_max_value>|<green_max_value>|<blue_max_value>\","
        " in that order, or \"<key>:<value>|<...>\", for keys in "
        "[red, green, blue, red_max, green_max, blue_max], in any order. "
        "Values may be the special strings INT32_MAX. All of them must be "
        "not negative int values.",
        member->name, value);
    free(buf);
    return -EINVAL;
}


#undef STRTOL_DECIMAL
#undef KEY_VALUES_RECAP
#undef LINEAR_VALUES_RECAP
#undef ASSIGN_LINEAR_VALUES
#undef ASSIGN_KEY_VAL

static int
member_parse(const struct sol_flow_node_options_description *desc, const struct sol_flow_node_options_member_description *member, struct sol_flow_node_options *opts, const char *str, uint16_t value_start)
{
    const char *t = member->data_type;
    const char *value = str + value_start;
    void *mem = get_member_memory(member, opts);

    if (streq(t, "string")) {
        char **s = mem;
        free(*s);
        *s = strdup(value);
    } else if (streq(t, "boolean")) {
        bool *b = mem;
        if (streq(value, "1") || streq(value, "true") || streq(value, "on") || streq(value, "yes"))
            *b = true;
        else if (streq(value, "0") || streq(value, "false") || streq(value, "off") || streq(value, "no"))
            *b = false;
        else {
            SOL_DBG("Invalid boolean value for option name=\"%s\": \"%s\"",
                member->name, value);
            return -EINVAL;
        }
    } else if (streq(t, "byte")) {
        unsigned char *byte = mem;
        int i;
        errno = 0;
        i = strtol(value, NULL, 0);
        if ((errno != 0) || (i < 0) || (i > 255)) {
            SOL_DBG("Invalid byte value for option name=\"%s\": \"%s\"",
                member->name, value);
            return -errno;
        }
        *byte = i;
    } else if (streq(t, "int")) {
        struct sol_irange *i = mem;
        int r = irange_parse(member, value, i);
        SOL_INT_CHECK(r, < 0, r);
    } else if (streq(t, "float")) {
        struct sol_drange *f = mem;
        int r = drange_parse(member, value, f);
        SOL_INT_CHECK(r, < 0, r);
    } else if (streq(t, "rgb")) {
        struct sol_rgb *rgb = mem;
        int r = rgb_parse(member, value, rgb);
        SOL_INT_CHECK(r, < 0, r);
    } else {
        SOL_WRN("Unsupported member parse #%u "
            "name=\"%s\", type=\"%s\", offset=%hu, size=%hu",
            (unsigned)(member - desc->members), member->name,
            member->data_type, member->offset, member->size);
    }

    return 0;
}

static const struct sol_flow_node_options_member_description *
find_member(const struct sol_flow_node_options_description *desc, const struct sol_str_slice name)
{
    const struct sol_flow_node_options_member_description *m;

    for (m = desc->members; m->name != NULL; m++) {
        if (sol_str_slice_str_eq(name, m->name))
            return m;
    }

    return NULL;
}

static int
split_option(const char *input, const char **key, unsigned int *key_len, const char **value)
{
    const char *equal = strchr(input, '=');

    if (!equal || equal == input || equal + 1 == '\0')
        return -EINVAL;

    *key = input;
    *key_len = equal - input;
    *value = equal + 1;
    return 0;
}

static bool
options_from_strv(const struct sol_flow_node_options_description *desc, struct sol_flow_node_options *opts, const char *const *strv)
{
    const struct sol_flow_node_options_member_description *m;
    const char *const *entry;
    uint16_t count;
    bool *handled_member = NULL;
    bool success = false, has_required = false;

    count = 0;
    for (m = desc->members; m->name != NULL; m++) {
        count++;
        has_required |= m->required;
    }

    if (has_required) {
        handled_member = calloc(count, sizeof(bool));
        SOL_NULL_CHECK(handled_member, false);
    }

    for (entry = strv; entry && *entry != NULL; entry++) {
        const char *key, *value;
        unsigned int key_len;
        int r;

        if (split_option(*entry, &key, &key_len, &value)) {
            SOL_DBG("Invalid option #%u format: \"%s\"", (unsigned)(entry - strv), *entry);
            goto end;
        }

        m = find_member(desc, SOL_STR_SLICE_STR(key, key_len));
        if (!m) {
            SOL_DBG("Unknown option: \"%s\"", *entry);
            goto end;
        }

        r = member_parse(desc, m, opts, *entry, value - *entry);
        if (r < 0) {
            SOL_DBG("Could not parse member #%u "
                "name=\"%s\", type=\"%s\", option=\"%s\": %s",
                (unsigned)(m - desc->members), m->name,
                m->data_type, *entry, sol_util_strerrora(-r));
            goto end;
        }

        if (has_required)
            handled_member[m - desc->members] = true;

        SOL_DBG("Parsed option \"%s\" member #%u "
            "name=\"%s\", type=\"%s\", offset=%hu, size=%hu",
            *entry, (unsigned)(m - desc->members), m->name,
            m->data_type, m->offset, m->size);
    }

    if (has_required) {
        for (m = desc->members; m->name != NULL; m++) {
            if (m->required && !handled_member[m - desc->members]) {
                SOL_DBG("Required member not in options: "
                    "name=\"%s\", type=\"%s\"", m->name, m->data_type);
                goto end;
            }
        }
    }

    success = true;

end:
    free(handled_member);
    return success;
}
#endif

SOL_API struct sol_flow_node_options *
sol_flow_node_options_new_from_strv(const struct sol_flow_node_type *type, const char *const *strv)
{
    struct sol_flow_node_options *opts;

    SOL_NULL_CHECK(type, NULL);
    SOL_FLOW_NODE_TYPE_API_CHECK(type, SOL_FLOW_NODE_TYPE_API_VERSION, NULL);
#ifndef SOL_FLOW_NODE_TYPE_DESCRIPTION_ENABLED
    SOL_WRN("does not work if compiled with --disable-flow-node-type-description");
    return NULL;
    (void)opts;
#else
    if (type->init_type)
        type->init_type();
    SOL_NULL_CHECK(type->description, NULL);
    SOL_NULL_CHECK(type->description->options, NULL);
    SOL_NULL_CHECK(type->description->options->members, NULL);
    SOL_NULL_CHECK(type->new_options, NULL);
    opts = type->new_options(NULL);
    SOL_NULL_CHECK(opts, NULL);
    if (!options_from_strv(type->description->options, opts, strv)) {
        type->free_options(opts);
        return NULL;
    }
    return opts;
#endif
}

SOL_API struct sol_flow_node_options *
sol_flow_node_options_copy(const struct sol_flow_node_type *type, const struct sol_flow_node_options *opts)
{
    SOL_FLOW_NODE_TYPE_API_CHECK(type, SOL_FLOW_NODE_TYPE_API_VERSION, NULL);
    SOL_FLOW_NODE_OPTIONS_API_CHECK(type, SOL_FLOW_NODE_OPTIONS_API_VERSION, NULL);

#ifndef SOL_FLOW_NODE_TYPE_DESCRIPTION_ENABLED
    SOL_WRN("does not work if compiled with --disable-flow-node-type-description");
    return NULL;
#else
    SOL_NULL_CHECK(type->description, NULL);
    SOL_NULL_CHECK(type->description->options, NULL);
    SOL_NULL_CHECK(type->description->options->members, NULL);
    SOL_NULL_CHECK(type->new_options, NULL);
    return type->new_options(opts);
#endif
}

SOL_API int
sol_flow_node_options_merge_from_strv(const struct sol_flow_node_type *type,
    struct sol_flow_node_options *opts, const char *const *strv)
{
    SOL_FLOW_NODE_TYPE_API_CHECK(type, SOL_FLOW_NODE_TYPE_API_VERSION, -EINVAL);
    SOL_FLOW_NODE_OPTIONS_API_CHECK(type, SOL_FLOW_NODE_OPTIONS_API_VERSION, -EINVAL);
    SOL_NULL_CHECK(strv, -EINVAL);

#ifndef SOL_FLOW_NODE_TYPE_DESCRIPTION_ENABLED
    SOL_WRN("does not work if compiled with --disable-flow-node-type-description");
    return -ENOTSUP;
#else
    SOL_NULL_CHECK(type->description, -EINVAL);
    SOL_NULL_CHECK(type->description->options, -EINVAL);
    SOL_NULL_CHECK(type->description->options->members, -EINVAL);
    if (!options_from_strv(type->description->options, opts, strv))
        return -EINVAL;
    return 0;
#endif
}

SOL_API void
sol_flow_node_options_del(const struct sol_flow_node_type *type, struct sol_flow_node_options *options)
{
    SOL_NULL_CHECK(type);
    SOL_FLOW_NODE_OPTIONS_API_CHECK(options, SOL_FLOW_NODE_OPTIONS_API_VERSION);
#ifndef SOL_FLOW_NODE_TYPE_DESCRIPTION_ENABLED
    SOL_WRN("does not work if compiled with --disable-flow-node-type-description");
#else
    SOL_NULL_CHECK(type->description);
    SOL_NULL_CHECK(type->description->options);
    SOL_NULL_CHECK(type->description->options->members);
    SOL_NULL_CHECK(type->free_options);
    SOL_FLOW_NODE_OPTIONS_SUB_API_CHECK(options, type->description->options->sub_api);
    type->free_options(options);
#endif
}

SOL_API void
sol_flow_node_options_strv_del(char **opts_strv)
{
    char **opts_it;

    if (!opts_strv)
        return;
    for (opts_it = opts_strv; *opts_it != NULL; opts_it++)
        free(*opts_it);
    free(opts_strv);
}
