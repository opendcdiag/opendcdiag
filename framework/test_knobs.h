/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef FRAMEWORK_TEST_KNOBS_H
#define FRAMEWORK_TEST_KNOBS_H

#include <stdint.h>

#ifdef __cplusplus
#  include <string_view>
#  include <variant>
extern "C" {

#else
#  include <stdbool.h>
#endif

#include "sandstone_config.h"
#if SANDSTONE_RESTRICTED_CMDLINE
#  define get_testspecific_knob_value_uint(test, key, value_if_not_present)    (uint64_t)(value_if_not_present)
#  define get_testspecific_knob_value_int(test, key, value_if_not_present)    (int64_t)(value_if_not_present)
#  define get_testspecific_knob_value_string(test, key, value_if_not_present) (const char*)(value_if_not_present)
#  define set_knob_from_key_value_string(key_value_pair)     ((bool) true)
#else

struct test;

uint64_t get_testspecific_knob_value_uint(const struct test *test, const char *key,
                                          uint64_t value_if_not_present);
int64_t  get_testspecific_knob_value_int(const struct test *test, const char *key,
                                         int64_t value_if_not_present);
const char *get_testspecific_knob_value_string(const struct test *test, const char *key,
                                               const char *value_if_not_present);

// not for tests!
bool set_knob_from_key_value_string(const char *key_value_pair);
#endif // !SANDSTONE_RESTRICTED_CMDLINE

static inline uint64_t get_test_knob_value_uint(const char *key, uint64_t value_if_not_present)
{ return get_testspecific_knob_value_uint(NULL, key, value_if_not_present); }
static inline int64_t  get_test_knob_value_int(const char *key, int64_t value_if_not_present)
{ return get_testspecific_knob_value_int(NULL, key, value_if_not_present); }
static inline const char *get_test_knob_value_string(const char *key, const char *value_if_not_present)
{ return get_testspecific_knob_value_string(NULL, key, value_if_not_present); }


#ifdef __cplusplus
} // extern "C"

// implemented in logging.cpp (or unit test)
enum class KnobOrigin { Options, Defaulted };
using TestKnobValue = std::variant<std::string_view, uint64_t, int64_t>;
void logging_mark_knob_used(std::string_view key, TestKnobValue value, KnobOrigin origin);
#endif

#endif //FRAMEWORK_TEST_KNOBS_H
