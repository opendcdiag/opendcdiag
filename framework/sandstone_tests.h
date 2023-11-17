/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_SANDSTONE_TESTS_H
#define INC_SANDSTONE_TESTS_H

#include <stddef.h>
#include "sandstone.h"

#ifdef __cplusplus
#include <span>

extern "C" {
#endif

struct testrun_info
{
    struct test *test;
    int duration_ms;
};

struct weighted_run_info
{
    struct test *test;
    int weight;
    int duration_ms;

    // populated at runtime
    unsigned int test_index;
};

extern struct test __start_tests;
extern struct test __stop_tests;

#ifdef __cplusplus

enum WeightedTestLength : int8_t {
    ShortenedTestrunTimes,
    NormalTestrunTimes,
    LongerTestrunTimes,
};

enum WeightedTestScheme : int8_t {
    Repeating,
    NonRepeating,
    Prioritized,
    Alphabetical,
    Ordered,
};

__attribute__((weak)) extern const struct test_group __start_test_group;
__attribute__((weak)) extern const struct test_group __stop_test_group;

inline std::span<struct test> regular_tests = { &__start_tests, &__stop_tests };
extern const std::span<struct test> selftests;

struct TestList {
    uint64_t features;
    const char* name;
    const std::span<struct test* const> content;
};

}
#endif

#endif /* INC_SANDSTONE_TESTS_H */
