/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SELFTEST_P_H
#define SELFTEST_P_H

#include <sandstone.h>

/// Same as DECLARE_TEST_SECTION, but places the test in the "selftests"
/// section instead of "tests": only reachable when --selftests option is used.
/// May be used by device-specific applications to implement custom self-tests
/// which tie into the framework's existing self-test capabilities.
/// Before the self-tests get assigned a proper short id, we need to sort them
/// because the compiler may reorder them, depending on selected optimization
/// options. We're using __COUNTER__ to assign monotonic pseudo short-ids to the
/// selftests, so that the framework can execute them in the order in which they
/// are created.
#define DECLARE_SELFTEST_SECTION(test_id) \
    extern const char SANDSTONE_CONCAT(_testid_, test_id); \
    __attribute__((used)) const char SANDSTONE_CONCAT(_testid_, test_id) = 0; \
    __attribute__((aligned(alignof(struct test)), used, section(SANDSTONE_SECTION_PREFIX "selftests")))

#define DECLARE_SELFTEST(test_id, test_description)                    \
    DECLARE_SELFTEST_SECTION(test_id)                                  \
    DECLARE_SELFTEST_INNER(test_id, __COUNTER__, test_description)

#define DECLARE_SELFTEST_INNER(test_id, test_order, test_description)  \
    DECLARE_TEST_STRUCT(test_id, test_id, test_order, test_description)

struct test_group;

extern const struct test_group group_positive;
extern const struct test_group group_selftest_passes;
extern const struct test_group group_init_skip;
extern const struct test_group group_fail_test_the_test;
extern const struct test_group group_negative;
extern const struct test_group group_random;
extern const struct test_group group_test_is_optional;
extern const struct test_group group_test_hw_features;

#endif // SELFTEST_P_H
