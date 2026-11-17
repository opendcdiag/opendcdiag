/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SELFTEST_P_H
#define SELFTEST_P_H

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
