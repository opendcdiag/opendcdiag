/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_TEST_GROUPS_H
#define SANDSTONE_TEST_GROUPS_H

#include "sandstone_config.h"

#ifdef __cplusplus
extern "C" {
#endif

struct test_group;
extern const struct test_group
        group_compression,
        group_math,
        group_fuzzing,
        group_smt;

#if defined(SANDSTONE_DEVICE_CPU) && defined(__x86_64__)
extern const struct test_group
        group_kvm;
#endif

#ifdef __cplusplus
}
#endif

#endif // SANDSTONE_TEST_GROUPS_H
