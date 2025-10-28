/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"

#define UNITTESTS_NUM_CPUS 16

/* Define dummy setup struct that can be used by unittests when needed */
device_info_t *cpu_info = nullptr;

/* Define dummy number of dummy cpus */
int num_cpus() { return UNITTESTS_NUM_CPUS; }

bool test_is_retry() noexcept { return false; }

