/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"

#define UNITTESTS_THREAD_COUNT 16

/* Define dummy setup struct that can be used by unittests when needed */
device_info_t *cpu_info = nullptr;

/* Define dummy number of dummy threads */
int thread_count() { return UNITTESTS_THREAD_COUNT; }
int num_cpus() { return thread_count(); }

bool test_is_retry() noexcept { return false; }

