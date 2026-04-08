/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"

#define UNITTESTS_THREAD_COUNT 16
#define UNITTESTS_DEVICE_COUNT UNITTESTS_THREAD_COUNT

/* Define dummy setup struct that can be used by unittests when needed */
device_info_t *device_info = nullptr;

/* Define dummy number of dummy threads */
int device_count() { return UNITTESTS_DEVICE_COUNT; }
int thread_count() { return UNITTESTS_THREAD_COUNT; }
int num_cpus() { return thread_count(); }

bool test_is_retry() noexcept { return false; }

