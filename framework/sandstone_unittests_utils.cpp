/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_unittests_utils.h"

/* Define dummy setup struct that can be used by unittests when needed */
device_info_t *device_info = nullptr;

/* Number of dummy threads/devices; tests may override this global to describe
 * topologies with more (or fewer) than the default count. */
int unittests_device_count = UNITTESTS_THREAD_COUNT;

int device_count() { return unittests_device_count; }
int thread_count() { return unittests_device_count; }
int num_cpus() { return thread_count(); }

bool test_is_retry() noexcept { return false; }

