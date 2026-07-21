/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"

#define UNITTESTS_THREAD_COUNT 16

/* Number of dummy threads/devices returned by device_count()/thread_count().
 * Defaults to UNITTESTS_THREAD_COUNT; tests may assign a different value to
 * describe topologies with more (or fewer) threads. */
extern int unittests_device_count;

/* Define empty log_* macros not useful for unittests */
#undef  log_warning
#define log_warning(...)
#undef  log_error
#define log_error(...)
#undef  log_info
#define log_info(...)
#undef  log_debug
#define log_debug(...)
#undef log_skip
#define log_skip(...)
