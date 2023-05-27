/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"

#define UNITTESTS_NUM_CPUS 16

/* Define empty log_* macros not useful for unittests */
#undef  log_warning
#define log_warning
#undef  log_error
#define log_error
#undef  log_info
#define log_info
#undef  log_debug
#define log_debug
#undef log_skip
#define log_skip
