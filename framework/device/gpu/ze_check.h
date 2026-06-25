/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_ZE_CHECK_H
#define INC_ZE_CHECK_H

#include "sandstone_p.h"
#include "ze_utils.h"

#include <level_zero/ze_api.h>

/// Check return value of an L0 API call.
/// In test context it returns EXIT_SKIP; outside tests it returns EXIT_FAILURE.
#define ZE_CHECK(...) \
    do { \
        auto result = (__VA_ARGS__); \
        if (result != ZE_RESULT_SUCCESS) { \
            return log_skip_or_print(RuntimeSkipCategory, "L0 API call failed with status %s", to_string(result)); \
        } \
    } while (0)

#endif // INC_ZE_CHECK_H
