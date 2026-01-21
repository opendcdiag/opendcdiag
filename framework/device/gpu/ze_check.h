/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_ZE_CHECK_H
#define INC_ZE_CHECK_H

#include "sandstone_p.h"
#include "ze_utils.h"

#include "level_zero/ze_api.h"

/// Check return value of an L0 API call. Log the return status and return EXIT_FAILURE if check against "success" status fails.
#define ZE_CHECK(...) \
    do { \
        auto result = (__VA_ARGS__); \
        if (result != ZE_RESULT_SUCCESS) { \
            if (!sApp->shmem) { \
                fprintf(stderr, "L0 API call failed with status %s\n", to_string(result)); \
            } else if (thread_num >= 0) { \
                log_debug("L0 API call failed with status %s", to_string(result)); \
            } else { \
                logging_printf(LOG_LEVEL_VERBOSE(1), "L0 API call failed with status %s\n", to_string(result)); \
            } \
            return EXIT_FAILURE; \
        } \
    } while (0)

#endif // INC_ZE_CHECK_H
