/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_ZE_CHECK_H
#define INC_ZE_CHECK_H

#include "sandstone_p.h"
#include "ze_utils.h"

#include <level_zero/ze_api.h>

#include <stdio.h>

extern bool logging_in_test;

/// Log a runtime skip reason during test execution; outside tests, print a quiet message instead.
#define LOG_RUNTIME_SKIP_OR_PRINT(fmt, ...) \
    do { \
        if (!sApp->shmem) { \
            fprintf(stderr, fmt "\n", ##__VA_ARGS__); \
        } else if (logging_in_test) { \
            log_skip(RuntimeSkipCategory, fmt, ##__VA_ARGS__); \
        } else { \
            logging_printf(LOG_LEVEL_QUIET, fmt "\n", ##__VA_ARGS__); \
        } \
    } while (0)

/// Check return value of an L0 API call.
/// In test context it returns EXIT_SKIP; outside tests it returns EXIT_FAILURE.
#define ZE_CHECK(...) \
    do { \
        auto result = (__VA_ARGS__); \
        if (result != ZE_RESULT_SUCCESS) { \
            LOG_RUNTIME_SKIP_OR_PRINT("L0 API call failed with status %s", to_string(result)); \
            if (logging_in_test) { \
                return EXIT_SKIP; \
            } \
            return EXIT_FAILURE; \
        } \
    } while (0)

#endif // INC_ZE_CHECK_H
