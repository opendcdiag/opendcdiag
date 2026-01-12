/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_ZE_UTILS_H
#define INC_ZE_UTILS_H

#include "level_zero/ze_api.h"
#include "level_zero/zes_api.h"

/// Functions converting resource type to a human readable string.
const char* to_string(ze_result_t value);
const char* to_string(zes_mem_type_t value);
const char* to_string(zes_mem_loc_t value);
const char* to_string(zes_ras_error_type_t value);
const char* to_string(zes_engine_group_t value);
const char* to_string(zes_device_ecc_state_t value);
const char* to_string(zes_device_action_t value);

#endif // INC_ZE_UTILS_H
