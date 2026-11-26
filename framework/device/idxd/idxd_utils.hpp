/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_IDXD_UTILS_HPP
#define INC_IDXD_UTILS_HPP

#include "idxd_device.h"

#include <accel-config/libaccel_config.h>

#include <string>

std::string to_string(const bdf_t& bdf);
const char* to_string(accfg_device_type device_type);
const char* to_string(accfg_wq_state state);

#endif // INC_IDXD_UTILS_HPP
