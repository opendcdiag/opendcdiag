/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_DEVICE_H
#define INC_DEVICE_H

#include "sandstone_config.h"

#if SANDSTONE_DEVICE_CPU
#include <device/cpu/cpu_device.h>
#elif SANDSTONE_DEVICE_GPU
#include <device/gpu/gpu_device.h>
#endif

#endif /* INC_DEVICE_H */
