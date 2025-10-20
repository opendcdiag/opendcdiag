/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_DEVICE_TOPOLOGY_H
#define INC_DEVICE_TOPOLOGY_H

#include "sandstone_config.h"

#if SANDSTONE_DEVICE_CPU
#include <device/cpu/topology_cpu.h>
#elif SANDSTONE_DEVICE_GPU
#include <device/gpu/topology_gpu.h>
#endif

#endif /* INC_DEVICE_TOPOLOGY_H */
