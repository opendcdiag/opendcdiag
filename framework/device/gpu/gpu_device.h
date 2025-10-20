/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

#ifndef INC_GPU_DEVICE_H
#define INC_GPU_DEVICE_H

struct gpu_info_t
{
    /// Logical OS processor number.
    /// On Unix systems, this is a sequential ID; on Windows, it encodes
    /// 64 * ProcessorGroup + ProcessorNumber
    int cpu_number;

    /// Package ID in the system, should be set to -1 (not known).
    /// We keep it for legacy reasons (used in selftest.cpp)
    int16_t package_id;
};

// Alias for use in common framework code
typedef struct gpu_info_t device_info_t;

extern struct gpu_info_t *cpu_info;

// Not used at the moment
typedef unsigned __int128 device_features_t;
static const device_features_t device_compiler_features = 0;
#define cpu_has_feature(f)      ((device_compiler_features & (f)) == (f) || (device_features & (f)) == (f))

#endif // INC_GPU_DEVICE_H
