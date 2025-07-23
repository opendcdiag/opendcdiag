/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_DEVICE_H
#define INC_DEVICE_H

// #ifdef SANDSTONE_DEVICE_CPU
#include <device/cpu/cpu_device.h>
// #endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/// Returns the number of hardware threads available to a test to run.
int num_devices() __attribute__((pure));

#ifdef __cplusplus
}
#endif

#endif /* INC_DEVICE_H */
