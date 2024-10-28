/*
 * Copyright 2024 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_DEVICES_H
#define INC_DEVICES_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // a contiguous range
    int starting_device;
    int device_count;
} DeviceRange;

/// @brief Generic device discovery and initialization function. Need to be
/// implemented by the device-specific code. The function is called from the
/// framework's main() function.
extern void device_init();

extern int num_devices();

/// Called from sandstone_main(). The default implementation performs no
/// checks, they just return. Feel free to implement a strong version elsewhere
/// if you prefer the framework to check for additional system or device criteria.
static __attribute__((unused, noinline)) void device_specific_init() {}

void restrict_devices(DeviceRange range);

#ifdef __cplusplus
}

// Base device type
class DeviceBase {
public:
    DeviceBase(int index) : index{index} {}
    virtual ~DeviceBase() {}
    int index;
};
#endif


#endif // INC_DEVICES_H
