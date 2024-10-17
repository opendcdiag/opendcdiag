/*
 * Copyright 2024 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_DEVICES_H
#define INC_DEVICES_H

struct DeviceRange
{
    // a contiguous range
    int starting_device;
    int device_count;
};

/*
 * Called from sandstone_main(). The default implementation performs no
 * checks, they just return. Feel free to implement a strong version elsewhere
 * if you prefer the framework to check for system or CPU criteria.
 */
static __attribute__((unused, noinline)) void device_specific_init() {}

#endif // INC_DEVICES_H
