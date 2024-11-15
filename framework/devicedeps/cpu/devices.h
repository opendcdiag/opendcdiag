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

#endif // INC_DEVICES_H
