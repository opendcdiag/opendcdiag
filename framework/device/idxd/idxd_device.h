/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_IDXD_DEVICE_H
#define INC_IDXD_DEVICE_H

#include <stdint.h>

// Work Queue is an atomic piece of a programmable accelerator HW,
// therefore device_info should store WQs, not DSA/IAX devices.
// Inside it we should only store immutable fields.
struct wq_info_t
{
    /// Logical OS processor number.
    /// On Unix systems, this is a sequential ID; on Windows, it encodes
    /// 64 * ProcessorGroup + ProcessorNumber
    int cpu_number;

    /// Package ID in the system.
    int16_t package_id;

    /// ...
    /// ...
    /// ...

#ifdef __cplusplus
    int wq() const;        ///! Internal WQ number
#endif
};

// Alias for use in common framework code
typedef struct wq_info_t device_info_t;

extern struct wq_info_t *device_info;

#ifdef __cplusplus
inline int wq_info_t::wq() const
{
    return this - ::device_info;
}
#endif

// Not used at the moment
typedef unsigned __int128 device_features_t;
static const device_features_t device_compiler_features = 0;
#define cpu_has_feature(f)      ((device_compiler_features & (f)) == (f) || (device_features & (f)) == (f))

#endif // INC_IDXD_DEVICE_H
