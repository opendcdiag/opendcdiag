/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_IDXD_DEVICE_H
#define INC_IDXD_DEVICE_H

#include <accel-config/libaccel_config.h>

#include <stdint.h>


struct bdf_t
{
    uint16_t domain;
    uint8_t bus;
    uint8_t device : 5;
    uint8_t function : 3;
};

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

    /// PCI location.
    struct bdf_t bdf;

    /// WQ unique index within a device.
    int wq_id;

    /// Device that this WQ belongs to.
    int device_id;

    /// Device type that this WQ belongs to (DSA/IAX).
    enum accfg_device_type dev_type;

    /// Device version (V1/V2/V3).
    enum accfg_device_version dev_version;

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
#define device_has_feature(f)      ((device_compiler_features & (f)) == (f) || (device_features & (f)) == (f))

#endif // INC_IDXD_DEVICE_H
