/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <level_zero/ze_api.h>

#include <stdint.h>

#ifndef INC_GPU_DEVICE_H
#define INC_GPU_DEVICE_H

#ifdef __cplusplus
#   include <compare>
#endif

struct gpu_info_t
{
    /// Logical OS processor number.
    /// On Unix systems, this is a sequential ID; on Windows, it encodes
    /// 64 * ProcessorGroup + ProcessorNumber
    int cpu_number;

    /// Package ID in the system, should be set to -1 (not known).
    /// We keep it for legacy reasons (used in selftest.cpp)
    int16_t package_id;

    /// GPU unique index, as iterated by the L0 driver.
    int gpu_number;

    /// GPU identification in the multi-stack GPU system.
    int device_index;     // equal to gpu_number when no subdevices
    int subdevice_index;  // a.k.a. tile/stack, set to -1 when no subdevices

    /// Properties read from L0 API.
    ze_pci_address_ext_t bdf;                          // from: ze_pci_ext_properties_t
    uint32_t num_subdevices;                           // from: zes_device_properties_t
    ze_device_properties_t device_properties;          // contains: uuid, bdf, deviceId, subdeviceId, num of Xe cores, etc.
    ze_device_compute_properties_t compute_properties; // contains: maxSharedLocalMemory, numSubGroupSizes, etc.

#ifdef __cplusplus
    friend constexpr std::strong_ordering operator<=>(const gpu_info_t& lhs, const gpu_info_t& rhs) noexcept {
        // no <=> operator for bdf, device_properties, compute_properties
        return lhs.gpu_number <=> rhs.gpu_number;
    }

    int gpu() const;        ///! Internal GPU number
#endif
};

// Alias for use in common framework code
typedef struct gpu_info_t device_info_t;

extern struct gpu_info_t *cpu_info;

#ifdef __cplusplus
inline int gpu_info_t::gpu() const
{
    return this - ::cpu_info;
}
#endif

// Not used at the moment
typedef unsigned __int128 device_features_t;
static const device_features_t device_compiler_features = 0;
#define cpu_has_feature(f)      ((device_compiler_features & (f)) == (f) || (device_features & (f)) == (f))

#endif // INC_GPU_DEVICE_H
