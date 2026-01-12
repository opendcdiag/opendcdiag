/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_TOPOLOGY_GPU_H
#define INC_TOPOLOGY_GPU_H

#include "topology.h"
#include "gpu_device.h"
#include "multi_slice_gpu.h"

#include "level_zero/ze_api.h"
#include "level_zero/zes_api.h"

#include <functional>
#include <map>
#include <variant>
#include <span>

/// Handles used during initial device discovery.
/// Whatever we store here, will be further used to initialize gpu_info in setup_devices().
/// Since detect/setup_devices() is guaranteed to happen in the same process, we can store
/// those handles as they won't become invalid in the meantime.
struct ZeDeviceCtx
{
    ze_driver_handle_t driver;
    ze_device_handle_t ze_handle;
    zes_device_handle_t zes_handle;
};
using GpusSet = std::map<MultiSliceGpu, ZeDeviceCtx>;
using EnabledDevices = GpusSet;

/// Topology: set of "root" devices, each having 0 or >0 (nested) subdevices.
class Topology
{
public:
    using Thread = struct gpu_info_t;

    // Example for 12 GPUs:
    // - FLAT: 12 EndDevices
    // - COMPOSITE: 6 RootDevices, 2 Tiles each
    using EndDevice = const Thread*;            // FLAT, does not contain subdevices
    using RootDevice = std::span<const Thread>; // COMPOSITE, a "multi-stack" GPU

    std::vector<std::variant<RootDevice, EndDevice>> devices;

    static const Topology &topology();
};

/// Fills the topology (devices & their subdevices) based on cpu_info.
/// Supports heterogenous topology (mixed kind of devices - End and Root).
Topology build_topology();

/// Calls passed function for each 'end' device within topology.
int for_each_topo_device(std::function<int(gpu_info_t&)> func);

/// Struct should contain common info for all detected GPUs, such as brand, etc.
struct HardwareInfo
{

};

#endif /* INC_TOPOLOGY_GPU_H */
