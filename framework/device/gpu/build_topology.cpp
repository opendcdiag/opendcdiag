/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sandstone.h>
#include <topology_gpu.h>

Topology build_topology()
{
    Topology topo;
    gpu_info_t* info = device_info;
    const gpu_info_t* cend = device_info + thread_count();
    auto root_first = info;
    while (info != cend) {
        if (info->subdevice_index == -1) {
            if (root_first != info) {
                topo.devices.emplace_back() = std::span(root_first, info); // close the open root
                root_first = info;
            }
            topo.devices.emplace_back() = info;
            info++;
            root_first++;
        } else {
            if (memcmp(&info->bdf, &root_first->bdf, sizeof(ze_pci_address_ext_t))) { // we're in different, new root, and there is one stil open
                topo.devices.emplace_back() = std::span(root_first, info); // close the open root
                root_first = info; // start a new root
            }
            info++;
        }
    }
    // commit last span of devices if open
    if (root_first != info) {
        topo.devices.emplace_back() = std::span(root_first, info); // close the open root
    }
    return topo;
}
