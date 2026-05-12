/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sandstone.h>
#include <topology_gpu.h>

#include <algorithm>

namespace {
void push_to_numa_domains(std::vector<Topology::NumaNode>& numa_domains, const Topology::Thread* info)
{
    auto domain = std::find_if(numa_domains.begin(), numa_domains.end(), [&](const auto& node) {
        return node.id() == info->numa_id; // devices with numa_id=-1 (unknown) will be grouped together
    });
    if (domain == numa_domains.end()) {
        domain = numa_domains.emplace(numa_domains.end());
    }
    domain->devices.push_back(info);
}
} // end anonymous namespace

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
            push_to_numa_domains(topo.numa_domains, info);
            info++;
            root_first++;
        } else {
            if (memcmp(&info->bdf, &root_first->bdf, sizeof(ze_pci_address_ext_t))) { // we're in different, new root, and there is one stil open
                topo.devices.emplace_back() = std::span(root_first, info); // close the open root
                root_first = info; // start a new root
            }
            push_to_numa_domains(topo.numa_domains, info);
            info++;
        }
    }
    // commit last span of devices if open
    if (root_first != info) {
        topo.devices.emplace_back() = std::span(root_first, info); // close the open root
    }
    return topo;
}

void slice_plan_init_for_device(SlicePlans::SlicesArray& plans, int max_cores_per_slice)
{
    std::vector plan = { DeviceRange{ 0, thread_count() } };
    plans[SlicePlans::IsolateSockets] = plan;

    auto& isolate_numa = plans[SlicePlans::IsolateNuma];
    auto& heuristic = plans[SlicePlans::Heuristic];

    const Topology &topology = Topology::topology();
    for (const auto& numa_domain : topology.numa_domains) {
        if (numa_domain.devices.empty()) {
            continue;
        }

        int range_start = numa_domain.devices.front()->gpu();
        int prev_gpu = range_start;
        for (size_t i = 1; i < numa_domain.devices.size(); ++i) {
            int gpu = numa_domain.devices[i]->gpu();
            if (gpu == prev_gpu + 1) {
                prev_gpu = gpu;
                continue; // continue within the contiguous range
            }

            // end of contiguous range
            isolate_numa.push_back(DeviceRange{ range_start, prev_gpu - range_start + 1 });
            range_start = prev_gpu = gpu;
        }

        // include open tailing range
        isolate_numa.push_back(DeviceRange{ range_start, prev_gpu - range_start + 1 });
    }

    if (isolate_numa.empty()) [[unlikely]] {
        isolate_numa = plan;
    }

    // Heuristic:
    // - is numa local,
    // - only contiguous range can form a slice,
    // - never splits RootDevice groups,
    // - takes max_devices_per_slice into account
    struct AtomicGroup
    {
        int start;
        int count;
        int16_t numa_id;
    };

    std::vector<AtomicGroup> groups;
    groups.reserve(topology.devices.size());
    for (const auto &device : topology.devices) {
        if (const auto* root = std::get_if<Topology::RootDevice>(&device)) {
            if (root->empty())
                continue;

            int start = root->front().gpu();
            int end = root->back().gpu();
            assert(end >= start);
            groups.push_back({ start, end - start + 1, root->front().numa_id });
        } else {
            auto end_device = std::get<Topology::EndDevice>(device);
            groups.push_back({ end_device->gpu(), 1, end_device->numa_id });
        }
    }

    int max_devices_per_slice = max_cores_per_slice > 0 ? max_cores_per_slice : SlicePlans::DefaultMaxCoresPerSlice;
    if (max_devices_per_slice < 1)
        max_devices_per_slice = 1;

    std::vector<int16_t> numa_ids;
    std::vector<std::vector<AtomicGroup>> buckets; // each bucket contains one numa node
    for (const auto &g : groups) {
        auto id = std::find(numa_ids.begin(), numa_ids.end(), g.numa_id);
        size_t idx = id - numa_ids.begin();
        if (id == numa_ids.end()) {
            numa_ids.push_back(g.numa_id);
            buckets.emplace_back();
        }
        buckets[idx].push_back(g);
    }

    for (const auto& bucket : buckets) {
        if (bucket.empty())
            continue;

        int range_start = bucket.front().start;
        int range_count = bucket.front().count;
        for (size_t i = 1; i < bucket.size(); ++i) {
            const auto &g = bucket[i];
            int expected_next_start = range_start + range_count;
            bool contiguous = (g.start == expected_next_start);

            if (!contiguous || range_count + g.count > max_devices_per_slice) {
                // commit the slice
                heuristic.push_back({ range_start, range_count });
                range_start = g.start;
                range_count = g.count;
            } else {
                // grow it further
                range_count += g.count;
            }
        }
        // end of devices for this NUMA node, close the slice
        heuristic.push_back({ range_start, range_count });
    }

    if (heuristic.empty()) [[unlikely]] {
        heuristic = plan;
    }
}
