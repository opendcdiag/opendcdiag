/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"
#include "topology.h"
#include "topology_idxd.hpp"

#include <accel-config/libaccel_config.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <format>
#include <optional>
#include <vector>

namespace {
// append existing group with a new wq, fill its config
void append_topo_group(Topology::Group& group, accfg_wq* wq_handle, const wq_info_t* info)
{
    auto& wq = group.wqs.emplace_back();

    wq.wq = info;
    wq.id = info->wq_id;
    wq.group_id = group.id;
    wq.state = accfg_wq_get_state(wq_handle);
    wq.type = accfg_wq_get_type(wq_handle);
    wq.mode = accfg_wq_get_mode(wq_handle);
    wq.max_transfer_size = accfg_wq_get_max_transfer_size(wq_handle);
    wq.max_batch_size = accfg_wq_get_max_batch_size(wq_handle);
    wq.size = accfg_wq_get_size(wq_handle);

    accfg_wq_get_op_config(wq_handle, &wq.op_config);

    if (int v = accfg_wq_get_threshold(wq_handle); wq.mode == ACCFG_WQ_SHARED && v >= 0) {
        wq.threshold = v;
    }

    if (int v = accfg_wq_get_priority(wq_handle); v >= 0) {
        wq.priority = v;
    }
    if (int v = accfg_wq_get_block_on_fault(wq_handle); v >= 0) {
        wq.block_on_fault = v;
    }
    if (int v = accfg_wq_get_ats_disable(wq_handle); v >= 0) {
        wq.ats_disable = v;
    }
    if (int v = accfg_wq_get_prs_disable(wq_handle); v >= 0) {
        wq.prs_disable = v;
    }

    wq.targetable = (wq.state == ACCFG_WQ_ENABLED && wq.type == ACCFG_WQT_USER);
}

// search for existing group or create new
void append_topo_device(Topology::Device& device, accfg_device* device_handle, const wq_info_t* info)
{
    auto wq_handle = accfg_device_wq_get_by_id(device_handle, info->wq_id);
    assert(wq_handle != nullptr);
    auto group_id = accfg_wq_get_group_id(wq_handle);

    auto it = std::ranges::find_if(device.groups, [&](const auto& g) { return g.id == group_id; });
    if (it ==  device.groups.end()) {
        // new group
        it = device.groups.emplace(it);
        it->id = group_id;
        it->name = std::format("group{}", group_id);
        accfg_engine* engine;
        accfg_engine_foreach(device_handle, engine) {
            if (accfg_engine_get_group_id(engine) == group_id) {
                auto& e = it->engines.emplace_back();
                e.id = accfg_engine_get_id(engine);
                const char* devname = accfg_engine_get_devname(engine);
                assert(devname != nullptr && devname[0] != '\0');
                e.name = devname;
            }
        }
    }
    append_topo_group(*it, wq_handle, info);
}
} // end anonymous namespace

void Topology::finalize_links()
{
    wqs.assign(device_count(), nullptr);
    for (auto& device : devices) {
        for (auto& group : device.groups) {
            for (auto& wq : group.wqs) {
                wq.this_device = &device;
                wq.this_group = &group;
                wqs.at(wq.wq->wq()) = &wq;
            }
        }
    }
}

Topology build_topology(accfg_ctx* ctx)
{
    Topology topo;

    const wq_info_t* info = device_info;
    const wq_info_t* cend = device_info + device_count();

    while (info != cend) {
        auto it = std::ranges::find_if(topo.devices, [&](const auto& d) { return d.id == info->device_id; });
        if (it == topo.devices.end()) {
            // new device
            it = topo.devices.emplace(it);

            it->id = info->device_id;
            it->dev_type = info->dev_type;
            it->dev_version = info->dev_version;
            if (!ctx)
                continue;

            auto device_handle = accfg_ctx_device_get_by_id(ctx, it->id);
            assert(device_handle != nullptr);
            const char* devname = accfg_device_get_devname(device_handle);
            assert(devname != nullptr && devname[0] != '\0');
            it->name = devname;
            it->max_transfer_size = accfg_device_get_max_transfer_size(device_handle);
            it->max_batch_size = accfg_device_get_max_batch_size(device_handle);
            it->max_groups = accfg_device_get_max_groups(device_handle);
            [[maybe_unused]] int op_cap_ret = accfg_device_get_op_cap(device_handle, &it->op_cap);
            assert(op_cap_ret == 0);
        }
        if (ctx) {
            auto device_handle = accfg_ctx_device_get_by_id(ctx, it->id);
            assert(device_handle != nullptr);
            append_topo_device(*it, device_handle, info);
        }
        it->wqs.emplace_back(info);
        info++;
    }

    topo.finalize_links();

    return topo;
}

Topology build_topology()
{
    AccfgCtx ctx;
    if (auto ret = ctx.init(); ret) {
        return {};
    }
    return build_topology(ctx.get());
}

// Heuristic:
// - keeps contiguous WQs of a device together,
// - groups by NUMA node,
// - takes max_cores_per_slice into account
void slice_plan_init_for_device(SlicePlans::SlicesArray& plans, int max_cores_per_slice)
{
    SlicePlans::Slices full_plan = { SlicePlans::Slice{ DeviceRange{ 0, device_count() }, {} } };
    plans[SlicePlans::IsolateSockets] = full_plan;

    auto& isolate_numa = plans[SlicePlans::IsolateNuma];
    auto& heuristic = plans[SlicePlans::Heuristic];
    const auto& topology = Topology::topology();

    std::vector<int> numa_ids;
    std::vector<std::vector<DeviceRange>> buckets; //each numa contains a vector of contiguous ranges
    for (const auto& device : topology.devices) {
        if (device.wqs.empty())
            continue;

        auto id = std::find(numa_ids.begin(), numa_ids.end(), device.wqs.front()->numa_id);
        size_t index = id - numa_ids.begin();
        if (id == numa_ids.end()) {
            numa_ids.push_back(device.wqs.front()->numa_id);
            buckets.emplace_back();
        }
        auto& bucket = buckets[index];
        int start = device.wqs.front()->wq();
        int last = start;
        for (size_t index = 1; index < device.wqs.size(); ++index) {
            int current = device.wqs[index]->wq();
            // not contiguous, must close range
            if (current != last + 1) {
                bucket.push_back({ start, last - start + 1 });
                start = current;
            }
            last = current;
        }
        bucket.push_back({ start, last - start + 1 });
    }

    int max_devices_per_slice = max_cores_per_slice > 0 ? max_cores_per_slice : SlicePlans::DefaultMaxCoresPerSlice;
    for (const auto& bucket : buckets) {
        DeviceRange numa_range = bucket.front();
        DeviceRange heuristic_range = numa_range;
        for (size_t index = 1; index < bucket.size(); ++index) {
            const auto& range = bucket[index];
            if (range.starting_device != numa_range.starting_device + numa_range.device_count) {
                isolate_numa.push_back(SlicePlans::Slice{ numa_range, {} });
                numa_range = range;
            } else {
                // merge adjacent contiguous WQs (split in the first loop due to being on different devices)
                numa_range.device_count += range.device_count;
            }

            if (range.starting_device != heuristic_range.starting_device + heuristic_range.device_count
                    || heuristic_range.device_count + range.device_count > max_devices_per_slice) {
                heuristic.push_back(SlicePlans::Slice{ heuristic_range, {} });
                heuristic_range = range;
            } else {
                // ditto, except we take max_devices_per_slice into account
                heuristic_range.device_count += range.device_count;
            }
        }
        isolate_numa.push_back(SlicePlans::Slice{ numa_range, {} });
        heuristic.push_back(SlicePlans::Slice{ heuristic_range, {} });
    }

    if (isolate_numa.empty())
        isolate_numa = full_plan;
    if (heuristic.empty())
        heuristic = full_plan;
}

/// Feature bits a device of this type and version satisfies, excluding op bits.
device_features_t device_type_features(accfg_device_type dev_type, unsigned version)
{
    device_features_t features = 0;
    if (dev_type == ACCFG_DEVICE_DSA) {
        features |= device_feature_dsa;
        if (version >= ACCFG_DEVICE_VERSION_1)
            features |= device_feature_dsa_v1;
        if (version >= ACCFG_DEVICE_VERSION_2)
            features |= device_feature_dsa_v2;
        if (version > ACCFG_DEVICE_VERSION_2)
            features |= device_feature_dsa_v3;
    } else if (dev_type == ACCFG_DEVICE_IAX) {
        features |= device_feature_iax;
        if (version >= ACCFG_DEVICE_VERSION_1)
            features |= device_feature_iax_v1;
        if (version >= ACCFG_DEVICE_VERSION_2)
            features |= device_feature_iax_v2;
        if (version > ACCFG_DEVICE_VERSION_2)
            features |= device_feature_iax_v3;
    }
    return features;
}

/// Maps each operation feature bit set in features to its IDXD opcode. Op must match its dev_type.
std::vector<unsigned> features_to_opcodes(device_features_t features, accfg_device_type dev_type)
{
    std::vector<unsigned> res;
    for (auto [feature, opcode, entry_type] : feature_to_opcode_map) {
        if ((features & feature) == 0)
            continue;
        if (entry_type != dev_type)
            continue;
        res.push_back(opcode);
    }
    return res;
}

bool has_feature(const wq_info_t& info, device_features_t features)
{
    auto this_dev_type_features = device_type_features(info.dev_type, info.dev_version);
    auto requested_dev_type_features = features & idxd_dev_type_features_mask;
    if ((requested_dev_type_features & this_dev_type_features) != requested_dev_type_features) {
        // i.e. info.dev_type=iax,info.dev_version=v1 and device_feature_iax_v2
        return false;
    }

    const accfg_op_cap& op_cap = Topology::topology().work_queue(info).this_device->op_cap;
    return std::ranges::all_of(features_to_opcodes(features, info.dev_type),
                               [&op_cap](unsigned opcode) { return has_opcode(op_cap, opcode); });
}


std::vector<const Topology::WorkQueue*> Topology::targetable_wqs(struct test* test, accfg_device_type required_device_type) const
{
    std::vector<const WorkQueue*> result;

    std::optional<accfg_wq_mode> required_mode = {}; // TODO: define somewhere, as a feature?

    for (const Device &device : devices) {
        if (device.dev_type != required_device_type) {
            continue;
        }

        for (const Group &group : device.groups) {
            for (const WorkQueue &wq : group.wqs) {
                if (wq.targetable && (!required_mode || wq.mode == *required_mode)
                        && has_feature(*wq.wq, test->minimum_cpu)) {
                    result.push_back(&wq);
                }
            }
        }
    }

    return result;
}
