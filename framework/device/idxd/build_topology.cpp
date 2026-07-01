/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"
#include "topology_idxd.hpp"

#include <accel-config/libaccel_config.h>

#include <algorithm>
#include <cassert>
#include <format>

namespace {
// append existing group with a new wq, fill its config
void append_topo_group(Topology::Group& group, accfg_wq* wq_handle, wq_info_t* info)
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
void append_topo_device(Topology::Device& device, accfg_device* device_handle, wq_info_t* info)
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

void finalize_topology_links(Topology& topo)
{
    for (auto& device : topo.devices) {
        for (auto& group : device.groups) {
            for (auto& wq : group.wqs) {
                wq.this_device = &device;
                wq.this_group = &group;
                // We can do const_cast because originally (in append_topo_group()) info was non-const.
                const_cast<wq_info_t*>(wq.wq)->path = { device.id, group.id };
            }
        }
    }
}
} // end anonymous namespace

Topology build_topology(const AccfgCtx& ctx)
{
    Topology topo;

    wq_info_t* info = device_info;
    const wq_info_t* cend = device_info + device_count();

    while (info != cend) {
        auto it = std::ranges::find_if(topo.devices, [&](const auto& d) { return d.id == info->device_id; });
        if (it == topo.devices.end()) {
            // new device
            it = topo.devices.emplace(it);

            it->id = info->device_id;
            it->dev_type = info->dev_type;
            auto device_handle = accfg_ctx_device_get_by_id(ctx.get(), it->id);
            assert(device_handle != nullptr);
            const char* devname = accfg_device_get_devname(device_handle);
            assert(devname != nullptr && devname[0] != '\0');
            it->name = devname;
            it->numa_node = accfg_device_get_numa_node(device_handle);
            it->max_transfer_size = accfg_device_get_max_transfer_size(device_handle);
            it->max_batch_size = accfg_device_get_max_batch_size(device_handle);
            int op_cap_ret = accfg_device_get_op_cap(device_handle, &it->op_cap);
            assert(op_cap_ret == 0);
        }
        auto device_handle = accfg_ctx_device_get_by_id(ctx.get(), it->id);
        assert(device_handle != nullptr);
        append_topo_device(*it, device_handle, info);
        info++;
    }

    finalize_topology_links(topo);

    return topo;
}

Topology build_topology()
{
    AccfgCtx ctx;
    if (auto ret = ctx.init(); ret) {
        return {};
    }
    return build_topology(ctx);
}
