/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_TOPOLOGY_IDXD_HPP
#define INC_TOPOLOGY_IDXD_HPP

#include "idxd_device.h"

#include <accel-config/libaccel_config.h>

#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

/// RAII wrapper around accfg_ctx. The lifetime of the underlying context is the same as this wrapper's.
/// accfg_ref is not used at this point.
struct AccfgCtx
{
    accfg_ctx* ctx = nullptr;

    AccfgCtx() = default;
    AccfgCtx(AccfgCtx&& other) noexcept
        : ctx(std::exchange(other.ctx, nullptr))
    {}
    ~AccfgCtx() {
        if (ctx) accfg_unref(ctx);
    }

    // non-copyable
    AccfgCtx(const AccfgCtx&) = delete;
    AccfgCtx& operator=(const AccfgCtx&) = delete;

    int init();
    accfg_ctx* get() const { return ctx; }
};

/// Immutable and unique id of a queue: device_id and wq_id, as in qw<device_id>.<wq_id>.
/// Since detect/setup_devices() is guaranteed to happen in the same process, we can store
/// accfg handles as they won't become invalid in the meantime (require accfg_ctx* though).
struct WorkQueueId
{
    accfg_device* device_handle = nullptr;
    accfg_device_type device_type = accfg_device_type::ACCFG_DEVICE_TYPE_UNKNOWN;
    int device_id = -1;
    int wq_id = -1;
};

/// To be able to store handles, we must carry around the ctx as well.
struct WorkQueueSet
{
    AccfgCtx ctx;
    std::vector<WorkQueueId> visible_wqs;
    bool empty() const noexcept { return visible_wqs.empty(); }
};

using EnabledDevices = WorkQueueSet;

// TODO: Apart from obvious Enabled and Disabled states, there are also Quiescing
// and Locked transitional/protective states. If those states are spotted during
// reconfiguration process, I don't know what should we do. Probably poll until
// Quiescing turns into a stable state, and maybe treat Locked as Locked.
// Ideally WQs should be either enabled or disabled.

/// Unlike for other devices, IDXD Topology is subject to change in-between tests.
class Topology
{
public:
    using Thread = struct wq_info_t;

    struct Device;
    struct WorkQueue
    {
        /// Immutable part.
        const wq_info_t* wq = nullptr;
        int id = -1;

        /// Mutable part, either configurable or just observed/effective.
        accfg_wq_mode mode = accfg_wq_mode::ACCFG_WQ_MODE_UNKNOWN;
        accfg_wq_state state = accfg_wq_state::ACCFG_WQ_UNKNOWN;
        accfg_wq_type type = accfg_wq_type::ACCFG_WQT_NONE;

        int group_id = -1; // same as Group::id

        // present on all queues
        uint32_t max_batch_size = 0;
        uint64_t size = 0;
        uint64_t max_transfer_size = 0;

        // for shared WQs
        std::optional<uint32_t> threshold;

        // optional features
        std::optional<uint32_t> priority;
        std::optional<bool> block_on_fault;
        std::optional<bool> ats_disable;
        std::optional<bool> prs_disable;

        accfg_op_config op_config = {}; // for effective op check: this_device->op_cap[i] & op_config[i]

        // TODO: experimental: set to true only if: state is enabled, ownership allows using it, and mode allows using it.
        // later we can add a function iterating over all targetable wqs or something...
        // this variable is derived, not set manually
        bool targetable = false;

        const Device* this_device = nullptr;
    };

    struct Engine
    {
        int id = -1;
    };

    struct Group
    {
        int id = -1;
        std::vector<WorkQueue> wqs;
        std::vector<Engine> engines; // TODO: I wonder if num_engines would suffice, since we cannot target them to test.
    };

    struct Device
    {
        int id = -1;
        accfg_device_type dev_type = accfg_device_type::ACCFG_DEVICE_TYPE_UNKNOWN;

        uint32_t max_batch_size = 0;
        uint64_t max_transfer_size = 0;

        accfg_op_cap op_cap = {};

        std::vector<Group> groups;
    };

    // Decide:
    //   - std::vector<std::variant<DsaDevice, IaxDevice>>
    //   - std::vector<DsaDevice> and std::vector<IaxDevice>
    //   - one std::vector<Device> and a type member to Device?
    std::vector<Device> devices;
};

struct HardwareInfo
{};

#endif // INC_TOPOLOGY_IDXD_HPP
