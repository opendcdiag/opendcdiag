/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_TOPOLOGY_IDXD_HPP
#define INC_TOPOLOGY_IDXD_HPP

#include "idxd_device.h"

 #include <cstdint>
#include <optional>
#include <vector>

/// Immutable and unique id of a queue: device_id and wq_id, as in qw<device_id>.<wq_id>.
struct WorkQueueId
{
    dev_type_t dev_type;
    int device_id;
    int wq_id;
};

using WorkQueueSet = std::vector<WorkQueueId>;
using EnabledDevices = WorkQueueSet;

enum class WorkQueueMode : int8_t
{
    Dedicated,
    Shared,
    Unknown = -1,
};

// TODO: there are also Quiescing and Locked transitional/protective states.
// If spotted during reconfiguration process, I don't know what should we do.
// Probably poll until Quiescing turns into a stable state, and maybe treat Locked as Locked.
// Ideally WQs should be either enabled or disabled.
enum class WorkQueueState : int8_t
{
    Enabled,
    Disabled,
    // Locked, // distinct from Disabled
    Unknown = -1,
};

enum class WorkQueueType : int8_t
{
    Kernel,
    User,
    Unknown = -1,
};

/// Unlike for other devices, IDXD Topology is subject to change in-between tests.
class Topology
{
public:
    using Thread = struct wq_info_t;

    struct Device;
    struct WorkQueue
    {
        // immutable part
        const wq_info_t* wq = nullptr;

        // mutable part, either configurable or just observed/effective
        WorkQueueMode mode = WorkQueueMode::Unknown;
        WorkQueueState state = WorkQueueState::Unknown;
        WorkQueueType type = WorkQueueType::Unknown;
        int group_id = -1; // same as Group::id

        // TODO: decide on what's actually useful later
        // present on all queues
        uint64_t size = 0;
        uint32_t max_batch_size = 0;
        uint64_t max_transfer_size = 0;

        // for shared WQs
        std::optional<uint32_t> threshold;

        // gated by capability bits, supported only if device supports it
        std::optional<uint32_t> priority;
        std::optional<bool> block_on_fault;
        std::optional<bool> ats_disable;
        std::optional<bool> prs_disable;

        uint32_t op_config[8] = {}; // effective op check: this_device->op_cap[i] & op_config[i]

        // TODO: experimental: set to true only if: state is enabled, ownership allows using it, and mode allows using it
        // later we can add a function iterating over all targetable wqs or something...
        // this variable is derived, not set manually
        bool targetable = false;

        const Device* this_device = nullptr;
    };

    struct Engine
    {
        int id;
    };

    struct Group
    {
        int id;
        std::vector<WorkQueue> wqs;
        std::vector<Engine> engines; // TODO: I wonder if num_engines would suffice, since we cannot target them to test.
    };

    struct Device
    {
        int id;
        dev_type_t dev_type;

        uint32_t max_batch_size = 0;
        uint64_t max_transfer_size = 0;

        bool supports_priority = false;
        bool supports_block_on_fault = false;
        bool supports_ats_disable = false;
        bool supports_prs_disable = false;

        uint32_t op_cap[8] = {};

        std::vector<Group> groups;
    };

    struct Node
    {
        int id;
        // TODO:
        // Decide:
        //   - std::vector<std::variant<DsaDevice, IaxDevice>>
        //   - std::vector<DsaDevice> and std::vector<IaxDevice>
        //   - one std::vector<Device> and a type member to Device?
        std::vector<Device> devices;
    };

    std::vector<Node> nodes;
};

struct HardwareInfo
{};

#endif // INC_TOPOLOGY_IDXD_HPP
