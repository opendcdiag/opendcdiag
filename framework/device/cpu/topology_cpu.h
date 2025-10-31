/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_TOPOLOGY_CPU_H
#define INC_TOPOLOGY_CPU_H

#include "sandstone.h"
#include "cpu_device.h"
#include "topology.h"

#include "gettid.h"

#include <algorithm>
#include <barrier>
#include <functional>
#include <span>

using EnabledDevices = LogicalProcessorSet;

class Topology
{
public:
    using Thread = cpu_info_t;
    struct Core
    {
        std::span<const Thread> threads;
    };
    struct Module
    {
        std::span<const Thread> threads;
    };

    struct CoreGrouping
    {
        std::vector<Core> cores;
        // std::vector<Module> modules;
    };

    struct NumaNode : CoreGrouping
    {
        int id() const
        {
            return cores.size() ? cores.front().threads.front().numa_id : -1;
        }
    };

    struct Package : CoreGrouping
    {
        // We consider different core types in a heterogeneous system to be a
        // different "NUMA" nodes.
        std::vector<NumaNode> numa_domains;
        int id() const
        {
            return cores.size() ? cores.front().threads.front().package_id : -1;
        }
    };

    std::vector<Package> packages;

    bool isValid() const
    {
        return !packages.empty();
    }

    std::string build_failure_mask(const struct test *test) const;

    static const Topology &topology();
    struct Data;
    Data clone() const;
};

struct Topology::Data
{
    // this type is move-only (not copyable)
    Data() = default;
    Data(const Data &) = delete;
    Data(Data &&) = default;
    Data &operator=(const Data &) = delete;
    Data &operator=(Data &&) = default;

    std::vector<Package> packages;
    std::vector<Topology::Thread> all_threads;
};

struct HardwareInfo
{
    // information for CPUs
    struct PackageInfo {
        int id;
        uint64_t ppin;
    };

    std::vector<PackageInfo> package_infos;
    uint16_t model = 0;
    uint8_t family = 0;
    uint8_t stepping = 0;

    const PackageInfo *find_package_id(int pkgid) const
    {
        auto it = std::find_if(package_infos.cbegin(), package_infos.cend(),
                               [pkgid](const PackageInfo &pi) { return pkgid == pi.id; });
        return it == package_infos.cend() ? nullptr : std::to_address(it);
    }
};

class BarrierDeviceScheduler : public DeviceScheduler
{
public:
    void reschedule_to_next_device() override;
    void finish_reschedule() override;

private:
    struct GroupInfo
    {
        std::barrier<std::function<void()>> *barrier;
        std::vector<pid_t> tid;     // Keep track of all members tid
        std::vector<int> next_cpu;  // Keep track of cpus on the group

        GroupInfo(int members_per_group, std::function<void()> on_completion)
        {
            barrier = new std::barrier<std::function<void()>>(members_per_group, std::move(on_completion));
            tid.resize(members_per_group);
            next_cpu.resize(members_per_group);
        }

        ~GroupInfo()
        {
            delete barrier;
        }
    };

    const int members_per_group = 2; // TODO: Make it configurable
    std::vector<GroupInfo> groups;
    std::mutex groups_mutex;
};

class QueueDeviceScheduler : public DeviceScheduler
{
public:
    void reschedule_to_next_device() override;
    void finish_reschedule() override {}

private:
    void shuffle_queue();

    int q_idx = 0;
    std::vector<int> queue;
    std::mutex q_mutex;
};

class RandomDeviceScheduler : public DeviceScheduler
{
public:
    void reschedule_to_next_device() override;
    void finish_reschedule() override {}
};

#endif /* INC_TOPOLOGY_CPU_H */
