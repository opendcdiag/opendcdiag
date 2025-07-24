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

#include <barrier>
#include <functional>
#include <span>

class Topology
{
public:
    using Thread = struct cpu_info;
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

    std::string build_falure_mask(const struct test *test) const;

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

bool pin_thread_to_logical_processor(LogicalProcessor n, tid_t thread_id, const char *thread_name = nullptr);

class BarrierDeviceSchedule : public DeviceSchedule
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

class QueueDeviceSchedule : public DeviceSchedule
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

class RandomDeviceSchedule : public DeviceSchedule
{
public:
    void reschedule_to_next_device() override;
    void finish_reschedule() override {}
};

#endif /* INC_TOPOLOGY_CPU_H */
