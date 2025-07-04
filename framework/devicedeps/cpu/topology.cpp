/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cpu_device.h"
#include "topology.h"
#include "sandstone_p.h"

int num_cpus()
{
    return sApp->thread_count;
}

int num_packages()
{
    return Topology::topology().packages.size();
}

void reschedule()
{
    if (sApp->device_schedule == nullptr) return;
    sApp->device_schedule->reschedule_to_next_device();
    return;
}

void DeviceSchedule::pin_to_next_cpu(int next_cpu, tid_t thread_id)
{
    if (!pin_thread_to_logical_processor(LogicalProcessor(next_cpu), thread_id)) {
        log_warning("Failed to reschedule %d (%tu) to CPU %d", thread_id, (uintptr_t)pthread_self(), next_cpu);
    }
}

void BarrierDeviceSchedule::reschedule_to_next_device()
{
    auto on_completion = [&]() noexcept {
        std::unique_lock lock(groups_mutex);
        int g_idx = thread_num / members_per_group;
        GroupInfo &group = groups[g_idx];

        // Rotate cpus vector so reschedule group members to a different cpu
        std::rotate(group.next_cpu.begin(), group.next_cpu.begin() + 1, group.next_cpu.end());
        lock.unlock();

        // Reschedule group members
        for (int i=0; i<group.tid.size(); i++) {
            pin_to_next_cpu(cpu_info[group.next_cpu[i]].cpu_number, group.tid[i]);
        }
    };

    std::unique_lock lock(groups_mutex);
    // Initialize groups on first run
    if (groups.empty()) {
        int full_groups = num_cpus() / members_per_group;
        int partial_group_members = num_cpus() % members_per_group;

        groups.reserve(full_groups + (partial_group_members > 0));
        for (int i=0; i<full_groups; i++) {
            groups.emplace_back(members_per_group, on_completion);
        }
        if (partial_group_members > 0) {
            groups.emplace_back(partial_group_members, on_completion);
        }
    }

    // Fill thread info if not done already
    int g_idx = thread_num / members_per_group;
    GroupInfo &group = groups[g_idx];
    int thread_info_idx = thread_num % members_per_group;
    if (group.tid[thread_info_idx] == 0) {
        group.tid[thread_info_idx] = sApp->test_thread_data(thread_num)->tid.load();
        group.next_cpu[thread_info_idx] = thread_num;
    }

    lock.unlock();

    // Wait on proper barrier
    group.barrier->arrive_and_wait();
    return;
}

void BarrierDeviceSchedule::finish_reschedule()
{
    // Don't clean up when test does not support rescheduling
    if (groups.size() == 0) return;

    // When thread finishes, unsubscribe it from barrier
    // this avoid partners deadlocks
    int g_idx = thread_num / members_per_group;
    GroupInfo &group = groups[g_idx];

    // Remove thread info from groups
    std::unique_lock lock(groups_mutex);
    int thread_info_idx = thread_num % members_per_group;
    group.tid.erase(group.tid.begin() + thread_info_idx);

    // Remove CPU information only if the thread failed, as it likely indicates a problematic device;
    // otherwise, keep it for execution.
    if(sApp->test_thread_data(thread_num)->has_failed())
        group.next_cpu.erase(group.next_cpu.begin() + thread_info_idx);
    lock.unlock();

    group.barrier->arrive_and_drop();
}

void QueueDeviceSchedule::reschedule_to_next_device()
{
    // Select a cpu from the queue
    std::lock_guard lock(q_mutex);
    if (q_idx == 0)
        shuffle_queue();

    int next_idx = queue[q_idx];
    if (++q_idx == queue.size())
        q_idx = 0;

    pin_to_next_cpu(cpu_info[next_idx].cpu_number);
    return;
}

void QueueDeviceSchedule::shuffle_queue()
{
    // Must be called with mutex locked
    if (queue.size() == 0) {
        // First use: populate queue with the indexes available
        for (int i=0; i<num_cpus(); i++)
            queue.push_back(i);
    }

    std::default_random_engine rng(random32());
    std::shuffle(queue.begin(), queue.end(), rng);
}

void RandomDeviceSchedule::reschedule_to_next_device()
{
    // Select a random cpu index among the ones available
    int next_idx = unsigned(random()) % num_cpus();
    pin_to_next_cpu(cpu_info[next_idx].cpu_number);

    return;
}
