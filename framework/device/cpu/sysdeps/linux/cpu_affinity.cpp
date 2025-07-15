/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

// #include "topology.h"
#include "device/device_topology.h"

#include <sched.h>
#include <stdio.h>

#ifdef __linux__
#include <sys/prctl.h>

static void set_thread_name(const char *thread_name)
{
    if (thread_name)
        prctl(PR_SET_NAME, thread_name);
}
#endif

bool pin_to_logical_processor(LogicalProcessor n, const char *thread_name)
{
    return pin_thread_to_logical_processor(n, 0, thread_name);
}

bool pin_thread_to_logical_processor(LogicalProcessor n, tid_t thread_id, const char *thread_name)
{
    set_thread_name(thread_name);
    if (n == LogicalProcessor(-1))
        return true;            // don't change affinity

    using Word = LogicalProcessorSetOps::Word;
    constexpr size_t ProcessorsPerWord = LogicalProcessorSetOps::ProcessorsPerWord;
    size_t size = size_t(n) / ProcessorsPerWord + 1;

    Word cpu_set[size];         // -Wvla
    memset(cpu_set, 0, sizeof(cpu_set));
    LogicalProcessorSetOps::setInArray({ cpu_set, size }, n);

    if (sched_setaffinity(thread_id, sizeof(cpu_set), reinterpret_cast<cpu_set_t *>(cpu_set))) {
        perror("sched_setaffinity");
        return false;
    }
    return true;
}

bool pin_to_logical_processors(DeviceRange range, const char *thread_name)
{
    set_thread_name(thread_name);

    // find the maximum CPU number
    int n = 0;
    for (int cpu = range.starting_device; cpu < range.starting_device + range.device_count; ++cpu)
        n = std::max(n, cpu_info[cpu].cpu_number);

    using Word = LogicalProcessorSetOps::Word;
    constexpr size_t ProcessorsPerWord = LogicalProcessorSetOps::ProcessorsPerWord;
    size_t size = size_t(n) / ProcessorsPerWord + 1;

    Word cpu_set[size];         // -Wvla
    memset(cpu_set, 0, sizeof(cpu_set));

    for (int cpu = range.starting_device; cpu < range.starting_device + range.device_count; ++cpu) {
        auto lp = LogicalProcessor(cpu_info[cpu].cpu_number);
        LogicalProcessorSetOps::setInArray({ cpu_set, size }, lp);
    }

    if (sched_setaffinity(0, sizeof(cpu_set), reinterpret_cast<cpu_set_t *>(cpu_set))) {
        perror("sched_setaffinity");
        return false;
    }
    return true;
}
