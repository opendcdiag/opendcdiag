/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <topology.h>

#include <windows.h>

static int *cpus_per_group;
static int group_count;

static constexpr WORD MaxLogicalProcessorsPerGroup = 64;

static WORD processor_group_for(LogicalProcessor n)
{
    int count = 0;
    int i = 0;

    for (; i < group_count; i++) {
        if (count + cpus_per_group[i] > int(n))
            break;
        count += cpus_per_group[i];
    }
    return i;
}

static BYTE processor_in_group(LogicalProcessor n)
{
    int count = 0;
    int i = 0;

    for (; i < group_count; i++) {
        if (count + cpus_per_group[i] > int(n))
            break;
        count += cpus_per_group[i];
    }
    return int(n) - count;
}

LogicalProcessorSet ambient_logical_processor_set()
{
    LogicalProcessorSet result = {};        // memsets to zero
    static_assert(sizeof(result.array[0]) * CHAR_BIT == MaxLogicalProcessorsPerGroup);

    group_count = GetActiveProcessorGroupCount();
    int total_cpu_count = 0;
    cpus_per_group = (int *)malloc(sizeof(int) * group_count);
    for (WORD i = 0; i < group_count; ++i) {
        DWORD processors = GetActiveProcessorCount(i);
        cpus_per_group[i] = processors;
        for (int j = 0; j < processors; j++)
            result.set(LogicalProcessor(total_cpu_count + j));
        total_cpu_count += processors;
    }
    return result;
}

bool pin_to_logical_processor(LogicalProcessor n, const char *thread_name)
{
    if (n == LogicalProcessor(-1))
        return true;            // don't change affinity

    PROCESSOR_NUMBER processorNumber = {};
    GROUP_AFFINITY groupAffinity = {};
    processorNumber.Group = processor_group_for(n);
    processorNumber.Number = processor_in_group(n);
    groupAffinity.Group = processorNumber.Group;
    groupAffinity.Mask = KAFFINITY(1) << processorNumber.Number;

    HANDLE hThread = GetCurrentThread();
    if (!SetThreadGroupAffinity(hThread, &groupAffinity, nullptr)) {
        // failed
        return false;
    }

    return SetThreadIdealProcessorEx(hThread, &processorNumber, nullptr) == 0;
}

bool pin_to_logical_processors(CpuRange range, const char *thread_name)
{
    // nothing
    (void) range;
    (void) thread_name;
    return true;
}
