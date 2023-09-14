/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <topology.h>

#include <limits>

#include <windows.h>

static constexpr unsigned MaxLogicalProcessorsPerGroup =
        std::numeric_limits<KAFFINITY>::digits;

static constexpr LogicalProcessor from_processor_number(PROCESSOR_NUMBER n)
{
    return LogicalProcessor(n.Group * MaxLogicalProcessorsPerGroup + n.Number);
}

static constexpr PROCESSOR_NUMBER to_processor_number(LogicalProcessor lp)
{
    PROCESSOR_NUMBER n = {};
    n.Group = unsigned(lp) / MaxLogicalProcessorsPerGroup;
    n.Number = unsigned(lp) % MaxLogicalProcessorsPerGroup;
    return n;
}

static void set_thread_name(const char *thread_name)
{
    (void) thread_name;
}

LogicalProcessorSet ambient_logical_processor_set()
{
    LogicalProcessorSet result = {};        // memsets to zero
    static_assert(sizeof(result.array[0]) * CHAR_BIT == MaxLogicalProcessorsPerGroup);

    WORD group_count = GetActiveProcessorGroupCount();
    PROCESSOR_NUMBER number = {};
    for (number.Group = 0; number.Group < group_count; ++number.Group) {
        DWORD processors = GetActiveProcessorCount(number.Group);
        for (number.Number = 0; number.Number < processors; number.Number++)
            result.set(from_processor_number(number));
    }
    return result;
}

bool pin_to_logical_processor(LogicalProcessor n, const char *thread_name)
{
    set_thread_name(thread_name);
    if (n == LogicalProcessor(-1))
        return true;            // don't change affinity

    PROCESSOR_NUMBER processorNumber = to_processor_number(n);
    GROUP_AFFINITY groupAffinity = {};
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
