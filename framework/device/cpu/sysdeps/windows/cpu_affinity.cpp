/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <topology.h>

#include <limits>

#include <windows.h>

static constexpr unsigned MaxLogicalProcessorsPerGroup =
        std::numeric_limits<KAFFINITY>::digits;

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

bool pin_handle_to_logical_processor(LogicalProcessor n, HANDLE hThread, const char *thread_name)
{
    set_thread_name(thread_name);
    if (n == LogicalProcessor(-1))
        return true;            // don't change affinity

    PROCESSOR_NUMBER processorNumber = to_processor_number(n);
    GROUP_AFFINITY groupAffinity = {};
    groupAffinity.Group = processorNumber.Group;
    groupAffinity.Mask = KAFFINITY(1) << processorNumber.Number;

    if (!SetThreadGroupAffinity(hThread, &groupAffinity, nullptr)) {
        win32_perror("SetThreadGroupAffinity");
        return false;
    }
    return true;
}

bool pin_to_logical_processor(LogicalProcessor n, const char *thread_name)
{
    HANDLE hThread = GetCurrentThread();
    return pin_handle_to_logical_processor(n, hThread, thread_name);
}

bool pin_thread_to_logical_processor(LogicalProcessor n, tid_t thread_id, const char *thread_name)
{
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
    bool ret = pin_handle_to_logical_processor(n, hThread, thread_name);
    CloseHandle(hThread);
    return ret;
}

bool pin_to_logical_processors(DeviceRange range, const char *thread_name)
{
    set_thread_name(thread_name);
    const struct cpu_info *first_cpu = &cpu_info[range.starting_device];
    const struct cpu_info *last_cpu = &cpu_info[range.starting_device + range.device_count - 1];
    PROCESSOR_NUMBER first = to_processor_number(LogicalProcessor(first_cpu->cpu_number));
    PROCESSOR_NUMBER last = to_processor_number(LogicalProcessor(last_cpu->cpu_number));
    if (first.Group != last.Group) {
        // do nothing; if we're running on Windows 11 or Server 2022, we're
        // already a multi-group process, so leave it at that
        return true;
    }

    GROUP_AFFINITY groupAffinity = { .Mask = KAFFINITY(-1), .Group = first.Group };
    if (last.Number != MaxLogicalProcessorsPerGroup) {
        groupAffinity.Mask = KAFFINITY(1) << (last.Number + 1 - first.Number);
        groupAffinity.Mask -= 1;
    }
    groupAffinity.Mask <<= first.Number;
    if (SetThreadGroupAffinity(GetCurrentThread(), &groupAffinity, nullptr) == 0) {
        win32_perror("SetThreadGroupAffinity");
        return false;
    }
    return true;
}
