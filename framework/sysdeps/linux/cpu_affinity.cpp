/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <topology.h>

#include <sched.h>
#include <stdio.h>
#include <sys/prctl.h>

static_assert(CPU_SETSIZE >= LogicalProcessorSet::Size);

LogicalProcessorSet ambient_logical_processor_set()
{
    LogicalProcessorSet result;
    if (sched_getaffinity(0, sizeof(result.array), reinterpret_cast<cpu_set_t *>(result.array)) != 0)
        result.clear();
    return result;
}

bool pin_to_logical_processor(LogicalProcessor n, const char *thread_name)
{
    if (thread_name)
        prctl(PR_SET_NAME, thread_name);

    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(int(n), &cpu_set);

    if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set)) {
        perror("sched_setaffinity");
        return false;
    }
    return true;
}

