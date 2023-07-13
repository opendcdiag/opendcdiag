/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <topology.h>

#include <sched.h>
#include <stdio.h>
#include <sysexits.h>

#ifdef __linux__
#include <sys/prctl.h>

static void set_thread_name(const char *thread_name)
{
    if (thread_name)
        prctl(PR_SET_NAME, thread_name);
}
#endif

LogicalProcessorSet ambient_logical_processor_set()
{
    int size = CPU_SETSIZE;
    LogicalProcessorSet result(size);
    int r = sched_getaffinity(0, result.size_bytes(), reinterpret_cast<cpu_set_t *>(result.array.data()));

    while (r != 0 && errno == EINVAL) {
        // increase the set size until it stops failing
        size *= 2;
        result.unset(LogicalProcessor(size - 1));
        r = sched_getaffinity(0, result.size_bytes(), reinterpret_cast<cpu_set_t *>(result.array.data()));
    }

    if (r != 0) {
        perror("could not get the ambient CPU set with sched_getaffinity()");
        exit(EX_OSERR);
    }

    return result;
}

bool pin_to_logical_processor(LogicalProcessor n, const char *thread_name)
{
    set_thread_name(thread_name);
    if (n == LogicalProcessor(-1))
        return true;            // don't change affinity

    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(int(n), &cpu_set);

    if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set)) {
        perror("sched_setaffinity");
        return false;
    }
    return true;
}

