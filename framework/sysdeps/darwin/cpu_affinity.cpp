/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "topology.h"

#include <stdio.h>
#include <unistd.h>

LogicalProcessorSet ambient_logical_processor_set()
{
    static bool warning_printed = []() {
        fprintf(stderr, "# WARNING: this OS does not support thread affinity. Results may be unreliable.\n");
        return true;
    }();
    (void) warning_printed;

    // assume all CPUs
    LogicalProcessorSet result = {};
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    for (long i = 0; i < n; ++i)
        result.set(LogicalProcessor(i));
    return result;
}

bool pin_to_logical_processor(LogicalProcessor n, const char *thread_name)
{
    // simulate success
    (void) n;
    (void) thread_name;
    return true;
}

bool pin_thread_to_logical_processor(LogicalProcessor n, tid_t thread_id, const char *thread_name)
{
    // simulate success
    (void) n;
    (void) thread_name;
    (void) thread_id;
    return true;
}

bool pin_to_logical_processors(CpuRange range, const char *thread_name)
{
    // nothing
    (void) range;
    (void) thread_name;
    return true;
}
