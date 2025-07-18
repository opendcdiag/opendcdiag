/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <topology.h>

#include <sched.h>
#include <sysexits.h>


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

