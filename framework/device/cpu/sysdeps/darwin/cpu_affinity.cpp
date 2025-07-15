/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "topology.h"

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

bool pin_to_logical_processors(DeviceRange range, const char *thread_name)
{
    // nothing
    (void) range;
    (void) thread_name;
    return true;
}
