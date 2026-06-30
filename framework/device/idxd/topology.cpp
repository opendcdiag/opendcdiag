/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "topology.h"
#include "sandstone_p.h"
#include "idxd_device.h"
#include "topology_idxd.hpp"

struct wq_info_t *device_info = nullptr;

int num_packages()
{
    return 1;
}

void make_rescheduler(RescheduleMode mode)
{
}

void apply_deviceset_param(const char *param)
{
}

std::string build_failure_mask_for_topology(const struct test* test)
{
    return {};
}

uint32_t mixin_from_device_info(int thread_num)
{
    return 1;
}

void print_temperature_of_device()
{
}

template <>
WorkQueueSet detect_devices<WorkQueueSet>()
{
    WorkQueueSet enabled_devices;

    // ...
    // ...
    // ...

    return enabled_devices;
}

void create_mock_topology(const char *topo)
{
}

template <>
void setup_devices<WorkQueueSet>(const WorkQueueSet &enabled_devices)
{
}

void restrict_topology(DeviceRange range)
{
}

void rebuild_topology()
{
}

void analyze_test_failures_for_topology(const struct test *test, const PerThreadFailures &per_thread_failures)
{
}

void slice_plan_init_for_device(SlicePlans::SlicesArray& plans, int max_cores_per_slice)
{
    SlicePlans::Slices plan = { SlicePlans::Slice{ DeviceRange{ 0, device_count() }, {} } };
    plans.fill(plan);
}

int slice_plan_init_for_threads(SlicePlans::SlicesArray& plans, ThreadRatio ratio_type)
{
    for (auto &plan : plans) {
        for (auto &slice : plan)
            slice.thread_range = { slice.device_range.starting_device, slice.device_range.device_count }; // 1:1 for now...
    }
    return device_count();
}
