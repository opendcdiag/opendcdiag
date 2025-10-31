/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "topology.h"
#include "sandstone_p.h"

struct gpu_info_t *cpu_info = nullptr;

int num_packages()
{
    // Return fixed 1
    // TODO: reconsider what to return
    return 1;
}

std::unique_ptr<DeviceScheduler> make_rescheduler(std::string_view mode)
{
    return nullptr;
}

void apply_deviceset_param(char *param)
{

}

std::string build_failure_mask_for_topology(const struct test* test)
{
    return {};
}

uint32_t mixin_from_device_info(int thread_num)
{
    return thread_num;
}

void print_temperature_of_device()
{

}

template <>
DeviceRange detect_devices<DeviceRange>()
{
    sApp->thread_count = 1;
    return DeviceRange{};
}

template <>
void setup_devices<DeviceRange>(const DeviceRange &enabled_devices)
{

}

void restrict_topology(DeviceRange range)
{

}

void analyze_test_failures_for_topology(const struct test *test, const PerThreadFailures &per_thread_failures)
{

}

void slice_plan_init(int max_cores_per_slice)
{
    std::vector plan = { DeviceRange{ 0, thread_count() } };
    sApp->slice_plans.plans.fill(plan);
}
