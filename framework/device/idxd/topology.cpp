/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "topology.h"
#include "sandstone_p.h"
#include "idxd_device.h"
#include "topology_idxd.hpp"

#include <accel-config/libaccel_config.h>

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

namespace {
struct AccfgCtx
{
    accfg_ctx* ctx = nullptr;

    AccfgCtx() = default;
    ~AccfgCtx() {
        if (ctx) accfg_unref(ctx);
    }
    int init() {
        if (accfg_new(&ctx) < 0) {
            return log_skip_or_print(RuntimeSkipCategory, "Failed to create AccfgCtx");
        }
        return EXIT_SUCCESS;
    }

    // non-copyable
    AccfgCtx(const AccfgCtx&) = delete;
    AccfgCtx& operator=(const AccfgCtx&) = delete;

    accfg_ctx* get() const { return ctx; }
};
} // end anonymous namespace

/// Collect all WQs visible in the system. Do not create any hierarchy of them at this point.
template <>
WorkQueueSet detect_devices<WorkQueueSet>()
{
    WorkQueueSet visible_wqs;

    AccfgCtx ctx;
    if (auto ret = ctx.init(); ret) {
        return visible_wqs;
    }

    accfg_device* device;
    accfg_device_foreach(ctx.get(), device) {
        auto device_type = accfg_device_get_type(device);
        auto device_id   = accfg_device_get_id(device);

        accfg_wq* wq;
        accfg_wq_foreach(device, wq) {
            auto& enabled = visible_wqs.emplace_back();
            enabled.device_type = device_type;
            enabled.device_id   = device_id;
            enabled.wq_id       = accfg_wq_get_id(wq);
        }
    }

    sApp->device_count = visible_wqs.size();
    sApp->user_thread_data.resize(sApp->device_count);

    return visible_wqs;
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
