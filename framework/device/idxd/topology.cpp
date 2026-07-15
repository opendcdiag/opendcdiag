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

namespace {
constexpr unsigned IDXD_OPCODE_NOOP              = 0x00;
constexpr unsigned IDXD_OPCODE_BATCH             = 0x01;
constexpr unsigned IDXD_OPCODE_DRAIN             = 0x02;
constexpr unsigned IDXD_OPCODE_MEMMOVE           = 0x03;
constexpr unsigned IDXD_OPCODE_FILL              = 0x04;
constexpr unsigned IDXD_OPCODE_COMPARE           = 0x05;
constexpr unsigned IDXD_OPCODE_COMPARE_PAT       = 0x06;
constexpr unsigned IDXD_OPCODE_CREATE_DELTA_REC  = 0x07;
constexpr unsigned IDXD_OPCODE_APPLY_DELTA_REC   = 0x08;
constexpr unsigned IDXD_OPCODE_DUAL_CAST         = 0x09;
constexpr unsigned IDXD_OPCODE_CRC_GEN           = 0x10;
constexpr unsigned IDXD_OPCODE_COPY_WITH_CRC_GEN = 0x11;
constexpr unsigned IDXD_OPCODE_DIF_CHECK         = 0x12;
constexpr unsigned IDXD_OPCODE_DIF_INSERT        = 0x13;
constexpr unsigned IDXD_OPCODE_DIF_STRIP         = 0x14;
constexpr unsigned IDXD_OPCODE_DIF_UPDATE        = 0x15;
constexpr unsigned IDXD_OPCODE_CACHE_FLUSH       = 0x20;
constexpr unsigned IDXD_OPCODE_DECOMPRESS        = 0x42;
constexpr unsigned IDXD_OPCODE_COMPRESS          = 0x43;
constexpr unsigned IDXD_OPCODE_CRC64             = 0x44;
constexpr unsigned IDXD_OPCODE_SCAN              = 0x50;
constexpr unsigned IDXD_OPCODE_EXTRACT           = 0x52;
constexpr unsigned IDXD_OPCODE_SELECT            = 0x53;
constexpr unsigned IDXD_OPCODE_EXPAND            = 0x56;
} // namespace

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

int AccfgCtx::init()
{
    if (accfg_new(&ctx) < 0) {
        return log_skip_or_print(RuntimeSkipCategory, "Failed to initialize accfg_ctx");
    }
    return EXIT_SUCCESS;
}

static device_features_t detect_features(accfg_device* device)
{
    device_features_t features = 0;

    unsigned int ver = accfg_device_get_version(device);
    accfg_device_type dev_type = accfg_device_get_type(device);
    if (dev_type == ACCFG_DEVICE_DSA) {
        features |= device_feature_dsa;
        if (ver >= ACCFG_DEVICE_VERSION_1)
            features |= device_feature_dsa_v1;
        if (ver >= ACCFG_DEVICE_VERSION_2)
            features |= device_feature_dsa_v2;
        if (ver > ACCFG_DEVICE_VERSION_2)
            features |= device_feature_dsa_v3;
    } else if (dev_type == ACCFG_DEVICE_IAX) {
        features |= device_feature_iax;
        if (ver >= ACCFG_DEVICE_VERSION_1)
            features |= device_feature_iax_v1;
        if (ver >= ACCFG_DEVICE_VERSION_2)
            features |= device_feature_iax_v2;
        if (ver > ACCFG_DEVICE_VERSION_2)
            features |= device_feature_iax_v3;
    }

    accfg_op_cap op_cap = {};
    if (accfg_device_get_op_cap(device, &op_cap) == 0) {
        if (dev_type == ACCFG_DEVICE_DSA) {
            if (has_opcode(op_cap, IDXD_OPCODE_NOOP))
                features |= device_feature_dsa_op_noop;
            if (has_opcode(op_cap, IDXD_OPCODE_BATCH))
                features |= device_feature_dsa_op_batch;
            if (has_opcode(op_cap, IDXD_OPCODE_DRAIN))
                features |= device_feature_dsa_op_drain;
            if (has_opcode(op_cap, IDXD_OPCODE_MEMMOVE))
                features |= device_feature_op_memmove;
            if (has_opcode(op_cap, IDXD_OPCODE_FILL))
                features |= device_feature_op_fill;
            if (has_opcode(op_cap, IDXD_OPCODE_COMPARE))
                features |= device_feature_op_compare;
            if (has_opcode(op_cap, IDXD_OPCODE_COMPARE_PAT))
                features |= device_feature_op_compare_pat;
            if (has_opcode(op_cap, IDXD_OPCODE_CRC_GEN))
                features |= device_feature_op_crc_gen;
            if (has_opcode(op_cap, IDXD_OPCODE_COPY_WITH_CRC_GEN))
                features |= device_feature_op_copy_with_crc_gen;
            if (has_opcode(op_cap, IDXD_OPCODE_DIF_CHECK))
                features |= device_feature_op_dif_check;
            if (has_opcode(op_cap, IDXD_OPCODE_DIF_INSERT))
                features |= device_feature_op_dif_insert;
            if (has_opcode(op_cap, IDXD_OPCODE_DIF_STRIP))
                features |= device_feature_op_dif_strip;
            if (has_opcode(op_cap, IDXD_OPCODE_DIF_UPDATE))
                features |= device_feature_op_dif_update;
            if (has_opcode(op_cap, IDXD_OPCODE_CACHE_FLUSH))
                features |= device_feature_op_cache_flush;
            if (has_opcode(op_cap, IDXD_OPCODE_CRC64))
                features |= device_feature_op_crc64;
        } else if (dev_type == ACCFG_DEVICE_IAX) {
            if (has_opcode(op_cap, IDXD_OPCODE_NOOP))
                features |= device_feature_iax_op_noop;
            if (has_opcode(op_cap, IDXD_OPCODE_BATCH))
                features |= device_feature_iax_op_batch;
            if (has_opcode(op_cap, IDXD_OPCODE_DRAIN))
                features |= device_feature_iax_op_drain;
            if (has_opcode(op_cap, IDXD_OPCODE_DUAL_CAST))
                features |= device_feature_op_dual_cast;
            if (has_opcode(op_cap, IDXD_OPCODE_CREATE_DELTA_REC))
                features |= device_feature_op_create_delta;
            if (has_opcode(op_cap, IDXD_OPCODE_APPLY_DELTA_REC))
                features |= device_feature_op_apply_delta;
            if (has_opcode(op_cap, IDXD_OPCODE_SCAN))
                features |= device_feature_op_scan;
            if (has_opcode(op_cap, IDXD_OPCODE_EXTRACT))
                features |= device_feature_op_extract;
            if (has_opcode(op_cap, IDXD_OPCODE_SELECT))
                features |= device_feature_op_select;
            if (has_opcode(op_cap, IDXD_OPCODE_EXPAND))
                features |= device_feature_op_expand;
            if (has_opcode(op_cap, IDXD_OPCODE_COMPRESS))
                features |= device_feature_op_compress;
            if (has_opcode(op_cap, IDXD_OPCODE_DECOMPRESS))
                features |= device_feature_op_decompress;
        }
    }

    return features;
}

device_features_t detect_features()
{
    AccfgCtx ctx;
    if (auto ret = ctx.init(); ret)
        return 0;

    device_features_t features = 0;
    accfg_device* device;
    accfg_device_foreach(ctx.get(), device) {
        features |= detect_features(device);
    }

    return features;
}

/// Collect all WQs visible in the system. Do not create any hierarchy of them at this point.
/// It also populates device_features.
template <>
WorkQueueSet detect_devices<WorkQueueSet>()
{
    WorkQueueSet res;

    if (auto ret = res.ctx.init(); ret) {
        return res;
    }

    device_features = 0; // reset

    accfg_device* device;
    accfg_device_foreach(res.ctx.get(), device) {
        device_features |= detect_features(device);
        auto device_type = accfg_device_get_type(device);
        auto device_id   = accfg_device_get_id(device);

        accfg_wq* wq;
        accfg_wq_foreach(device, wq) {
            auto& v = res.visible_wqs.emplace_back();
            v.device_handle = device;
            v.device_type = device_type;
            v.device_id   = device_id;
            v.wq_id       = accfg_wq_get_id(wq);
        }
    }

    sApp->device_count = res.visible_wqs.size();
    sApp->user_thread_data.resize(sApp->device_count);

    return res;
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
