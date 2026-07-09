/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"
#include "idxd_config.hpp"

namespace {
// This object has static storage duration, so tests can point to it safely.
idxd_config_t dummy_idxd_config = {
    .desired = {
        .devices = {
            {
                .device_id = 0,
                .enabled = true,
                .read_buffer_limit = 8,
            },
        },
        .wqs = {
            {
                .device_id = 0,
                .wq_id = 0,
                .enabled = true,
                .group_id = 0,
                .priority = 10,
                .max_batch_size = 32,
                .mode = ACCFG_WQ_SHARED,
                .type = ACCFG_WQT_USER,
            },
        },
    },
};
} // end anonymous namespace

DECLARE_TEST(idxd_dummy_config, "Dummy IDXD test showing static idxd_config_t wiring")
    .test_run = [](struct test*, int) { return EXIT_SUCCESS; },
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_BETA,
    .flags = test_schedule_sequential | test_in_parent,
    .idxd_config = &dummy_idxd_config,
END_DECLARE_TEST

DECLARE_TEST(idxd_dummy_config_inplace, "Dummy IDXD test showing in-place idxd_config_t wiring")
    .test_run = [](struct test*, int) { return EXIT_SUCCESS; },
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_BETA,
    .flags = test_schedule_sequential | test_in_parent,
    .idxd_config = DECLARE_TEST_IDXD_CONFIG(
        .desired = {
            .devices = {
                {
                    .device_id = 0,
                    .enabled = false,
                },
            },
        }
    ),
END_DECLARE_TEST