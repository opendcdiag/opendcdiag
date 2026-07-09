/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"
#include "idxd_config.hpp"

namespace {
idxd_config_t::config_t user_default_dsa_config()
{
    idxd_config_t::config_t config = {
        .devices = {
            {
                .device_id = 0,
                .enabled = true,
            },
        },
    };

    for (int engine_id = 0; engine_id < 4; ++engine_id)
        config.engines.push_back({
            .device_id = 0,
            .engine_id = engine_id,
            .group_id = 0,
        });

    for (int wq_id = 0; wq_id < 8; ++wq_id)
        config.wqs.push_back({
            .device_id = 0,
            .wq_id = wq_id,
            .enabled = true,
            .group_id = 0,
            .wq_size = 16,
            .threshold = 16,
            .priority = 10,
            .block_on_fault = 1,
            .mode = ACCFG_WQ_SHARED,
            .type = ACCFG_WQT_USER,
            .name = "user_default_wq",
            .driver_name = "user",
        });

    return config;
}

// This object has static storage duration, so tests can point to it safely.
idxd_config_t dummy_idxd_config = {
    .desired = user_default_dsa_config(),
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
        .desired = user_default_dsa_config()
    ),
END_DECLARE_TEST
