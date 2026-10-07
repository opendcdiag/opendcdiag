/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IDXD_DEFAULT_CONFIG_H
#define IDXD_DEFAULT_CONFIG_H

#include "idxd_config.hpp"

inline const idxd_config_t dsa_default_config = {
    .desired = {
        .templates = {{
            .device_type = ACCFG_DEVICE_DSA,
            .device = idxd_config_t::config_t::device_t{ .enabled = true },
            .group = idxd_config_t::config_t::group_t{},
            .engine = idxd_config_t::config_t::engine_t{ .group_id = 0 },
            .wq = idxd_config_t::config_t::wq_t{
                .enabled = true,
                .group_id = 0,
                .priority = 10,
                .block_on_fault = 1,
                .ats_disable = 0,
                .prs_disable = 1,
                .mode = ACCFG_WQ_SHARED,
                .type = ACCFG_WQT_USER,
                .name = "user_default_wq",
                .driver_name = "user",
            },
        }},
    },
};

inline const idxd_config_t iax_default_config = {
    .desired = {
        .templates = {{
            .device_type = ACCFG_DEVICE_IAX,
            .device = idxd_config_t::config_t::device_t{ .enabled = true },
            .group = idxd_config_t::config_t::group_t{},
            .engine = idxd_config_t::config_t::engine_t{ .group_id = 0 },
            .wq = idxd_config_t::config_t::wq_t{
                .enabled = true,
                .group_id = 0,
                .priority = 10,
                .block_on_fault = 1,
                .ats_disable = 0,
                .prs_disable = 1,
                .mode = ACCFG_WQ_SHARED,
                .type = ACCFG_WQT_USER,
                .name = "user_default_wq",
                .driver_name = "user",
            },
        }},
    },
};

#endif
