/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_IDXD_CONFIG_HPP
#define INC_IDXD_CONFIG_HPP

#include <accel-config/libaccel_config.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct idxd_config_t
{
    int apply_desired();
    int restore_previous();

    struct config_t
    {
        struct device_t
        {
            int device_id = -1;
            bool enabled = false;
            unsigned int read_buffer_limit = 0;
            int event_log_size = -1;
        };

        struct group_t
        {
            int device_id = -1;
            int group_id = -1;
            int read_buffers_reserved = -1;
            int read_buffers_allowed = -1;
            int use_read_buffer_limit = -1;
            int traffic_class_a = -1;
            int traffic_class_b = -1;
            int desc_progress_limit = -1;
            int batch_progress_limit = -1;
        };

        struct engine_t
        {
            int device_id = -1;
            int engine_id = -1;
            int group_id = -1;
        };

        struct wq_t
        {
            int device_id = -1;
            int wq_id = -1;
            bool enabled = false;
            int group_id = -1;
            uint64_t wq_size = 0;
            int threshold = -1;
            int priority = -1;
            int block_on_fault = -1;
            unsigned int max_batch_size = 0;
            uint64_t max_transfer_size = 0;
            int ats_disable = -1;
            int prs_disable = -1;
            accfg_wq_mode mode = ACCFG_WQ_MODE_UNKNOWN;
            accfg_wq_type type = ACCFG_WQT_NONE;
            std::string name = {};
            std::string driver_name = {};
            std::optional<accfg_op_config> op_config = {};
        };

        std::vector<device_t> devices;
        std::vector<group_t> groups;
        std::vector<engine_t> engines;
        std::vector<wq_t> wqs;

        void clear()
        {
            devices.clear();
            groups.clear();
            engines.clear();
            wqs.clear();
        }
    };

    const config_t desired;
    config_t previous;
};

inline idxd_config_t* make_static_idxd_config(const idxd_config_t& config) {
    static const auto stored = config;
    return const_cast<idxd_config_t*>(&stored);
}

// Macro for creating configs in-place at the test declaration stage. Can't use GCC
// compound literal due to std::vector in idxd_config_t (must be constructed at runtime).
#define DECLARE_TEST_IDXD_CONFIG(...) \
    make_static_idxd_config({ __VA_ARGS__ })

#endif // INC_IDXD_CONFIG_HPP
