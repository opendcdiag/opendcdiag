/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"
#include "idxd_config.hpp"

#include <accel-config/libaccel_config.h>

#include <limits>
#include <utility>

#include <sysexits.h>

namespace {
const char* wq_type_to_string(accfg_wq_type type)
{
    switch (type) {
    case ACCFG_WQT_KERNEL:
        return "kernel";
    case ACCFG_WQT_USER:
        return "user";
    case ACCFG_WQT_NONE:
    default:
        return nullptr;
    }
}

int read_config(idxd_config_t::config_t& into)
{
    into.clear();

    accfg_ctx* ctx = nullptr;
    assert(accfg_new(&ctx) == 0);

    accfg_device* device;
    accfg_device_foreach(ctx, device) {
        idxd_config_t::config_t::device_t dev;
        dev.device_id = accfg_device_get_id(device);
        dev.enabled = accfg_device_get_state(device) == ACCFG_DEVICE_ENABLED;
        dev.read_buffer_limit = accfg_device_get_read_buffer_limit(device);
        if (int event_log_size = accfg_device_get_event_log_size(device); event_log_size >= 0) {
            dev.event_log_size = event_log_size;
        }
        into.devices.push_back(dev);

        accfg_group* group;
        accfg_group_foreach(device, group) {
            idxd_config_t::config_t::group_t grp;
            grp.device_id = dev.device_id;
            grp.group_id = accfg_group_get_id(group);

            if (int v = accfg_group_get_read_buffers_reserved(group); v >= 0) {
                grp.read_buffers_reserved = v;
            }
            if (int v = accfg_group_get_read_buffers_allowed(group); v >= 0) {
                grp.read_buffers_allowed = v;
            }
            if (int v = accfg_group_get_use_read_buffer_limit(group); v >= 0) {
                grp.use_read_buffer_limit = v;
            }
            if (int v = accfg_group_get_traffic_class_a(group); v >= 0) {
                grp.traffic_class_a = v;
            }
            if (int v = accfg_group_get_traffic_class_b(group); v >= 0) {
                grp.traffic_class_b = v;
            }
            if (int v = accfg_group_get_desc_progress_limit(group); v >= 0) {
                grp.desc_progress_limit = v;
            }
            if (int v = accfg_group_get_batch_progress_limit(group); v >= 0) {
                grp.batch_progress_limit = v;
            }

            into.groups.push_back(grp);
        }

        accfg_engine* engine;
        accfg_engine_foreach(device, engine) {
            idxd_config_t::config_t::engine_t e;
            e.device_id = dev.device_id;
            e.engine_id = accfg_engine_get_id(engine);

            if (int group_id = accfg_engine_get_group_id(engine); group_id >= 0) {
                e.group_id = group_id;
            }

            into.engines.push_back(e);
        }

        accfg_wq* wq;
        accfg_wq_foreach(device, wq) {
            idxd_config_t::config_t::wq_t q;
            q.device_id = dev.device_id;
            q.wq_id = accfg_wq_get_id(wq);
            q.enabled = accfg_wq_is_enabled(wq) > 0;

            if (int v = accfg_wq_get_group_id(wq); v >= 0) {
                q.group_id = v;
            }
            q.wq_size = accfg_wq_get_size(wq);
            if (int v = accfg_wq_get_priority(wq); v >= 0) {
                q.priority = v;
            }
            if (int v = accfg_wq_get_threshold(wq); v >= 0) {
                q.threshold = v;
            }
            if (int v = accfg_wq_get_block_on_fault(wq); v >= 0) {
                q.block_on_fault = v;
            }

            q.max_batch_size = accfg_wq_get_max_batch_size(wq);
            q.max_transfer_size = accfg_wq_get_max_transfer_size(wq);

            if (int v = accfg_wq_get_ats_disable(wq); v >= 0) {
                q.ats_disable = v;
            }
            if (int v = accfg_wq_get_prs_disable(wq); v >= 0) {
                q.prs_disable = v;
            }

            q.mode = accfg_wq_get_mode(wq);
            q.type = accfg_wq_get_type(wq);

            if (const char* name = accfg_wq_get_devname(wq)) {
                q.name = name;
            }
            if (const char* driver_name = accfg_wq_get_driver_name(wq)) {
                q.driver_name = driver_name;
            }

            accfg_op_config op_config;
            if (auto ret = accfg_wq_get_op_config(wq, &op_config); ret == 0) {
                q.op_config = op_config;
            }
            into.wqs.push_back(std::move(q));
        }
    }

    accfg_unref(ctx);
    return EXIT_SUCCESS;
}

// differentiate between wrong user config (SKIP) and other failures when applying it (FAILURE)
int write_config(const idxd_config_t::config_t& from)
{
    accfg_ctx* ctx = nullptr;
    assert(accfg_new(&ctx) == 0);

    for (const auto& q : from.wqs) {
        accfg_device* device = accfg_ctx_device_get_by_id(ctx, q.device_id);
        if (!device) {
            log_skip(RuntimeSkipCategory, "Cannot find device %d", q.device_id);
            return EXIT_SKIP;
        }

        accfg_wq* wq = accfg_device_wq_get_by_id(device, q.wq_id);
        if (!wq) {
            log_skip(RuntimeSkipCategory, "Cannot find work queue %d on device %d", q.wq_id, q.device_id);
            return EXIT_SKIP;
        }

        if (accfg_wq_disable(wq, true) < 0) {
            log_error("Failed to disable work queue before applying configuration");
            return EXIT_FAILURE;
        }
    }

    for (const auto& d : from.devices) {
        accfg_device* device = accfg_ctx_device_get_by_id(ctx, d.device_id);
        if (!device) {
            log_skip(RuntimeSkipCategory, "Cannot find device %d", d.device_id);
            return EXIT_SKIP;
        }

        if (accfg_device_get_state(device) == ACCFG_DEVICE_ENABLED && accfg_device_disable(device, true) < 0) {
            log_error("Failed to disable device before applying configuration");
            return EXIT_FAILURE;
        }
    }

    for (const auto& d : from.devices) {
        accfg_device* device = accfg_ctx_device_get_by_id(ctx, d.device_id);
        if (!device) {
            log_skip(RuntimeSkipCategory, "Cannot find device %d", d.device_id);
            return EXIT_SKIP;
        }

        if (accfg_device_set_read_buffer_limit(device, d.read_buffer_limit) < 0) {
            log_error("Failed to set device read buffer limit");
            return EXIT_FAILURE;
        }
        if (d.event_log_size >= 0 && accfg_device_set_event_log_size(device, d.event_log_size) < 0) {
            log_error("Failed to set device event log size");
            return EXIT_FAILURE;
        }
    }

    for (const auto& g : from.groups) {
        accfg_device* device = accfg_ctx_device_get_by_id(ctx, g.device_id);
        if (!device) {
            log_skip(RuntimeSkipCategory, "Cannot find device %d", g.device_id);
            return EXIT_SKIP;
        }

        accfg_group* group = accfg_device_group_get_by_id(device, g.group_id);
        if (!group) {
            log_skip(RuntimeSkipCategory, "Cannot find group %d on device %d", g.group_id, g.device_id);
            return EXIT_SKIP;
        }

        if (g.read_buffers_reserved >= 0 && accfg_group_set_read_buffers_reserved(group, g.read_buffers_reserved) < 0) {
            log_error("Failed to set group read buffers reserved");
            return EXIT_FAILURE;
        }
        if (g.read_buffers_allowed >= 0 && accfg_group_set_read_buffers_allowed(group, g.read_buffers_allowed) < 0) {
            log_error("Failed to set group read buffers allowed");
            return EXIT_FAILURE;
        }
        if (g.use_read_buffer_limit >= 0 && accfg_group_set_use_read_buffer_limit(group, g.use_read_buffer_limit) < 0) {
            log_error("Failed to set group use read buffer limit");
            return EXIT_FAILURE;
        }
        if (g.traffic_class_a >= 0 && accfg_group_set_traffic_class_a(group, g.traffic_class_a) < 0) {
            log_error("Failed to set group traffic class a");
            return EXIT_FAILURE;
        }
        if (g.traffic_class_b >= 0 && accfg_group_set_traffic_class_b(group, g.traffic_class_b) < 0) {
            log_error("Failed to set group traffic class b");
            return EXIT_FAILURE;
        }
        if (g.desc_progress_limit >= 0 && accfg_group_set_desc_progress_limit(group, g.desc_progress_limit) < 0) {
            log_error("Failed to set group descriptor progress limit");
            return EXIT_FAILURE;
        }
        if (g.batch_progress_limit >= 0 && accfg_group_set_batch_progress_limit(group, g.batch_progress_limit) < 0) {
            log_error("Failed to set group batch progress limit");
            return EXIT_FAILURE;
        }
    }

    for (const auto& e : from.engines) {
        accfg_device* device = accfg_ctx_device_get_by_id(ctx, e.device_id);
        if (!device) {
            log_skip(RuntimeSkipCategory, "Cannot find device %d", e.device_id);
            return EXIT_SKIP;
        }

        accfg_engine* engine = accfg_device_engine_get_by_id(device, e.engine_id);
        if (!engine) {
            log_skip(RuntimeSkipCategory, "Cannot find engine %d on device %d", e.engine_id, e.device_id);
            return EXIT_SKIP;
        }

        if (e.group_id >= 0 && accfg_engine_set_group_id(engine, e.group_id) < 0) {
            log_error("Failed to set engine group id");
            return EXIT_FAILURE;
        }
    }

    for (const auto& q : from.wqs) {
        accfg_device* device = accfg_ctx_device_get_by_id(ctx, q.device_id);
        if (!device) {
            log_skip(RuntimeSkipCategory, "Cannot find device %d", q.device_id);
            return EXIT_SKIP;
        }

        accfg_wq* wq = accfg_device_wq_get_by_id(device, q.wq_id);
        if (!wq) {
            log_skip(RuntimeSkipCategory, "Cannot find work queue %d on device %d", q.wq_id, q.device_id);
            return EXIT_SKIP;
        }

        if (q.group_id >= 0 && accfg_wq_set_group_id(wq, q.group_id) < 0) {
            log_error("Failed to set work queue group id");
            return EXIT_FAILURE;
        }

        if (q.mode != ACCFG_WQ_MODE_UNKNOWN && accfg_wq_set_mode(wq, q.mode) < 0) {
            log_error("Failed to set work queue mode");
            return EXIT_FAILURE;
        }

        if (const char* type = wq_type_to_string(q.type); type && accfg_wq_set_str_type(wq, type) < 0) {
            log_error("Failed to set work queue type");
            return EXIT_FAILURE;
        }

        if (!q.name.empty() && accfg_wq_set_str_name(wq, q.name.c_str()) < 0) {
            log_error("Failed to set work queue name");
            return EXIT_FAILURE;
        }
        if (!q.driver_name.empty() && accfg_wq_set_str_driver_name(wq, q.driver_name.c_str()) < 0) {
            log_error("Failed to set work queue driver");
            return EXIT_FAILURE;
        }

        if (accfg_wq_set_size(wq, static_cast<int>(q.wq_size)) < 0) {
            log_error("Failed to set work queue size");
            return EXIT_FAILURE;
        }
        if (accfg_wq_set_max_batch_size(wq, static_cast<int>(q.max_batch_size)) < 0) {
            log_error("Failed to set work queue max batch size");
            return EXIT_FAILURE;
        }
        if (accfg_wq_set_max_transfer_size(wq, q.max_transfer_size) < 0) {
            log_error("Failed to set work queue max transfer size");
            return EXIT_FAILURE;
        }

        if (q.priority >= 0 && accfg_wq_set_priority(wq, q.priority) < 0) {
            log_error("Failed to set work queue priority");
            return EXIT_FAILURE;
        }
        if (q.threshold >= 0 && accfg_wq_set_threshold(wq, q.threshold) < 0) {
            log_error("Failed to set work queue threshold");
            return EXIT_FAILURE;
        }
        if (q.block_on_fault >= 0 && accfg_wq_set_block_on_fault(wq, q.block_on_fault) < 0) {
            log_error("Failed to set work queue block on fault");
            return EXIT_FAILURE;
        }
        if (q.ats_disable >= 0 && accfg_wq_set_ats_disable(wq, q.ats_disable) < 0) {
            log_error("Failed to set work queue ats disable");
            return EXIT_FAILURE;
        }
        if (q.prs_disable >= 0 && accfg_wq_set_prs_disable(wq, q.prs_disable) < 0) {
            log_error("Failed to set work queue prs disable");
            return EXIT_FAILURE;
        }

        if (q.op_config && accfg_wq_set_op_config(wq, const_cast<accfg_op_config*>(&*q.op_config)) < 0) {
            log_error("Failed to set work queue operation configuration");
            return EXIT_FAILURE;
        }
    }

    for (const auto& d : from.devices) {
        accfg_device* device = accfg_ctx_device_get_by_id(ctx, d.device_id);
        if (!device) {
            log_skip(RuntimeSkipCategory, "Cannot find device %d", d.device_id);
            return EXIT_SKIP;
        }

        if (d.enabled) {
            if (accfg_device_enable(device) < 0) {
                log_error("Failed to enable device");
                return EXIT_FAILURE;
            }
        } else if (accfg_device_disable(device, true) < 0) {
            log_error("Failed to disable device");
            return EXIT_FAILURE;
        }
    }

    for (const auto& q : from.wqs) {
        accfg_device* device = accfg_ctx_device_get_by_id(ctx, q.device_id);
        accfg_wq* wq = device ? accfg_device_wq_get_by_id(device, q.wq_id) : nullptr;
        if (!wq) {
            log_skip(RuntimeSkipCategory, "Cannot find work queue %d on device %d", q.wq_id, q.device_id);
            return EXIT_SKIP;
        }

        bool device_should_be_enabled = false;
        bool found_device = false;
        for (const auto& d : from.devices) {
            if (d.device_id == q.device_id) {
                device_should_be_enabled = d.enabled;
                found_device = true;
                break;
            }
        }
        if (!found_device) {
            log_skip(RuntimeSkipCategory, "Cannot find final state for device %d", q.device_id);
            return EXIT_SKIP;
        }

        if (q.enabled && !device_should_be_enabled) {
            log_skip(RuntimeSkipCategory, "Inconsistent configuration: WQ %d.%d enabled while device %d is disabled",
                             q.device_id, q.wq_id, q.device_id);
            return EXIT_SKIP;
        }

        if (q.enabled) {
            if (accfg_wq_enable(wq) < 0) {
                log_error("Failed to enable work queue");
                return EXIT_FAILURE;
            }
        } else if (accfg_wq_disable(wq, true) < 0) {
            log_error("Failed to disable work queue");
            return EXIT_FAILURE;
        }
    }

    accfg_unref(ctx);
    return EXIT_SUCCESS;
}
} // end anonymous namespace

int idxd_config_t::apply_desired()
{
    // save snapshot of current system state
    auto ret = read_config(previous);
    if (ret != EXIT_SUCCESS) {
        return ret;
    }

    // apply desired config
    ret = write_config(desired);
    if (ret == EXIT_SUCCESS) {
        return EXIT_SUCCESS;
    }

    // best-effort rollback if applying desired config failed
    if (write_config(previous) != EXIT_SUCCESS) {
        // non-recoverable state...
        fprintf(stderr, "Failed to apply desired IDXD configuration and failed to restore previous configuration");
        _exit(EX_CONFIG);
    } else {
        log_warning("Failed to apply desired IDXD configuration; restored previous configuration");
    }

    return ret;
}

int idxd_config_t::restore_previous()
{
    return write_config(previous);
}
