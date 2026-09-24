/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"
#include "sandstone_p.h"
#include "idxd_config.hpp"

#include <accel-config/libaccel_config.h>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <utility>

#include <sysexits.h>
#include <stdarg.h>

namespace fs = std::filesystem;

namespace {
using boost::property_tree::ptree;

std::string create_filtered_message_string(const char *fmt, va_list va)
{
    std::string s = vstdprintf(fmt, va);
    for (char &c : s) {
        // filter any non-US-ASCII character from the message
        // (this includes any non-terminating NUL)
        if (c < 0x20 || c > 0x7e) {
            if (c != '\n' && c != '\t')
                c = '?';
        }
    }
    return s;
}

void log_error_or_print(const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    std::string msg = create_filtered_message_string(fmt, va);
    va_end(va);

    if (!sApp->shmem) {
        fprintf(stderr, "error: %s\n", msg.c_str());
    } else if (logging_in_test) {
        log_error("%s", msg.c_str());
    } else {
        logging_printf(LOG_LEVEL_ERROR, "error: %s\n", msg.c_str());
    }
}

void log_warning_or_print(const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    std::string msg = create_filtered_message_string(fmt, va);
    va_end(va);

    if (!sApp->shmem) {
        fprintf(stderr, "warning: %s\n", msg.c_str());
    } else if (logging_in_test) {
        log_warning("%s", msg.c_str());
    } else {
        logging_printf(LOG_LEVEL_ERROR, "warning: %s\n", msg.c_str());
    }
}

int parse_number(std::string_view value, const std::string& path)
{
    size_t parsed = 0;
    int result;
    try {
        result = std::stoi(std::string(value), &parsed);
    } catch (const std::exception&) {
        throw std::runtime_error("invalid numeric ID at " + path);
    }
    if (parsed != value.size())
        throw std::runtime_error("invalid numeric ID at " + path);
    return result;
}

std::pair<int, int> parse_pair(std::string_view value, std::string_view prefix, const std::string& path)
{
    if (!value.starts_with(prefix))
        throw std::runtime_error("invalid name at " + path + ": " + std::string(value));
    const auto ids = value.substr(prefix.size());
    const auto separator = ids.find('.');
    if (separator == std::string_view::npos)
        throw std::runtime_error("invalid name at " + path + ": " + std::string(value));
    return { parse_number(ids.substr(0, separator), path),
             parse_number(ids.substr(separator + 1), path) };
}

template <typename T>
void set_value(const ptree& node, const char* key, T& value)
{
    if (auto item = node.get_optional<T>(key))
        value = *item;
}

void set_optional_value(const ptree& node, const char* key, std::optional<unsigned int>& value)
{
    if (auto item = node.get_optional<unsigned int>(key))
        value = *item;
}

void set_optional_value(const ptree& node, const char* key, std::optional<uint64_t>& value)
{
    if (auto item = node.get_optional<uint64_t>(key))
        value = *item;
}

accfg_wq_mode parse_mode(const ptree& node)
{
    const auto value = node.get_optional<std::string>("mode");
    if (!value)
        return ACCFG_WQ_MODE_UNKNOWN;
    if (*value == "shared")
        return ACCFG_WQ_SHARED;
    if (*value == "dedicated")
        return ACCFG_WQ_DEDICATED;
    throw std::runtime_error("unsupported work queue mode: " + *value);
}

accfg_wq_type parse_type(const ptree& node)
{
    const auto value = node.get_optional<std::string>("type");
    if (!value)
        return ACCFG_WQT_NONE;
    if (*value == "kernel")
        return ACCFG_WQT_KERNEL;
    if (*value == "user")
        return ACCFG_WQT_USER;
    throw std::runtime_error("unsupported work queue type: " + *value);
}

void parse_workqueue(const ptree& node, int device_id, int group_id,
                     idxd_config_t::config_t& result, const std::string& path)
{
    const auto name = node.get_optional<std::string>("dev");
    if (!name)
        throw std::runtime_error("missing dev at " + path);
    const auto [parsed_device_id, wq_id] = parse_pair(*name, "wq", path);
    if (parsed_device_id != device_id)
        throw std::runtime_error("device mismatch at " + path);

    idxd_config_t::config_t::wq_t wq;
    wq.device_id = device_id;
    wq.wq_id = wq_id;
    wq.enabled = true;
    wq.group_id = group_id;
    wq.type = ACCFG_WQT_USER;
    wq.name = "user_default_wq";
    wq.driver_name = "user";
    set_value(node, "group_id", wq.group_id);
    set_optional_value(node, "size", wq.wq_size);
    set_value(node, "priority", wq.priority);
    set_value(node, "threshold", wq.threshold);
    set_value(node, "block_on_fault", wq.block_on_fault);
    set_optional_value(node, "max_batch_size", wq.max_batch_size);
    set_optional_value(node, "max_transfer_size", wq.max_transfer_size);
    set_value(node, "ats_disable", wq.ats_disable);
    set_value(node, "prs_disable", wq.prs_disable);
    wq.mode = parse_mode(node);
    wq.type = parse_type(node);
    wq.name = node.get("name", wq.name);
    wq.driver_name = node.get("driver_name", wq.driver_name);
    result.wqs.push_back(std::move(wq));
}

void parse_device(const ptree& node, idxd_config_t::config_t& result, const std::string& path)
{
    const auto name = node.get_optional<std::string>("dev");
    if (!name)
        throw std::runtime_error("missing dev at " + path);

    int device_id;
    if (name->starts_with("dsa"))
        device_id = parse_number(std::string_view(*name).substr(3), path);
    else if (name->starts_with("iax"))
        device_id = parse_number(std::string_view(*name).substr(3), path);
    else
        throw std::runtime_error("unsupported device name at " + path + ": " + *name);

    idxd_config_t::config_t::device_t device;
    device.device_id = device_id;
    device.enabled = true;
    set_value(node, "read_buffer_limit", device.read_buffer_limit);
    set_value(node, "event_log_size", device.event_log_size);
    result.devices.push_back(device);

    if (auto groups = node.get_child_optional("groups")) {
        for (const auto& entry : *groups) {
            const auto group_name = entry.second.get_optional<std::string>("dev");
            if (!group_name)
                throw std::runtime_error("missing group dev at " + path);
            const auto [parsed_device_id, group_id] = parse_pair(*group_name, "group", path);
            if (parsed_device_id != device_id)
                throw std::runtime_error("device mismatch in group at " + path);

            idxd_config_t::config_t::group_t group;
            group.device_id = device_id;
            group.group_id = group_id;
            set_value(entry.second, "read_buffers_reserved", group.read_buffers_reserved);
            set_value(entry.second, "read_buffers_allowed", group.read_buffers_allowed);
            set_value(entry.second, "use_read_buffer_limit", group.use_read_buffer_limit);
            set_value(entry.second, "traffic_class_a", group.traffic_class_a);
            set_value(entry.second, "traffic_class_b", group.traffic_class_b);
            set_value(entry.second, "desc_progress_limit", group.desc_progress_limit);
            set_value(entry.second, "batch_progress_limit", group.batch_progress_limit);
            result.groups.push_back(group);

            if (auto queues = entry.second.get_child_optional("grouped_workqueues")) {
                for (const auto& queue : *queues)
                    parse_workqueue(queue.second, device_id, group_id, result, path);
            }
        }
    }
}

void expand_default_profile(idxd_config_t::config_t& config)
{
    accfg_ctx* ctx = nullptr;
    assert(accfg_new(&ctx) == 0);

    auto find_group = [&config](int device_id, int group_id) {
        return std::find_if(config.groups.begin(), config.groups.end(),
            [device_id, group_id](const auto& group) {
                return group.device_id == device_id && group.group_id == group_id;
            });
    };
    auto find_engine = [&config](int device_id, int engine_id) {
        return std::find_if(config.engines.begin(), config.engines.end(),
            [device_id, engine_id](const auto& engine) {
                return engine.device_id == device_id && engine.engine_id == engine_id;
            });
    };
    auto find_wq = [&config](int device_id, int wq_id) {
        return std::find_if(config.wqs.begin(), config.wqs.end(),
            [device_id, wq_id](const auto& wq) {
                return wq.device_id == device_id && wq.wq_id == wq_id;
            });
    };

    for (const auto& device_config : config.devices) {
        accfg_device* device = accfg_ctx_device_get_by_id(ctx, device_config.device_id);
        if (!device)
            continue;

        const auto group_template = std::find_if(config.groups.begin(), config.groups.end(),
            [&device_config](const auto& group) { return group.device_id == device_config.device_id; });
        const auto wq_template = std::find_if(config.wqs.begin(), config.wqs.end(),
            [&device_config](const auto& wq) { return wq.device_id == device_config.device_id; });
        const std::optional group_defaults = group_template == config.groups.end()
            ? std::optional<idxd_config_t::config_t::group_t>{}
            : std::optional{*group_template};
        const std::optional wq_defaults = wq_template == config.wqs.end()
            ? std::optional<idxd_config_t::config_t::wq_t>{}
            : std::optional{*wq_template};

        accfg_group* group;
        accfg_group_foreach(device, group) {
            const int group_id = accfg_group_get_id(group);
            if (group_defaults &&
                find_group(device_config.device_id, group_id) == config.groups.end()) {
                auto expanded = *group_defaults;
                expanded.group_id = group_id;
                config.groups.push_back(std::move(expanded));
            }
        }

        accfg_engine* engine;
        accfg_engine_foreach(device, engine) {
            const int engine_id = accfg_engine_get_id(engine);
            if (find_engine(device_config.device_id, engine_id) != config.engines.end())
                continue;

            idxd_config_t::config_t::engine_t expanded;
            expanded.device_id = device_config.device_id;
            expanded.engine_id = engine_id;
            expanded.group_id = accfg_engine_get_group_id(engine);
            if (group_defaults)
                expanded.group_id = group_defaults->group_id;
            config.engines.push_back(expanded);
        }

        accfg_wq* wq;
        accfg_wq_foreach(device, wq) {
            const int wq_id = accfg_wq_get_id(wq);
            auto existing = find_wq(device_config.device_id, wq_id);
            if (existing == config.wqs.end()) {
                if (!wq_defaults)
                    continue;
                auto expanded = *wq_defaults;
                expanded.wq_id = wq_id;
                expanded.group_id = group_defaults
                    ? group_defaults->group_id : accfg_wq_get_group_id(wq);
                config.wqs.push_back(std::move(expanded));
                existing = std::prev(config.wqs.end());
            }

            auto& current = *existing;
            if (!current.wq_size)
                current.wq_size = accfg_wq_get_size(wq);
            if (!current.max_batch_size)
                current.max_batch_size = accfg_wq_get_max_batch_size(wq);
            if (!current.max_transfer_size)
                current.max_transfer_size = accfg_wq_get_max_transfer_size(wq);
            if (current.threshold < 0)
                current.threshold = accfg_wq_get_threshold(wq);
            if (current.priority < 0)
                current.priority = accfg_wq_get_priority(wq);
            if (current.block_on_fault < 0)
                current.block_on_fault = accfg_wq_get_block_on_fault(wq);
            if (current.mode == ACCFG_WQ_MODE_UNKNOWN)
                current.mode = accfg_wq_get_mode(wq);
            if (current.type == ACCFG_WQT_NONE)
                current.type = accfg_wq_get_type(wq);
            if (current.name.empty()) {
                if (const char* name = accfg_wq_get_devname(wq))
                    current.name = name;
            }
            if (current.driver_name.empty()) {
                if (const char* driver_name = accfg_wq_get_driver_name(wq))
                    current.driver_name = driver_name;
            }
        }
    }

    accfg_unref(ctx);
}

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
            log_skip_or_print(RuntimeSkipCategory, "Cannot find device %d", q.device_id);
            return EXIT_SKIP;
        }

        accfg_wq* wq = accfg_device_wq_get_by_id(device, q.wq_id);
        if (!wq) {
            log_skip_or_print(RuntimeSkipCategory, "Cannot find work queue %d on device %d", q.wq_id, q.device_id);
            return EXIT_SKIP;
        }

        // A work queue under a disabled device is already down, and accel-config
        // rejects operating on it.
        if (accfg_device_get_state(device) == ACCFG_DEVICE_ENABLED && accfg_wq_is_enabled(wq) > 0) {
            if (int ret = accfg_wq_disable(wq, true); ret < 0) {
                log_error_or_print("Failed to disable work queue %d.%d before applying configuration: %s",
                          q.device_id, q.wq_id, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
    }

    for (const auto& d : from.devices) {
        accfg_device* device = accfg_ctx_device_get_by_id(ctx, d.device_id);
        if (!device) {
            log_skip_or_print(RuntimeSkipCategory, "Cannot find device %d", d.device_id);
            return EXIT_SKIP;
        }

        if (accfg_device_get_state(device) == ACCFG_DEVICE_ENABLED) {
            if (int ret = accfg_device_disable(device, true); ret < 0) {
                log_error_or_print("Failed to disable device %d before applying configuration: %s",
                          d.device_id, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
    }

    for (const auto& d : from.devices) {
        accfg_device* device = accfg_ctx_device_get_by_id(ctx, d.device_id);
        if (!device) {
            log_skip_or_print(RuntimeSkipCategory, "Cannot find device %d", d.device_id);
            return EXIT_SKIP;
        }

        if (int ret = accfg_device_set_read_buffer_limit(device, d.read_buffer_limit); ret < 0) {
            log_error_or_print("Failed to set device %d read buffer limit to %u: %s",
                      d.device_id, d.read_buffer_limit, strerror(-ret));
            return EXIT_FAILURE;
        }
        if (d.event_log_size >= 0) {
            if (int ret = accfg_device_set_event_log_size(device, d.event_log_size); ret < 0) {
                log_error_or_print("Failed to set device %d event log size to %d: %s",
                          d.device_id, d.event_log_size, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
    }

    for (const auto& g : from.groups) {
        accfg_device* device = accfg_ctx_device_get_by_id(ctx, g.device_id);
        if (!device) {
            log_skip_or_print(RuntimeSkipCategory, "Cannot find device %d", g.device_id);
            return EXIT_SKIP;
        }

        accfg_group* group = accfg_device_group_get_by_id(device, g.group_id);
        if (!group) {
            log_skip_or_print(RuntimeSkipCategory, "Cannot find group %d on device %d", g.group_id, g.device_id);
            return EXIT_SKIP;
        }

        if (g.read_buffers_reserved >= 0) {
            if (int ret = accfg_group_set_read_buffers_reserved(group, g.read_buffers_reserved); ret < 0) {
                log_error_or_print("Failed to set group %d.%d read buffers reserved to %d: %s",
                          g.device_id, g.group_id, g.read_buffers_reserved, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
        if (g.read_buffers_allowed >= 0) {
            if (int ret = accfg_group_set_read_buffers_allowed(group, g.read_buffers_allowed); ret < 0) {
                log_error_or_print("Failed to set group %d.%d read buffers allowed to %d: %s",
                          g.device_id, g.group_id, g.read_buffers_allowed, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
        // Setting those params can return EPERM. Fail only if we try to set to different value than present.
        if (g.use_read_buffer_limit >= 0 &&
            accfg_group_get_use_read_buffer_limit(group) != g.use_read_buffer_limit) {
            if (int ret = accfg_group_set_use_read_buffer_limit(group, g.use_read_buffer_limit); ret < 0) {
                log_error_or_print("Failed to set group %d.%d use read buffer limit to %d: %s",
                          g.device_id, g.group_id, g.use_read_buffer_limit, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
        if (g.traffic_class_a >= 0 &&
            accfg_group_get_traffic_class_a(group) != g.traffic_class_a) {
            if (int ret = accfg_group_set_traffic_class_a(group, g.traffic_class_a); ret < 0) {
                log_error_or_print("Failed to set group %d.%d traffic class A to %d: %s",
                          g.device_id, g.group_id, g.traffic_class_a, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
        if (g.traffic_class_b >= 0 &&
            accfg_group_get_traffic_class_b(group) != g.traffic_class_b) {
            if (int ret = accfg_group_set_traffic_class_b(group, g.traffic_class_b); ret < 0) {
                log_error_or_print("Failed to set group %d.%d traffic class B to %d: %s",
                          g.device_id, g.group_id, g.traffic_class_b, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
        if (g.desc_progress_limit >= 0) {
            if (int ret = accfg_group_set_desc_progress_limit(group, g.desc_progress_limit); ret < 0) {
                log_error_or_print("Failed to set group %d.%d descriptor progress limit to %d: %s",
                          g.device_id, g.group_id, g.desc_progress_limit, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
        if (g.batch_progress_limit >= 0) {
            if (int ret = accfg_group_set_batch_progress_limit(group, g.batch_progress_limit); ret < 0) {
                log_error_or_print("Failed to set group %d.%d batch progress limit to %d: %s",
                          g.device_id, g.group_id, g.batch_progress_limit, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
    }

    for (const auto& e : from.engines) {
        accfg_device* device = accfg_ctx_device_get_by_id(ctx, e.device_id);
        if (!device) {
            log_skip_or_print(RuntimeSkipCategory, "Cannot find device %d", e.device_id);
            return EXIT_SKIP;
        }

        accfg_engine* engine = accfg_device_engine_get_by_id(device, e.engine_id);
        if (!engine) {
            log_skip_or_print(RuntimeSkipCategory, "Cannot find engine %d on device %d", e.engine_id, e.device_id);
            return EXIT_SKIP;
        }

        if (e.group_id >= 0) {
            if (int ret = accfg_engine_set_group_id(engine, e.group_id); ret < 0) {
                log_error_or_print("Failed to set engine %d.%d group id to %d: %s",
                          e.device_id, e.engine_id, e.group_id, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
    }

    for (const auto& q : from.wqs) {
        accfg_device* device = accfg_ctx_device_get_by_id(ctx, q.device_id);
        if (!device) {
            log_skip_or_print(RuntimeSkipCategory, "Cannot find device %d", q.device_id);
            return EXIT_SKIP;
        }

        accfg_wq* wq = accfg_device_wq_get_by_id(device, q.wq_id);
        if (!wq) {
            log_skip_or_print(RuntimeSkipCategory, "Cannot find work queue %d on device %d", q.wq_id, q.device_id);
            return EXIT_SKIP;
        }

        if (q.group_id >= 0) {
            if (int ret = accfg_wq_set_group_id(wq, q.group_id); ret < 0) {
                log_error_or_print("Failed to set work queue %d.%d group id to %d: %s",
                          q.device_id, q.wq_id, q.group_id, strerror(-ret));
                return EXIT_FAILURE;
            }
        }

        if (const char* type = wq_type_to_string(q.type)) {
            if (int ret = accfg_wq_set_str_type(wq, type); ret < 0) {
                log_error_or_print("Failed to set work queue %d.%d type to %s: %s",
                          q.device_id, q.wq_id, type, strerror(-ret));
                return EXIT_FAILURE;
            }
        }

        if (!q.name.empty()) {
            if (int ret = accfg_wq_set_str_name(wq, q.name.c_str()); ret < 0) {
                log_error_or_print("Failed to set work queue %d.%d name to %s: %s",
                          q.device_id, q.wq_id, q.name.c_str(), strerror(-ret));
                return EXIT_FAILURE;
            }
        }
        if (!q.driver_name.empty()) {
            if (int ret = accfg_wq_set_str_driver_name(wq, q.driver_name.c_str()); ret < 0) {
                log_error_or_print("Failed to set work queue %d.%d driver to %s: %s",
                          q.device_id, q.wq_id, q.driver_name.c_str(), strerror(-ret));
                return EXIT_FAILURE;
            }
        }

        if (q.mode != ACCFG_WQ_MODE_UNKNOWN) {
            if (int ret = accfg_wq_set_mode(wq, q.mode); ret < 0) {
                log_error_or_print("Failed to set work queue %d.%d mode: %s",
                          q.device_id, q.wq_id, strerror(-ret));
                return EXIT_FAILURE;
            }
        }

        if (q.wq_size) {
            if (int ret = accfg_wq_set_size(wq, static_cast<int>(*q.wq_size)); ret < 0) {
                log_error_or_print("Failed to set work queue %d.%d size to %lu: %s",
                          q.device_id, q.wq_id, *q.wq_size, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
        if (q.max_batch_size) {
            int ret = accfg_wq_set_max_batch_size(wq, static_cast<int>(*q.max_batch_size));
            if (ret < 0) {
                log_error_or_print("Failed to set work queue %d.%d max batch size to %u: %s",
                          q.device_id, q.wq_id, *q.max_batch_size, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
        if (q.max_transfer_size) {
            int ret = accfg_wq_set_max_transfer_size(wq, *q.max_transfer_size);
            if (ret < 0) {
                log_error_or_print("Failed to set work queue %d.%d max transfer size to %lu: %s",
                          q.device_id, q.wq_id, *q.max_transfer_size, strerror(-ret));
                return EXIT_FAILURE;
            }
        }

        if (q.priority >= 0) {
            if (int ret = accfg_wq_set_priority(wq, q.priority); ret < 0) {
                log_error_or_print("Failed to set work queue %d.%d priority to %d: %s",
                          q.device_id, q.wq_id, q.priority, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
        if (q.threshold >= 0) {
            if (int ret = accfg_wq_set_threshold(wq, q.threshold); ret < 0) {
                log_error_or_print("Failed to set work queue %d.%d threshold to %d: %s",
                          q.device_id, q.wq_id, q.threshold, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
        if (q.block_on_fault >= 0) {
            if (int ret = accfg_wq_set_block_on_fault(wq, q.block_on_fault); ret < 0) {
                log_error_or_print("Failed to set work queue %d.%d block on fault to %d: %s",
                          q.device_id, q.wq_id, q.block_on_fault, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
        if (q.ats_disable >= 0) {
            int current = accfg_wq_get_ats_disable(wq);
            if (current < 0) {
                log_warning_or_print("Work queue %d.%d does not support ATS disable; ignoring configuration",
                            q.device_id, q.wq_id);
            } else if (current != q.ats_disable) {
                if (int ret = accfg_wq_set_ats_disable(wq, q.ats_disable); ret < 0) {
                    log_error_or_print("Failed to set work queue %d.%d ATS disable to %d: %s",
                              q.device_id, q.wq_id, q.ats_disable, strerror(-ret));
                    return EXIT_FAILURE;
                }
            }
        }
        if (q.prs_disable >= 0) {
            int current = accfg_wq_get_prs_disable(wq);
            if (current < 0) {
                log_warning_or_print("Work queue %d.%d does not support PRS disable; ignoring configuration",
                            q.device_id, q.wq_id);
            } else if (current != q.prs_disable) {
                if (int ret = accfg_wq_set_prs_disable(wq, q.prs_disable); ret < 0) {
                    log_error_or_print("Failed to set work queue %d.%d PRS disable to %d: %s",
                              q.device_id, q.wq_id, q.prs_disable, strerror(-ret));
                    return EXIT_FAILURE;
                }
            }
        }

        if (q.op_config) {
            if (int ret = accfg_wq_set_op_config(wq, const_cast<accfg_op_config*>(&*q.op_config)); ret < 0) {
                log_error_or_print("Failed to set work queue %d.%d operation configuration: %s",
                          q.device_id, q.wq_id, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
    }

    for (const auto& d : from.devices) {
        accfg_device* device = accfg_ctx_device_get_by_id(ctx, d.device_id);
        if (!device) {
            log_skip_or_print(RuntimeSkipCategory, "Cannot find device %d", d.device_id);
            return EXIT_SKIP;
        }

        if (d.enabled) {
            if (int ret = accfg_device_enable(device); ret < 0) {
                log_error_or_print("Failed to enable device %d: %s", d.device_id, strerror(-ret));
                return EXIT_FAILURE;
            }
        } else if (accfg_device_get_state(device) == ACCFG_DEVICE_ENABLED) {
            if (int ret = accfg_device_disable(device, true); ret < 0) {
                log_error_or_print("Failed to disable device %d: %s", d.device_id, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
    }

    for (const auto& q : from.wqs) {
        accfg_device* device = accfg_ctx_device_get_by_id(ctx, q.device_id);
        accfg_wq* wq = device ? accfg_device_wq_get_by_id(device, q.wq_id) : nullptr;
        if (!wq) {
            log_skip_or_print(RuntimeSkipCategory, "Cannot find work queue %d on device %d", q.wq_id, q.device_id);
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
            log_skip_or_print(RuntimeSkipCategory, "Cannot find final state for device %d", q.device_id);
            return EXIT_SKIP;
        }

        if (q.enabled && !device_should_be_enabled) {
            log_skip_or_print(RuntimeSkipCategory, "Inconsistent configuration: WQ %d.%d enabled while device %d is disabled",
                             q.device_id, q.wq_id, q.device_id);
            return EXIT_SKIP;
        }

        if (q.enabled) {
            if (int ret = accfg_wq_enable(wq); ret < 0) {
                log_error_or_print("Failed to enable work queue %d.%d: %s",
                          q.device_id, q.wq_id, strerror(-ret));
                return EXIT_FAILURE;
            }
        } else if (device_should_be_enabled && accfg_wq_is_enabled(wq) > 0) {
            if (int ret = accfg_wq_disable(wq, true); ret < 0) {
                log_error_or_print("Failed to disable work queue %d.%d: %s",
                          q.device_id, q.wq_id, strerror(-ret));
                return EXIT_FAILURE;
            }
        }
    }

    accfg_unref(ctx);
    return EXIT_SUCCESS;
}

// Returns a config with all templates resolved against the devices present on this system.
idxd_config_t::config_t expand_templates_for_system(const idxd_config_t::config_t& desired)
{
    idxd_config_t::config_t result = desired;
    result.templates.clear();

    auto has_entry = [](const auto& list, int device_id, auto member, int id) {
        for (const auto& entry : list) {
            if (entry.device_id == device_id && entry.*member == id)
                return true;
        }
        return false;
    };

    accfg_ctx* ctx = nullptr;
    assert(accfg_new(&ctx) == 0);

    accfg_device* device;
    accfg_device_foreach(ctx, device) {
        const int device_id = accfg_device_get_id(device);
        const accfg_device_type device_type = accfg_device_get_type(device);

        for (const auto& t : desired.templates) {
            if (t.device_type != ACCFG_DEVICE_TYPE_UNKNOWN && t.device_type != device_type)
                continue;

            if (t.device && !has_entry(result.devices, device_id, &idxd_config_t::config_t::device_t::device_id, device_id)) {
                idxd_config_t::config_t::device_t d = *t.device;
                d.device_id = device_id;
                result.devices.push_back(d);
            }

            if (t.group) {
                accfg_group* group;
                accfg_group_foreach(device, group) {
                    const int group_id = accfg_group_get_id(group);
                    if (has_entry(result.groups, device_id, &idxd_config_t::config_t::group_t::group_id, group_id))
                        continue;
                    idxd_config_t::config_t::group_t g = *t.group;
                    g.device_id = device_id;
                    g.group_id = group_id;
                    result.groups.push_back(g);
                }
            }

            if (t.engine) {
                accfg_engine* engine;
                accfg_engine_foreach(device, engine) {
                    const int engine_id = accfg_engine_get_id(engine);
                    if (has_entry(result.engines, device_id, &idxd_config_t::config_t::engine_t::engine_id, engine_id))
                        continue;
                    idxd_config_t::config_t::engine_t e = *t.engine;
                    e.device_id = device_id;
                    e.engine_id = engine_id;
                    result.engines.push_back(e);
                }
            }

            if (t.wq) {
                accfg_wq* wq;
                accfg_wq_foreach(device, wq) {
                    const int wq_id = accfg_wq_get_id(wq);
                    if (has_entry(result.wqs, device_id, &idxd_config_t::config_t::wq_t::wq_id, wq_id))
                        continue;
                    idxd_config_t::config_t::wq_t q = *t.wq;
                    q.device_id = device_id;
                    q.wq_id = wq_id;
                    result.wqs.push_back(std::move(q));
                }
            }
        }
    }

    accfg_unref(ctx);
    return result;
}

// Disabling a device clears its engine-to-group bindings, so a config that targets a device
// without listing its engines has to inherit the bindings it wants to keep.
void inherit_unlisted_engines(idxd_config_t::config_t& into, const idxd_config_t::config_t& current)
{
    for (const auto& e : current.engines) {
        // don't inherit engines from devices whose WQs are not targeted
        auto targets_device = [&](const auto& entry) { return entry.device_id == e.device_id; };
        if (std::none_of(into.wqs.begin(), into.wqs.end(), targets_device))
            continue;

        into.engines.push_back(e);
    }
}
} // end anonymous namespace

int apply_with_fallback(idxd_config_t::config_t& desired, idxd_config_t::config_t& previous)
{
    // save snapshot of current system state
    auto ret = read_config(previous);
    if (ret != EXIT_SUCCESS) {
        return ret;
    }

    // apply desired config
    if (!desired.templates.empty()) { // first we have to expand templates if defined
        desired = expand_templates_for_system(desired);
    }
    if (desired.engines.empty()) { // we allow to omit defining engines and inherit them from system
        inherit_unlisted_engines(desired, previous);
    }
    ret = write_config(desired);
    if (ret == EXIT_SUCCESS) {
        return EXIT_SUCCESS;
    }

    // best-effort rollback if applying desired config failed
    if (write_config(previous) != EXIT_SUCCESS) {
        log_error_or_print("Failed to apply desired IDXD configuration and failed to restore previous configuration");
        return EXIT_FAILURE;
    } else {
        log_warning_or_print("Failed to apply desired IDXD configuration; restored previous configuration");
    }

    return ret;
}

int idxd_config_t::apply_desired()
{
    return apply_with_fallback(desired, previous);
}

idxd_config_t::config_t read_from_file(const std::string& path)
{
    idxd_config_t::config_t res;

    try {
        ptree root;
        std::ifstream input{path};
        if (!input)
            throw std::runtime_error("cannot open configuration file");
        boost::property_tree::read_json(input, root);

        for (const auto& entry : root)
            parse_device(entry.second, res, path);
        expand_default_profile(res);
    } catch (const std::exception& error) {
        fprintf(stderr, "Invalid IDXD configuration file %s: %s\n", path.c_str(), error.what());
        exit(EX_USAGE);
    }

    return res;
}

int apply_global_idxd_config(int argc, char **argv)
{
    std::string path;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        constexpr std::string_view option = "--idxd-config";
        if (arg == option) {
            if (++i >= argc) {
                fprintf(stderr, "%s: option '--idxd-config' requires an argument\n",
                        program_invocation_name);
                return EX_USAGE;
            }
            path = argv[i];
        } else if (arg.starts_with(option) && arg.size() > option.size() &&
                   arg[option.size()] == '=') {
            path = arg.substr(option.size() + 1);
        }
    }

    if (path.empty()) {
        // no config specified by user
        return EXIT_SUCCESS;
    }

    if (!fs::exists(fs::path{path})) {
        fprintf(stderr, "IDXD user config file %s does not exist\n", path.c_str());
        return EX_USAGE;
    }

    auto desired = read_from_file(path);
    idxd_config_t::config_t previous{};
    return apply_with_fallback(desired, previous);
}

int idxd_config_t::restore_previous()
{
    return write_config(previous);
}
