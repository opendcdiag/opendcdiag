/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "logging.h"
#include "idxd_device.h"
#include "topology_idxd.hpp"

#include <algorithm>
#include <format>
#include <string>

#if !SANDSTONE_NO_LOGGING
static std::string to_string(accfg_device_type device_type)
{
    switch (device_type) {
    case ACCFG_DEVICE_DSA:
        return "dsa";
    case ACCFG_DEVICE_IAX:
        return "iax";
    default:
        return {};
    }
}

static auto calc_spacing()
{
    static const auto spacing = []() {
        struct {
            int device;
            int wq;
            int cpu;
            uint32_t group;
        } result = {};
        const auto digit_count = [](auto value) {
            int result = 0;
            do { value /= 10; result++; } while (value != 0);
            return result;
        };
        const auto max_value = [](auto member) {
            return std::max_element(
                device_info, device_info + thread_count(),
                [member](const auto& first, const auto& second) { return first.*member < second.*member; }
            )->*member;
        };

        result.device = digit_count(max_value(&wq_info_t::device_id));
        result.wq = digit_count(max_value(&wq_info_t::wq_id));
        result.cpu = digit_count(max_value(&wq_info_t::cpu_number));
        const auto max_groups = std::max_element(
            Topology::topology().devices.begin(), Topology::topology().devices.end(),
            [](const auto& first, const auto& second) { return first.max_groups < second.max_groups; }
        )->max_groups;
        result.group = digit_count(max_groups - 1);

        return result;
    }();
    return spacing;
}

std::string AbstractLogger::thread_id_header_for_device(int thread, LogLevelVerbosity verbosity)
{
    const wq_info_t* info = device_info + thread;
    std::string line;

    const auto spacing = calc_spacing();
    line = std::format("{{ device: {}{:{}}, wq: {:{}}, ",
        to_string(info->dev_type), info->device_id, spacing.device, info->wq_id, spacing.wq);
    const auto& path = info->path;
    line += std::format("group: {:{}}, ", Topology::topology().devices[path.device].groups[path.group].id, spacing.group);
    line += std::format("logical_cpu: {:{}}, ", info->cpu_number, spacing.cpu);
    line += std::format("pci_address: {:04x}:{:02x}:{:02x}.{:01x}",
        info->bdf.domain, info->bdf.bus, info->bdf.device, info->bdf.function
    );
    line += " }";

    return line;
}

void AbstractLogger::print_thread_header_for_device(int fd, PerThreadData::Test *thr)
{

}

void AbstractLogger::print_fixed_for_device()
{

}

void AbstractLogger::device_print_extra_info()
{

}

void dump_device_state(std::string&, int)
{

}

#else
void dump_device_state(std::string&, int)
{}
#endif // !SANDSTONE_NO_LOGGING
