/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "logging.h"
#include "idxd_device.h"

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
    // Note: this assumes the topology won't change after the first time this
    // function is called. And it shouldn't, in the sense of devices' ids at least.
    static const auto spacing = []() {
        int res = 0;
        auto max_cpu = std::max_element(
            device_info, device_info + thread_count(),
            [](const auto& i1, const auto& i2) { return i1.cpu_number < i2.cpu_number; }
        )->cpu_number;
        do { max_cpu /= 10; res++; } while (max_cpu != 0);
        return res;
    }();
    return spacing;
}

std::string AbstractLogger::thread_id_header_for_device(int thread, LogLevelVerbosity verbosity)
{
    const wq_info_t* info = device_info + thread;
    std::string line;

    line = std::format("{{ device: {}{}, wq: {}, ", to_string(info->dev_type), info->device_id, info->wq_id);
    line += std::format("logical_cpu: {:{}}, ", info->cpu_number, calc_spacing());
    line += std::format("pci_address: {:04x}:{:02x}:{:02x}.{:01x}",
        info->bdf.domain, info->bdf.bus, info->bdf.device, info->bdf.function
    );
    line += " }";
    // TODO: should we print mutable data as well?

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
