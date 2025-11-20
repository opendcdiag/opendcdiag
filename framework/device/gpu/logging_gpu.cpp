/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "logging.h"
#include "gpu_device.h"
#include "test_data_gpu.h"

#if !SANDSTONE_NO_LOGGING
namespace {
auto calc_spacing()
{
    // Note: this assumes the topology won't change after the first time this
    // function is called.
    static const auto spacing = []() {
        struct { int gpu, cpu; } result {0, 0};
        auto max_gpu = std::max_element(
            device_info, device_info + thread_count(),
            [](const auto& g1, const auto& g2) { return g1.gpu_number < g2.gpu_number; }
        )->gpu_number;
        auto max_cpu = std::max_element(
            device_info, device_info + thread_count(),
            [](const auto& g1, const auto& g2) { return g1.cpu_number < g2.cpu_number; }
        )->cpu_number;

        do { max_gpu /= 10; result.gpu++; } while (max_gpu != 0);
        do { max_cpu /= 10; result.cpu++; } while (max_cpu != 0);

        return result;
    }();
    return spacing;
}
} // end unnamed namespace

std::string AbstractLogger::thread_id_header_for_device(int thread, LogLevelVerbosity verbosity)
{
    gpu_info_t *info = device_info + thread;
    std::string line;
    if (info->subdevice_index != -1) {
        line = std::format("{{ gpu_index: {}/{}, gpu_number: {:{}}, ", info->device_index, info->subdevice_index, info->gpu_number, calc_spacing().gpu);
    } else {
        assert(info->device_index == info->gpu_number);
        line = std::format("{{ gpu_number: {:{}}, ", info->gpu_number, calc_spacing().gpu);
    }
    line += std::format("logical_cpu: {:{}}, ", calc_spacing().cpu, info->cpu_number);
    const auto& uuid = info->device_properties.uuid.id;
    line += std::format(
        "uuid: {:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}, ",
        uuid[15], uuid[14], uuid[13], uuid[12], uuid[11], uuid[10], uuid[9], uuid[8],
        uuid[7],  uuid[6],  uuid[5],  uuid[4],  uuid[3],  uuid[2],  uuid[1], uuid[0]
    );
    line += std::format("pci_address: {:04x}:{:02x}:{:02x}.{:01x}, ",
        info->bdf.domain, info->bdf.bus, info->bdf.device, info->bdf.function
    );
    line += std::format("name: \"{}\"", // no comma
        info->device_properties.name
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

#endif // !SANDSTONE_NO_LOGGING
