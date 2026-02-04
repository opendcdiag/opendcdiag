/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sandstone_p.h>
#include "gpu_device.h"
#include "topology_gpu.h"

#include <string>
#include <print>

bool logging_in_test = false;

std::string device_features_to_string(device_features_t f)
{
    std::string result;
    return result;
}

namespace {
void dump_single_gpu(const gpu_info_t* info)
{
    std::print("{}\t", info->gpu_number);
    if (info->subdevice_index != -1) {
        std::print("{}/{}\t", info->device_index, info->subdevice_index);
    } else {
        std::print("{}\t", info->gpu_number);
    }

    std::print("{:04x}:{:02x}:{:02x}.{:01x}\t",
        info->bdf.domain, info->bdf.bus, info->bdf.device, info->bdf.function
    );
    const auto& uuid = info->device_properties.uuid.id;
    std::print(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}\t",
        uuid[15], uuid[14], uuid[13], uuid[12], uuid[11], uuid[10], uuid[9], uuid[8],
        uuid[7],  uuid[6],  uuid[5],  uuid[4],  uuid[3],  uuid[2],  uuid[1], uuid[0]
    );
    std::print("{}\n", info->device_properties.name);
}
}

void dump_device_info()
{
    printf("#GPU\t#Topo\tPCI-addr\tUUID\t\t\t\t\tModel\n");
    for_each_topo_device([&](const gpu_info_t& info) {
        dump_single_gpu(&info);
        return EXIT_SUCCESS;
    });
}

TestResult prepare_test_for_device(struct test *test)
{
    logging_in_test = true;
    return TestResult::Passed;
}

void finish_test_for_device(struct test *test)
{
    logging_in_test = false;
}

std::vector<struct test*> special_tests_for_device()
{
    return {};
}
