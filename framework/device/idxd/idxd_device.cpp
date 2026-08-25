/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_p.h"
#include "idxd_device.h"
#include "idxd_features.h"
#include "topology_idxd.hpp"

#include <cstdint>
#include <print>
#include <string>
#include <vector>

std::string device_features_to_string(device_features_t f)
{
    std::string result;
    return result;
}

void dump_device_info()
{
    std::print("#Device\t#Version\t#WQs\tPCI-addr\n");
    for (const auto& device : Topology::topology().devices) {
        uint32_t num_wqs = 0;
        bdf_t bdf{};
        const char* version = nullptr;
        for (const auto& group : device.groups) {
            auto size = group.wqs.size();
            num_wqs += size;
            if (!version && size != 0) {
                bdf = group.wqs.front().wq->bdf;

                switch (group.wqs.front().wq->dev_version) {
                case ACCFG_DEVICE_VERSION_1:
                    version = "v1";
                    break;
                case ACCFG_DEVICE_VERSION_2:
                    version = "v2";
                    break;
                }
            }
        }

        std::print("{}\t{}\t{}\t", device.name, version, num_wqs);
        std::print("{:04x}:{:02x}:{:02x}.{:01x}\n",
            bdf.domain, bdf.bus, (uint8_t)bdf.device, (uint8_t)bdf.function
        );
    }
}

TestResult prepare_test_for_device(struct test *test)
{
    return TestResult::Passed;
}

void finish_test_for_device(struct test *test)
{
}

std::vector<struct test*> special_tests_for_device()
{
    return {};
}
