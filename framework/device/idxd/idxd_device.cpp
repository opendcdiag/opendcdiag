/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_p.h"
#include "idxd_device.h"
#include "idxd_features.h"
#include "topology_idxd.hpp"

#include <cassert>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <optional>
#include <print>
#include <string>
#include <vector>

std::string device_features_to_string(device_features_t f)
{
    std::string result;
    const char *comma = "";
    for (size_t i = 0; i < IDXD_FEATURE_SIZE; ++i) {
        if (f & IDXD_FEATURE_CONSTANT(i)) {
            result += comma;
            result += features_names[i];
            comma = ",";
        }
    }
    return result;
}

void dump_device_info()
{
    std::print("#Dev\t#Ver\t#WQs\t#Engs\tPCI-addr\n");
    for (const auto& device : Topology::topology().devices) {
        uint32_t num_wqs = 0;
        uint32_t num_eng = 0;
        std::optional<bdf_t> bdf{};
        for (const auto& group : device.groups) {
            auto size = group.wqs.size();
            num_wqs += size;
            num_eng += group.engines.size();
            if (!bdf && size != 0) {
                bdf = group.wqs.front().wq->bdf;
            }
        }

        std::string version;
        if (device.dev_version & 0xff)
            version = std::format("v{}.{}", device.dev_version >> 8, device.dev_version & 0xff);
        else if (device.dev_version != 0)
            version = std::format("v{}", device.dev_version >> 8);
        else
            version = "??";

        std::print("{}\t{}\t{}\t{}\t", device.name, version, num_wqs, num_eng);
        assert(bdf.has_value());
        std::print("{:04x}:{:02x}:{:02x}.{:01x}\n",
            bdf->domain, bdf->bus, (uint8_t)bdf->device, (uint8_t)bdf->function
        );
    }
}

/// Does validation check of the minimum_cpu features, being undefined feature bits or
/// conflicting devices' features bits. Aborts in case of a mismatch, as it's a test
/// design problem, rather than a skipable condition.
TestResult prepare_test_for_device(struct test *test)
{
    if (test->minimum_cpu & ~idxd_all_features_mask) {
        fprintf(stderr, "Undefined feature bits");
        abort();
    }

    // UINT_MAX due to lack of ACCFG_DEVICE_VERSION_MAX
    bool wants_dsa = test->minimum_cpu
        & (idxd_dsa_operation_features_mask | device_type_features(ACCFG_DEVICE_DSA, UINT_MAX));
    bool wants_iax = test->minimum_cpu
        & (idxd_iax_operation_features_mask | device_type_features(ACCFG_DEVICE_IAX, UINT_MAX));

    if (wants_dsa && wants_iax) {
        fprintf(stderr, "Ambiguous features, can't determine device type (%s)",
                 device_features_to_string(test->minimum_cpu).c_str());
        abort();
    }

    if (!wants_dsa && !wants_iax) {
        // The test has no device-specific requirements, so either device type can run it (but must be targetable still).
        if (Topology::topology().targetable_wqs(test, ACCFG_DEVICE_DSA).empty()
            && Topology::topology().targetable_wqs(test, ACCFG_DEVICE_IAX).empty())
        {
            log_skip(CpuTopologyIssueSkipCategory, "No enabled user-mode WQ");
            return TestResult::Skipped;
        } else {
            return TestResult::Passed;
        }
    }

    accfg_device_type required_device_type = wants_dsa ? ACCFG_DEVICE_DSA : ACCFG_DEVICE_IAX;
    if (Topology::topology().targetable_wqs(test, required_device_type).empty()) {
        log_skip(CpuTopologyIssueSkipCategory, "No enabled user-mode WQ to satisfy required features (%s)",
                 device_features_to_string(test->minimum_cpu).c_str());
        return TestResult::Skipped;
    }

    return TestResult::Passed;
}

void finish_test_for_device(struct test *test)
{
}

std::vector<struct test*> special_tests_for_device()
{
    return {};
}
