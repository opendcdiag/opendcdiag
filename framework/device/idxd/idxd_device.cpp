/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_p.h"
#include "idxd_config.hpp"
#include "idxd_device.h"

std::string device_features_to_string(device_features_t f)
{
    std::string result;
    return result;
}

void dump_device_info()
{
}

TestResult prepare_test_for_device(struct test *test)
{
    if (test->idxd_config) {
        auto ret = test->idxd_config->apply_desired();
        if (ret != EXIT_SUCCESS) {
             // depending on the fatality of the error, we either skip or fail
            return ret == EXIT_FAILURE ? TestResult::Failed : TestResult::Skipped;
        }
        // visible system configuration changed - topo rebuild required
        rebuild_topology();
    }
    return TestResult::Passed;
}

void finish_test_for_device(struct test *test)
{
    if (test->idxd_config) {
        if (test->idxd_config->restore_previous() != EXIT_SUCCESS) {
            fprintf(stderr, "Failed to restore previous IDXD configuration");
            exit(EX_OSERR);
        } else {
            // rebuild required again
            rebuild_topology();
        }
    }
}

std::vector<struct test*> special_tests_for_device()
{
    return {};
}
