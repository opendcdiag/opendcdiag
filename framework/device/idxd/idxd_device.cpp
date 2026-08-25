/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_p.h"
#include "idxd_device.h"
#include "idxd_features.h"

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
