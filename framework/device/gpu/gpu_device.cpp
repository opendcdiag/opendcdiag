/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sandstone_p.h>
#include "gpu_device.h"

#include <string>

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
    return TestResult::Passed;
}

std::vector<struct test*> special_tests_for_device()
{
    return {};
}
