/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IFS_TEST_CASES_H_INCLUDED
#define IFS_TEST_CASES_H_INCLUDED

#include "ifs_unit_utils.h"

/* Check requirements */

static ifs_unit reqs_test2 = {
    "/tmp/intel_ifs_0.test2_current_batch_found",
    5,
    {
        {"current_batch", "0x1"},
        {"details", "0x8082"},
        {"image_version", "0x171"},
        {"run_test", "1"},
        {"status", "pass"}
    }
};

static ifs_unit reqs_test3 = {
    "/tmp/intel_ifs_0.test3_current_batch_not_found",
    3,
    {
        {"details", "0x8082"},
        {"run_test", "1"},
        {"status", "pass"}
    }
};

#endif //IFS_TEST_CASES_H_INCLUDED
