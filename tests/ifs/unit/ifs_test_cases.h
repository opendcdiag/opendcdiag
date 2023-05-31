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

static ifs_unit reqs_test4 = {
    "/tmp/intel_ifs_0.test1_previous_image_fail",
    5,
    {
        {"current_batch", "0x3"},
        {"details", "0x8082"},
        {"image_version", "0x173"},
        {"run_test", "1"},
        {"status", "fail"}
    }
};

/* Load image */

static ifs_unit load_test2 = {
    "/tmp/intel_ifs_0.test2_previous_image_none",
    5,
    {
        {"current_batch", "none"},
        {"details", "0x8082"},
        {"image_version", "none"},
        {"run_test", "1"},
        {"status", "untested"}
    }
};

static ifs_unit load_test3 = {
    "/tmp/intel_ifs_0.test3_previous_image_cannot_be_parsed",
    5,
    {
        {"current_batch", "wxyz"},
        {"details", "0x8082"},
        {"image_version", "0x17a"},
        {"run_test", "1"},
        {"status", "other"}
    }
};

static ifs_unit load_test4 = {
    "/tmp/intel_ifs_0.test4_previous_image_untested",
    5,
    {
        {"current_batch", "0x4"},
        {"details", "0x8082"},
        {"image_version", "0x174"},
        {"run_test", "4"},
        {"status", "untested"}
    }
};

static ifs_unit load_test5 = {
    "/tmp/intel_ifs_0.test5_load_next_image",
    5,
    {
        {"current_batch", "0xa4"},
        {"details", "0x8082"},
        {"image_version", "0x17a"},
        {"run_test", "10"},
        {"status", "pass"}
    }
};

/* Trigger and execute */
static ifs_unit trigger_test1 = {
    "/tmp/intel_ifs_0.test1_all_cores_pass",
    5,
    {
        {"current_batch", "0x1"},
        {"details", "0x8082"},
        {"image_version", "0x171"},
        {"run_test", "1"},
        {"status", "pass"}
    }
};

static ifs_unit trigger_test2 = {
    "/tmp/intel_ifs_0.test2_all_cores_fail",
    5,
    {
        {"current_batch", "0x2"},
        {"details", "0x8082"},
        {"image_version", "0x172"},
        {"run_test", "1"},
        {"status", "fail"}
    }
};

static ifs_unit trigger_test3 = {
    "/tmp/intel_ifs_0.test3_only_one_core_fail",
    5,
    {
        {"current_batch", "0x3"},
        {"details", "0x8082"},
        {"image_version", "0x173"},
        {"run_test", "3"},
        {"status", "pass"}
    }
};

static ifs_unit trigger_test4 = {
    "/tmp/intel_ifs_0.test4_all_cores_untested",
    5,
    {
        {"current_batch", "0x4"},
        {"details", "0x600008082"},
        {"image_version", "0x174"},
        {"run_test", ""},
        {"status", "untested"}
    }
};

#endif //IFS_TEST_CASES_H_INCLUDED
