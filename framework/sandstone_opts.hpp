/*
 * Copyright 2024 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_OPTS
#define SANDSTONE_OPTS

#include "sandstone_tests.h"
#include "sandstone_utils.h"

#include <string>
#include <vector>

struct ParsedOpts {
    std::string seed;
    int max_cores_per_slice = 0;
    int thread_count = -1;
    bool fatal_errors = false;
    std::string on_hang_arg;
    std::string on_crash_arg;

    // test selection
    std::vector<std::string> enabled_tests;
    std::vector<std::string> disabled_tests;
    std::string test_list_file_path;

    struct test_set_cfg test_set_config = {
        .ignore_unknown_tests = false,
        .randomize = false,
        .cycle_through = false,
    };
    std::string builtin_test_list_name;
    int starting_test_number = 1;  // One based count for user interface, not zero based
    int ending_test_number = INT_MAX;
};

std::optional<ParsedOpts> parse_and_validate(int argc, char **argv, SandstoneApplication* app);

#endif /* SANDSTONE_OPTS */
