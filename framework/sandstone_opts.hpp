/*
 * Copyright 2024 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_OPTS
#define SANDSTONE_OPTS

#include "sandstone_tests.h"

enum class Action {
    list_tests,
    list_group,
    dump_cpu_info,
    version,
    exit,
    run,
};

struct ParsedCmdLineOpts {
    Action action = Action::run; // action to be taken after cmdline parsing is done, default: run tests

    const char* seed = nullptr;
    int max_cores_per_slice = 0;
    int thread_count = -1;
    bool fatal_errors = false;
    const char* on_hang_arg = nullptr;
    const char* on_crash_arg = nullptr;
    std::string cpuset;

    std::string list_group_name; // for list_group
    bool list_tests_include_descriptions = false; // for list_tests
    bool list_tests_include_tests = false; // for list_tests
    bool list_tests_include_groups = false; // for list_tests

    // test selection
    std::vector<const char *> enabled_tests;
    std::vector<const char *> disabled_tests;
    const char *test_list_file_path = nullptr;

    struct test_set_cfg test_set_config = {
        .ignore_unknown_tests = false,
        .randomize = false,
        .cycle_through = false,
    };
    const char *builtin_test_list_name = nullptr;
    int starting_test_number = 1;  // One based count for user interface, not zero based
    int ending_test_number = INT_MAX;
};

int parse_cmdline(int argc, char** argv, SandstoneApplication* app, ParsedCmdLineOpts& opts);

#endif /* SANDSTONE_OPTS */
