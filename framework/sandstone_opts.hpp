/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_SANDSTONE_OPTS_H
#define INC_SANDSTONE_OPTS_H

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
    int max_cores_per_slice_ = 0;
    int max_cores_per_slice() const {
        // in RestrictedCommandLine mode, allow compiler to optimize the variable to a static value
        if constexpr (SandstoneConfig::RestrictedCommandLine)
            return 0;
        return max_cores_per_slice_;
    }
    int thread_count_ = -1;
    int thread_count() const {
        if constexpr (SandstoneConfig::RestrictedCommandLine)
            return -1;
        return thread_count_;
    }
    bool fatal_errors = false;
    const char* on_hang_arg = nullptr;
    const char* on_crash_arg = nullptr;
    char* cpuset = nullptr;

    const char* list_group_name = nullptr; // for list_group
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
};

int parse_cmdline(int argc, char** argv, SandstoneApplication* app, ParsedCmdLineOpts& opts);

#endif /* INC_SANDSTONE_OPTS_H */
