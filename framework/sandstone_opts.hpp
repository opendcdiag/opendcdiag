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

struct ProgramOptions {
    Action action = Action::run; // action to be taken after cmdline parsing is done, default: run tests

    const char* seed = nullptr;
    int max_cores_per_slice = 0;
    int thread_count = -1;
    bool fatal_errors = false;
    const char* on_hang_arg = nullptr;
    const char* on_crash_arg = nullptr;
    std::string deviceset; // not sure about those strings...

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

    int parse(int argc, char** argv, SandstoneApplication* app, ProgramOptions& opts);

    // for RestrictedCommandLine put it here to enable code elimination
    void apply_restrictions() {
        seed = nullptr;
        max_cores_per_slice = 0;
        thread_count = -1;
        fatal_errors = true;
        on_hang_arg = nullptr;
        on_crash_arg = nullptr;
        builtin_test_list_name = "auto";
    }
};

inline int parse_cmdline(int argc, char** argv, SandstoneApplication* app, ProgramOptions& opts) {
    auto ret = opts.parse(argc, argv, app, opts);
    if constexpr (SandstoneConfig::RestrictedCommandLine) {
        opts.apply_restrictions(); // enable code elimination
    }
    return ret;
}

#endif /* INC_SANDSTONE_OPTS_H */
