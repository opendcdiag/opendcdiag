/*
 * Copyright 2024 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gtest/gtest.h"

#include "sandstone_opts.hpp"

#include "boost/algorithm/string.hpp"

#include <cstring>

namespace {
std::optional<ParsedOpts> call_parse_and_validate(const char* cmdline, SandstoneApplication* app) {
    std::vector<std::string> cmdline_vec;
    auto cmdline_vecs = boost::algorithm::split(cmdline_vec, cmdline, boost::is_any_of("\t "), boost::token_compress_on);

    std::vector<char*> argv;
    argv.reserve(cmdline_vec.size());
    for (auto& token: cmdline_vec) {
        argv.emplace_back(&token[0]);
    }

    return parse_and_validate(argv.size(), argv.data(), app);
}

auto sApp_deleter = [](SandstoneApplication* app) { delete app->shmem; };
using sApp_ptr = std::unique_ptr<SandstoneApplication, decltype(sApp_deleter)>;
sApp_ptr mock_sApp() {
    sApp_ptr res(new_sApp(), sApp_deleter);
    res->shmem = new SandstoneApplication::SharedMemory;
    // we do not set shmemfd, shmem->thread_data_offset, shmem->main_process_pid, just zero initialize SharedMemory
    return res;
}

auto pred_2_variants = [](const char* what, const char* str1, const char* str2) {
    return strcmp(what, str1) == 0 || strcmp(what, str2) == 0;
};
}

TEST(OptsValidation, Verbosity) {
    auto app = mock_sApp();
    static constexpr auto cmdline = "opendcdiag -v -v -vv";
    try {
        [[maybe_unused]] auto opts = call_parse_and_validate(cmdline, app.get());
        ASSERT_EQ(app->shmem->verbosity, 4);
    } catch (std::exception& e) {
        FAIL() << "Got unexpected error";
    }
}

TEST(OptsValidation, ExclusionQuality) {
    auto app = mock_sApp();
    static constexpr auto cmdline = "opendcdiag --beta --quality 1";
    try {
        [[maybe_unused]] auto opts = call_parse_and_validate(cmdline, app.get());
        FAIL() << "Expected to throw";
    } catch (std::exception& e) {
        EXPECT_PRED3(
            pred_2_variants,
            e.what(),
            "Options beta and quality are mutually exclusive",
            "Options quality and beta are mutually exclusive"
        );
    }
}

TEST(OptsValidation, ExclusionSlicing) {
    auto app = mock_sApp();
    static constexpr auto cmdline = "opendcdiag --max-cores-per-slice 77 --no-slicing";
    try {
        [[maybe_unused]] auto opts = call_parse_and_validate(cmdline, app.get());
        FAIL() << "Expected to throw";
    } catch (std::exception& e) {
        EXPECT_PRED3(
            pred_2_variants,
            e.what(),
            "Options max-cores-per-slice and no-slicing are mutually exclusive",
            "Options no-slicing and max-cores-per-slice are mutually exclusive"
        );
    }
}
