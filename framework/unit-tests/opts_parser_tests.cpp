/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gtest/gtest.h"

#include "sandstone_opts.hpp"

namespace {
class DummyScheduler : public DeviceScheduler
{
public:
    void reschedule_to_next_device() override {};
    void finish_reschedule() override {};
};
} // unnamed namespace

std::unique_ptr<DeviceScheduler> make_rescheduler(std::string_view mode)
{
    return std::make_unique<DummyScheduler>();
}

TEST(ProgramOptionsParser, last_option_takes_precedence__action)
{
    {
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--version",
            (char*)"-h",
            (char*)"--list-group-members=foo",
            (char*)"--list",
            (char*)"--list-tests",
            (char*)"--list-groups",
            (char*)"--dump-cpu-info",
        };
        auto ret = opts.parse(8, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(opts.action, Action::dump_cpu_info);
    }

    {
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--version",
            (char*)"-h",
            (char*)"--list-group-members=foo",
            (char*)"--list-tests",
            (char*)"--list-groups",
            (char*)"--dump-cpu-info",
            (char*)"--list",
        };
        auto ret = opts.parse(8, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(opts.action, Action::list_tests);
    }

    {
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--version",
            (char*)"-h",
            (char*)"--list-tests",
            (char*)"--dump-cpu-info",
            (char*)"--list",
            (char*)"--list-groups",
            (char*)"--list-group-members=foo",
        };
        auto ret = opts.parse(8, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(opts.action, Action::list_group);
        EXPECT_EQ(opts.list_group_name, "foo");
    }
}

TEST(ProgramOptionsParser, last_option_takes_precedence__output_format)
{
    ProgramOptions opts;
    SandstoneApplicationConfig cfg{};
    char* argv[] = {
        (char*)"foo-bar", // binary name
        (char*)"-Y",
        (char*)"--output-format=tap",
        (char*)"-Y7",
    };
    auto ret = opts.parse(4, argv, &cfg);
    EXPECT_EQ(ret, EXIT_SUCCESS);
    EXPECT_EQ(opts.shmem_cfg.output_format, SandstoneApplication::OutputFormat::yaml);
    EXPECT_EQ(opts.shmem_cfg.output_yaml_indent, 7);
}

TEST(ProgramOptionsParser, wrong_arguments_cause_print_help)
{
    ProgramOptions opts;
    SandstoneApplicationConfig cfg{};
    char* argv[] = {
        (char*)"foo-bar", // binary name
        (char*)"--non-existing-opt-1",
        (char*)"--non-existing-opt-2=foo",
        (char*)"--dump-cpu-info", // one correct argument
        (char*)"--non-existing-opt-3",
        (char*)"--non-existing-opt-4=bar",
    };
    auto ret = opts.parse(6, argv, &cfg);
    EXPECT_EQ(ret, EX_USAGE);
    // this is default action which was not overriden due to unrecognized option error
    EXPECT_EQ(opts.action, Action::run);
}

TEST(ProgramOptionsParser, times_correctly_parsed)
{
    ProgramOptions opts;
    SandstoneApplicationConfig cfg{};
    char* argv[] = {
        (char*)"foo-bar", // binary name
        (char*)"--test-time=2m",
        (char*)"--timeout=3600000ms",
        (char*)"--timeout-kill=15s",
        (char*)"--test-delay=48h",
    };
    auto ret = opts.parse(5, argv, &cfg);
    EXPECT_EQ(ret, EXIT_SUCCESS);
    EXPECT_EQ(cfg.test_time, std::chrono::minutes(2));
    EXPECT_EQ(cfg.max_test_time, std::chrono::hours(1));
    EXPECT_EQ(cfg.timeout_to_kill, std::chrono::seconds(15));
    EXPECT_EQ(cfg.delay_between_tests, std::chrono::days(2));
}

TEST(ProgramOptionsParser, last_option_takes_precedence__duration)
{
    {
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--total-time=123s",
            (char*)"--1sec",
            (char*)"--30sec",
            (char*)"--5min",
            (char*)"--2min",
        };
        auto ret = opts.parse(6, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.endtime - cfg.starttime, std::chrono::minutes(2));
    }

    {
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--1sec",
            (char*)"--30sec",
            (char*)"--5min",
            (char*)"--2min",
            (char*)"--total-time=123s",
        };
        auto ret = opts.parse(6, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.endtime - cfg.starttime, std::chrono::seconds(123));
    }
}

TEST(ProgramOptionsParser, last_option_takes_precedence__mtlp)
{
    {
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-test-loop-count=100",
            (char*)"--quick",
        };
        auto ret = opts.parse(3, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.max_test_loop_count, 1);
    }

    {
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--quick",
            (char*)"--max-test-loop-count=123",
        };
        auto ret = opts.parse(3, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.max_test_loop_count, 123);
    }
}

TEST(ProgramOptionsParser, last_option_takes_precedence__max_cores_per_slice)
{
    {
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-cores-per-slice=100",
            (char*)"--no-slicing",
        };
        auto ret = opts.parse(3, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(opts.max_cores_per_slice, -1);
    }

    {
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--no-slicing",
            (char*)"--max-cores-per-slice=4",
        };
        auto ret = opts.parse(3, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(opts.max_cores_per_slice, 4);
    }
}

TEST(ProgramOptionsParser, mtlp__zero_sets_to_maxint)
{
    ProgramOptions opts;
    SandstoneApplicationConfig cfg{};
    char* argv[] = {
        (char*)"foo-bar", // binary name
        (char*)"--max-test-loop-count=0",
    };
    auto ret = opts.parse(2, argv, &cfg);
    EXPECT_EQ(ret, EXIT_SUCCESS);
    EXPECT_EQ(cfg.max_test_loop_count, std::numeric_limits<int>::max());
}

TEST(ProgramOptionsParser, test_selection_works)
{
    ProgramOptions opts;
    SandstoneApplicationConfig cfg{};
    char* argv[] = {
        (char*)"foo-bar", // binary name
        (char*)"--enable=foo",
        (char*)"--enable=bar",
        (char*)"--disable=baz",
        (char*)"--disable=qux",
    };
    auto ret = opts.parse(5, argv, &cfg);
    EXPECT_EQ(ret, EXIT_SUCCESS);
    EXPECT_EQ(opts.enabled_tests.size(), 2);
    EXPECT_TRUE(memcmp(opts.enabled_tests[0], "foo", 3) == 0);
    EXPECT_TRUE(memcmp(opts.enabled_tests[1], "bar", 3) == 0);
    EXPECT_EQ(opts.disabled_tests.size(), 2);
    EXPECT_TRUE(memcmp(opts.disabled_tests[0], "baz", 3) == 0);
    EXPECT_TRUE(memcmp(opts.disabled_tests[1], "qux", 3) == 0);
}

TEST(ProgramOptionsParser, saturation_works__thread_count)
{
    { // max
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--threads=49",
        };

        // simulate init_cpus() before parsing
        cfg.thread_count = 48;

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(opts.thread_count, 48);
    }

    { // min
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--threads=-123",
        };

        // simulate init_cpus() before parsing
        cfg.thread_count = 1000;

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(opts.thread_count, 1);
    }

    { // in range
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--threads=24",
        };

        // simulate init_cpus() before parsing
        cfg.thread_count = 48;

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(opts.thread_count, 24);
    }
}

TEST(ProgramOptionsParser, saturation_works__retest_on_failure)
{
    { // max
        static_assert(SandstoneApplication::MaxRetestCount < 123456, "MaxRetestCount seems to has changed, please update this test");
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--retest-on-failure=123456",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.retest_count, SandstoneApplication::MaxRetestCount);
    }

    { // min
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--retest-on-failure=-123",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.retest_count, 0);
    }

    { // in range
        static_assert(SandstoneApplication::MaxRetestCount >= 9, "MaxRetestCount seems to has changed, please update this test");
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--retest-on-failure=9",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.retest_count, 9);
    }
}

TEST(ProgramOptionsParser, saturation_works__max_messages)
{
    { // max
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-messages=12345786234837246823648237648326",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(opts.shmem_cfg.max_messages_per_thread, std::numeric_limits<int>::max());
    }

    { // min
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-messages=-123",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(opts.shmem_cfg.max_messages_per_thread, INT_MAX);
    }

    { // in range
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-messages=1234",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(opts.shmem_cfg.max_messages_per_thread, 1234);
    }
}

TEST(ProgramOptionsParser, duration_set_to_forever_works)
{
    ProgramOptions opts;
    SandstoneApplicationConfig cfg{};
    char* argv[] = {
        (char*)"foo-bar", // binary name
        (char*)"--total-time=forever",
    };
    auto ret = opts.parse(2, argv, &cfg);
    EXPECT_EQ(ret, EXIT_SUCCESS);
    EXPECT_EQ(cfg.endtime, MonotonicTimePoint::max());
}

TEST(ProgramOptionsParser, last_option_takes_precedence__quality)
{
    {
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--beta",
            (char*)"--alpha",
            (char*)"--quality=1",
        };
        auto ret = opts.parse(4, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.requested_quality, 1);
    }

    {
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--alpha",
            (char*)"--quality=1",
            (char*)"--beta",
        };
        auto ret = opts.parse(4, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.requested_quality, TEST_QUALITY_BETA);
    }

    {
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--beta",
            (char*)"--quality=1",
            (char*)"--alpha",
        };
        auto ret = opts.parse(4, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.requested_quality, TEST_QUALITY_SKIP);
    }
}

TEST(ProgramOptionsParser, saturation_works__quality)
{
    { // max
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--quality=1234",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.requested_quality, TEST_QUALITY_PROD);
    }

    { // min
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--quality=-123",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.requested_quality, TEST_QUALITY_SKIP);
    }

    { // in range
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--quality=0",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.requested_quality, 0);
    }
}

TEST(ProgramOptionsParser, saturation_works__inject_idle)
{
    { // max
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--inject-idle=1234",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.inject_idle, 50);
    }

    { // min
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--inject-idle=-123",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.inject_idle, 0);
    }

    { // in range
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--inject-idle=25",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.inject_idle, 25);
    }
}

TEST(ProgramOptionsParser, invalid_int_from_string_conversion_exits)
{
    ProgramOptions opts;
    SandstoneApplicationConfig cfg{};
    char* argv[] = {
        (char*)"foo-bar", // binary name
        (char*)"--quality=foo",
    };
    auto ret = opts.parse(2, argv, &cfg);
    EXPECT_EQ(ret, EX_USAGE);
}

TEST(ProgramOptionsParser, out_of_range_exits__max_test_count)
{
    { // max
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-test-count=21367342534765237465324",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EX_USAGE);
    }

    { // min
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-test-count=-123",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EX_USAGE);
    }

    { // in range
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-test-count=123",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.max_test_count, 123);
    }
}

TEST(ProgramOptionsParser, out_of_range_exits__max_test_loop_count)
{
    { // max
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-test-loop-count=21367342534765237465324",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EX_USAGE);
    }

    { // min
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-test-loop-count=-123",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EX_USAGE);
    }

    { // in range
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-test-loop-count=123",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.max_test_loop_count, 123);
    }
}

TEST(ProgramOptionsParser, out_of_range_exits__yaml)
{
    { // max
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--yaml=161",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EX_USAGE);
    }

    { // min
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--yaml=-1",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EX_USAGE);
    }

    { // in range
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--yaml=12",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(opts.shmem_cfg.output_yaml_indent, 12);
    }
}

TEST(ProgramOptionsParser, out_of_range_exits__max_cores_per_slice)
{
    { // max
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-cores-per-slice=1233242345823794723234",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EX_USAGE);
    }

    { // min
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-cores-per-slice=-2",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EX_USAGE);
    }

    { // in range
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-cores-per-slice=-1",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(opts.max_cores_per_slice, -1);
    }
}
