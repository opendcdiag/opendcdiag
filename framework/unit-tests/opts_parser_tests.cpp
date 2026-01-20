/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gtest/gtest.h"

#include "sandstone_opts.hpp"

FILE* test_stream = nullptr;

namespace {
static constexpr auto EMPTY_STR = "";

class StreamBuffer
{
public:
    StreamBuffer() {
#ifdef _WIN32
        test_stream = tmpfile();
#else
        test_stream = open_memstream(&buffer, &buflen);
#endif
    }

    ~StreamBuffer() {
        fclose(test_stream);
        free(buffer);
    }

    void check_eq(std::string_view expected, bool find_unittests_keyword = true) {
        flush();
        ASSERT_NE(buffer, nullptr);
        std::string buffer_stripped{buffer};
        buffer_stripped.erase(std::remove(buffer_stripped.begin(), buffer_stripped.end(), '\n'), buffer_stripped.cend());
        if (!find_unittests_keyword || expected == EMPTY_STR) {
            EXPECT_EQ(buffer_stripped, expected); // compare whole strings
            return;
        }
        check_eq_substr(buffer_stripped, expected);
    }

    void check_eqs(std::vector<std::string_view> expected, bool find_unittests_keyword = true) {
        flush();
        std::vector<std::string> got_strs;
        std::string tmp;
        ASSERT_NE(buffer, nullptr);
        std::stringstream ss(buffer);
        while (std::getline(ss, tmp, '\n')) {
            if (!tmp.empty()) {
                got_strs.emplace_back(tmp);
            }
        }

        ASSERT_EQ(got_strs.size(), expected.size());
        for (auto i = 0; i < got_strs.size(); i++) {
            if (find_unittests_keyword) {
                check_eq_substr(got_strs[i], expected[i]);
            } else {
                EXPECT_EQ(got_strs[i], expected[i]);
            }
        }
    }

private:
    // search for "unittests:" keyword and compare substrings. Useful when
    // message uses program_invocation_name
    void check_eq_substr(std::string_view got, std::string_view exp) const {
        auto n = got.find("unittests:"); // locate binary name
        ASSERT_NE(n, got.npos);
        auto substr = got.substr(n, got.size() - n);
        EXPECT_EQ(substr, exp);
    }

    void flush() {
        fflush(test_stream);

#ifdef _WIN32
        buflen = ftell(test_stream);
        if (buflen < 0)
            buflen = 0;
        buffer = (char *)malloc(buflen);
        fseek(test_stream, 0, SEEK_SET);
        fread(buffer, 1, buflen, test_stream);
#endif
    }

    char* buffer = nullptr;
    size_t buflen = 0;
};

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
        StreamBuffer sb;
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
        sb.check_eq(EMPTY_STR); // no messages printed
    }

    {
        StreamBuffer sb;
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
        sb.check_eq(EMPTY_STR); // no messages printed
    }

    {
        StreamBuffer sb;
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
        sb.check_eq(EMPTY_STR); // no messages printed
    }
}

TEST(ProgramOptionsParser, last_option_takes_precedence__output_format)
{
    StreamBuffer sb;
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
    sb.check_eq(EMPTY_STR); // no messages printed
}

TEST(ProgramOptionsParser, wrong_arguments_cause_print_help)
{
    StreamBuffer sb;
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
    sb.check_eq("Try 'foo-bar --help' for more information.", false); // from suggest_help();
}

TEST(ProgramOptionsParser, times_correctly_parsed)
{
    StreamBuffer sb;
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
    sb.check_eq(EMPTY_STR); // no messages printed
}

TEST(ProgramOptionsParser, last_option_takes_precedence__duration)
{
    {
        StreamBuffer sb;
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
        sb.check_eq(EMPTY_STR); // no messages printed
    }

    {
        StreamBuffer sb;
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
        sb.check_eq(EMPTY_STR); // no messages printed
    }
}

TEST(ProgramOptionsParser, last_option_takes_precedence__mtlp)
{
    {
        StreamBuffer sb;
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
        sb.check_eq(EMPTY_STR); // no messages printed
    }

    {
        StreamBuffer sb;
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
        sb.check_eq(EMPTY_STR); // no messages printed
    }
}

TEST(ProgramOptionsParser, last_option_takes_precedence__max_cores_per_slice)
{
    {
        StreamBuffer sb;
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
        sb.check_eq(EMPTY_STR); // no messages printed
    }

    {
        StreamBuffer sb;
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
        sb.check_eq(EMPTY_STR); // no messages printed
    }
}

TEST(ProgramOptionsParser, mtlp__zero_sets_to_maxint)
{
    StreamBuffer sb;
    ProgramOptions opts;
    SandstoneApplicationConfig cfg{};
    char* argv[] = {
        (char*)"foo-bar", // binary name
        (char*)"--max-test-loop-count=0",
    };
    auto ret = opts.parse(2, argv, &cfg);
    EXPECT_EQ(ret, EXIT_SUCCESS);
    EXPECT_EQ(cfg.max_test_loop_count, std::numeric_limits<int>::max());
    sb.check_eq(EMPTY_STR); // no messages printed
}

TEST(ProgramOptionsParser, test_selection_works)
{
    StreamBuffer sb;
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
    sb.check_eq(EMPTY_STR); // no messages printed
}

TEST(ProgramOptionsParser, saturation_works__thread_count)
{
    { // max
        StreamBuffer sb;
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
        sb.check_eq("unittests: warning: value out of range for option '-n / --threads': 49 (minimum is 1, maximum 48)");
    }

    { // min
        StreamBuffer sb;
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
        sb.check_eq("unittests: warning: value out of range for option '-n / --threads': -123 (minimum is 1, maximum 1000)");
    }

    { // in range
        StreamBuffer sb;
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
        sb.check_eq(EMPTY_STR); // no messages printed
    }
}

TEST(ProgramOptionsParser, saturation_works__retest_on_failure)
{
    { // max
        static_assert(SandstoneApplication::MaxRetestCount < 123456, "MaxRetestCount seems to has changed, please update this test");
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--retest-on-failure=123456",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.retest_count, SandstoneApplication::MaxRetestCount);
        sb.check_eq("unittests: warning: value out of range for option '--retest-on-failure': 123456 (minimum is 0, maximum 128)");
    }

    { // min
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--retest-on-failure=-123",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.retest_count, 0);
        sb.check_eq("unittests: warning: value out of range for option '--retest-on-failure': -123 (minimum is 0, maximum 128)");
    }

    { // in range
        static_assert(SandstoneApplication::MaxRetestCount >= 9, "MaxRetestCount seems to has changed, please update this test");
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--retest-on-failure=9",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.retest_count, 9);
        sb.check_eq(EMPTY_STR); // no messages printed
    }
}

TEST(ProgramOptionsParser, saturation_works__max_messages)
{
    { // max
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-messages=12345786234837246823648237648326",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(opts.shmem_cfg.max_messages_per_thread, std::numeric_limits<int>::max());
        sb.check_eqs({
            "unittests: warning: value out of range for option '--max-messages': 12345786234837246823648237648326 (minimum is -1, maximum 2147483647)",
            "unittests: value is maximum number of messages (per thread) to log in each test (0 is unlimited)"
        });
    }

    { // min
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-messages=-123",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(opts.shmem_cfg.max_messages_per_thread, INT_MAX);
        sb.check_eqs({
            "unittests: warning: value out of range for option '--max-messages': -123 (minimum is -1, maximum 2147483647)",
            "unittests: value is maximum number of messages (per thread) to log in each test (0 is unlimited)"
        });
    }

    { // in range
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-messages=1234",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(opts.shmem_cfg.max_messages_per_thread, 1234);
        sb.check_eq(EMPTY_STR); // no messages printed
    }
}

TEST(ProgramOptionsParser, duration_set_to_forever_works)
{
    StreamBuffer sb;
    ProgramOptions opts;
    SandstoneApplicationConfig cfg{};
    char* argv[] = {
        (char*)"foo-bar", // binary name
        (char*)"--total-time=forever",
    };
    auto ret = opts.parse(2, argv, &cfg);
    EXPECT_EQ(ret, EXIT_SUCCESS);
    EXPECT_EQ(cfg.endtime, MonotonicTimePoint::max());
    sb.check_eq(EMPTY_STR); // no messages printed
}

TEST(ProgramOptionsParser, last_option_takes_precedence__quality)
{
    {
        StreamBuffer sb;
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
        sb.check_eq(EMPTY_STR); // no messages printed
    }

    {
        StreamBuffer sb;
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
        sb.check_eq(EMPTY_STR); // no messages printed
    }

    {
        StreamBuffer sb;
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
        sb.check_eq(EMPTY_STR); // no messages printed
    }
}

TEST(ProgramOptionsParser, saturation_works__quality)
{
    { // max
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--quality=1234",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.requested_quality, TEST_QUALITY_PROD);
        sb.check_eq("unittests: warning: value out of range for option '--quality': 1234 (minimum is -1, maximum 2)");
    }

    { // min
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--quality=-123",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.requested_quality, TEST_QUALITY_SKIP);
        sb.check_eq("unittests: warning: value out of range for option '--quality': -123 (minimum is -1, maximum 2)");
    }

    { // in range
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--quality=0",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.requested_quality, 0);
        sb.check_eq(EMPTY_STR); // no messages printed
    }
}

TEST(ProgramOptionsParser, saturation_works__inject_idle)
{
    { // max
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--inject-idle=1234",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.inject_idle, 50);
        sb.check_eq("unittests: warning: value out of range for option '--inject-idle': 1234 (minimum is 0, maximum 50)");
    }

    { // min
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--inject-idle=-123",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.inject_idle, 0);
        sb.check_eq("unittests: warning: value out of range for option '--inject-idle': -123 (minimum is 0, maximum 50)");
    }

    { // in range
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--inject-idle=25",
        };
        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.inject_idle, 25);
        sb.check_eq(EMPTY_STR); // no messages printed
    }
}

TEST(ProgramOptionsParser, invalid_int_from_string_conversion_exits)
{
    StreamBuffer sb;
    ProgramOptions opts;
    SandstoneApplicationConfig cfg{};
    char* argv[] = {
        (char*)"foo-bar", // binary name
        (char*)"--quality=foo",
    };
    auto ret = opts.parse(2, argv, &cfg);
    EXPECT_EQ(ret, EX_USAGE);
    sb.check_eq("unittests: invalid argument for option '--quality': foo");
}

TEST(ProgramOptionsParser, out_of_range_exits__max_test_count)
{
    { // max
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-test-count=21367342534765237465324",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EX_USAGE);
        sb.check_eq("unittests: error: value out of range for option '--max-test-count': 21367342534765237465324 (minimum is 0, maximum 2147483647)");
    }

    { // min
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-test-count=-123",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EX_USAGE);
        sb.check_eq("unittests: error: value out of range for option '--max-test-count': -123 (minimum is 0, maximum 2147483647)");
    }

    { // in range
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-test-count=123",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.max_test_count, 123);
        sb.check_eq(EMPTY_STR); // no messages printed
    }
}

TEST(ProgramOptionsParser, out_of_range_exits__max_test_loop_count)
{
    { // max
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-test-loop-count=21367342534765237465324",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EX_USAGE);
        sb.check_eq("unittests: error: value out of range for option '--max-test-loop-count': 21367342534765237465324 (minimum is 0, maximum 2147483647)");
    }

    { // min
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-test-loop-count=-123",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EX_USAGE);
        sb.check_eq("unittests: error: value out of range for option '--max-test-loop-count': -123 (minimum is 0, maximum 2147483647)");
    }

    { // in range
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-test-loop-count=123",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(cfg.max_test_loop_count, 123);
        sb.check_eq(EMPTY_STR); // no messages printed
    }
}

TEST(ProgramOptionsParser, out_of_range_exits__yaml)
{
    { // max
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--yaml=161",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EX_USAGE);
        sb.check_eq("unittests: error: value out of range for option '-Y / --yaml': 161 (minimum is 0, maximum 160)");
    }

    { // min
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--yaml=-1",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EX_USAGE);
        sb.check_eq("unittests: error: value out of range for option '-Y / --yaml': -1 (minimum is 0, maximum 160)");
    }

    { // in range
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--yaml=12",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(opts.shmem_cfg.output_yaml_indent, 12);
        sb.check_eq(EMPTY_STR); // no messages printed
    }
}

TEST(ProgramOptionsParser, out_of_range_exits__max_cores_per_slice)
{
    { // max
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-cores-per-slice=1233242345823794723234",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EX_USAGE);
        sb.check_eq("unittests: error: value out of range for option '--max-cores-per-slice': 1233242345823794723234 (minimum is -1, maximum 2147483647)");
    }

    { // min
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-cores-per-slice=-2",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EX_USAGE);
        sb.check_eq("unittests: error: value out of range for option '--max-cores-per-slice': -2 (minimum is -1, maximum 2147483647)");
    }

    { // in range
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--max-cores-per-slice=-1",
        };

        auto ret = opts.parse(2, argv, &cfg);
        EXPECT_EQ(ret, EXIT_SUCCESS);
        EXPECT_EQ(opts.max_cores_per_slice, -1);
        sb.check_eq(EMPTY_STR); // no messages printed
    }
}


TEST(ProgramOptionsParser, repeated_opt_accumulates__cpuset_deviceset)
{
    {
        StreamBuffer sb;
        ProgramOptions opts;
        SandstoneApplicationConfig cfg{};
        char* argv[] = {
            (char*)"foo-bar", // binary name
            (char*)"--cpuset=1",
            (char*)"--cpuset=2",
            (char*)"--deviceset=3",
        };

        auto ret = opts.parse(4, argv, &cfg);
        EXPECT_FALSE(opts.deviceset.empty());
        EXPECT_STREQ(opts.deviceset.at(0), "1");
        EXPECT_STREQ(opts.deviceset.at(1), "2");
        EXPECT_STREQ(opts.deviceset.at(2), "3");

        EXPECT_EQ(ret, EXIT_SUCCESS);
        sb.check_eq(EMPTY_STR); // no messages printed
    }
}
