/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_LOGGING_H
#define INC_LOGGING_H

#include "sandstone_chrono.h"
#include "sandstone_config.h"
#include "sandstone_p.h"

#include "gitid.h"

#include <string>
#include <span>

class AbstractLogger
{
public:
    AbstractLogger(const struct test *test, std::span<const ChildExitStatus> state);

    static constexpr char program_version[] = SANDSTONE_EXECUTABLE_NAME "-" GIT_ID;
    static int real_stdout_fd;
    static int file_log_fd;

    const struct test *test;
    MonotonicTimePoint earliest_fail = MonotonicTimePoint::max();
    std::span<const ChildExitStatus> slices;
    ChildExitStatus childExitStatus;
    TestResult testResult = TestResult::Passed;
    int pc = 0;
    bool skipInMainThread = false;

protected:
    int loglevel() const;
    bool should_print_fail_info() const;

    // shared between the TAP and key-value loggers; YAML overrides
    static void format_and_print_message(int fd, std::string_view message, bool from_thread_message);
    int print_one_thread_messages_tdata(int fd, PerThreadData::Common *data, struct mmap_region r, int level);
};

class YamlLogger : public AbstractLogger
{
public:
    YamlLogger(const struct test *test, std::span<const ChildExitStatus> state)
        : AbstractLogger(test, state)
    { }

    static std::string get_current_time();

    // non-virtual override
    void print();
    static void print_header(std::string_view cmdline, Duration test_duration, Duration test_timeout);

    enum TestHeaderTime { AtStart, OnFirstFail };
    static void print_tests_header(TestHeaderTime mode);

protected:
    std::string fail_info_details();
    static void format_and_print_message(int fd, std::string_view level, std::string_view message);

private:
    int init_skip_message_bytes = 0;
    bool file_printed_messages_header = false;
    bool stdout_printed_messages_header = false;

    static std::string thread_id_header(int device, int verbosity);
    void maybe_print_messages_header(int fd);
    void print_fixed();
    void print_thread_messages();
    void print_thread_header(int fd, int device, int verbosity);
    void maybe_print_slice_resource_usage(int fd, int slice);
    static int print_test_knobs(int fd, mmap_region r);
    static void format_and_print_skip_reason(int fd, std::string_view message);
    int print_one_thread_messages(int fd, mmap_region r, int level);
    void print_result_line(int &init_skip_message_bytes);
};

std::string log_timestamp();
std::string get_skip_message(int thread_num);
const char *char_to_skip_category(int val);
mmap_region maybe_mmap_log(const PerThreadData::Common *data);
void munmap_and_truncate_log(PerThreadData::Common *data, mmap_region r);
void print_child_stderr_common(std::function<void(int)> header);
const char *quality_string(const struct test *test);
std::string format_duration(MonotonicTimePoint tp, FormatDurationOptions opts = FormatDurationOptions::WithoutUnit);
[[gnu::pure]] const char *crash_reason(const ChildExitStatus &status);
[[gnu::pure]] const char *sysexit_reason(const ChildExitStatus &status);

#if !SANDSTONE_DEVICE_CPU || SANDSTONE_NO_LOGGING
// there's only one use of this, in logging.cpp, so let the compiler
// eliminate anything not used
namespace {
#endif

enum class Iso8601Format : unsigned {
    WithoutMs           = 0,
    WithMs              = 1,
    FilenameCompatible  = 2,
};
const char *iso8601_time_now(Iso8601Format format);

std::string thread_id_header_for_device(int device, int verbosity);
#if SANDSTONE_NO_LOGGING
inline std::string thread_id_header_for_device(int device, int verbosity)
{ __builtin_unreachable(); return {}; }
#endif

#if !SANDSTONE_DEVICE_CPU || SANDSTONE_NO_LOGGING
} // unnamed namespace
#endif

#endif /* INC_LOGGING_H */
