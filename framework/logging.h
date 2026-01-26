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

#include <functional>
#include <string>
#include <span>

// Whether only the YAML logger is compiled in. This includes the NO_LOGGING
// case, which is disabled via dead-code elimination in logging.cpp.
#define SANDSTONE_LOGGING_YAML_ONLY (!SANDSTONE_DEVICE_CPU || SANDSTONE_NO_LOGGING)

enum class Iso8601Format : unsigned {
    WithoutMs           = 0,
    WithMs              = 1,
    FilenameCompatible  = 2,
};

class AbstractLogger
{
public:
    enum class LogTypes : uint8_t;

    AbstractLogger(const struct test *test, std::span<const ChildExitStatus> state);

    static constexpr char program_version[] = SANDSTONE_EXECUTABLE_NAME "-" GIT_ID;
    static int real_stdout_fd;
    static int file_log_fd;

    static const char *iso8601_time_now(Iso8601Format format);
    static std::string log_timestamp();
    static std::string get_skip_message(int thread_num);
    static const char *char_to_skip_category(int val);
    static mmap_region maybe_mmap_log(const PerThreadData::Common *data);
    static void munmap_and_truncate_log(PerThreadData::Common *data, mmap_region r);
    static void print_child_stderr_common(std::function<void(int)> header);
    static std::string_view indent_spaces();

    static std::string format_duration(MonotonicTimePoint tp, FormatDurationOptions opts = FormatDurationOptions::WithoutUnit)
    {
        if (tp <= MonotonicTimePoint() || tp == MonotonicTimePoint::max())
            return {};

        return ::format_duration(tp - sApp->current_test_starttime, opts);
    }
    [[gnu::pure]] static const char *crash_reason(const ChildExitStatus &status);
    [[gnu::pure]] static const char *sysexit_reason(const ChildExitStatus &status);

    // device-specific interfaces
    static std::string thread_id_header_for_device(int device, LogLevelVerbosity verbosity);
    static void print_thread_header_for_device(int fd, PerThreadData::Test *thr);
    static void print_fixed_for_device();

    const struct test *test;
    MonotonicTimePoint earliest_fail = MonotonicTimePoint::max();
    std::span<const ChildExitStatus> slices;
    ChildExitStatus childExitStatus;
    TestResult testResult = TestResult::Passed;
    int pc = 0;
    bool skipInMainThread = false;

protected:
    LogLevelVerbosity loglevel() const;
    bool should_print_fail_info() const;

    // shared between the TAP and key-value loggers; YAML overrides
    static void format_and_print_message(int fd, std::string_view message, bool from_thread_message);
    LogLevelVerbosity print_one_thread_messages_tdata(int fd, PerThreadData::Common *data, struct mmap_region r, LogLevelVerbosity level);
};

class YamlLogger : public AbstractLogger
{
public:
    YamlLogger(const struct test *test, std::span<const ChildExitStatus> state)
        : AbstractLogger(test, state)
    { }

    static inline std::string get_current_time();
    static const char *quality_string(const struct test *test);

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

    inline void maybe_print_messages_header(int fd);
    void print_fixed();
    void print_thread_messages();
    void print_thread_header(int fd, int device, LogLevelVerbosity verbosity);
    inline bool want_slice_resource_usage(int slice);
    void maybe_print_slice_resource_usage(int fd, int slice);
    inline int print_test_knobs(int fd, mmap_region r);
    static void format_and_print_skip_reason(int fd, std::string_view message);
    LogLevelVerbosity print_one_thread_messages(int fd, mmap_region r, LogLevelVerbosity level);
    void print_result_line(int &init_skip_message_bytes);

    static void maybe_print_virt_state();
};

#if SANDSTONE_NO_LOGGING
inline std::string AbstractLogger::thread_id_header_for_device(int device, LogLevelVerbosity verbosity)
{ __builtin_unreachable(); return {}; }
inline void AbstractLogger::print_thread_header_for_device(int fd, PerThreadData::Test *thr)
{ __builtin_unreachable(); }
inline void AbstractLogger::print_fixed_for_device()
{ __builtin_unreachable(); }
#endif

#endif /* INC_LOGGING_H */
