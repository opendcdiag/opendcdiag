/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef LOGGING_CPU_H
#define LOGGING_CPU_H

#include "logging.h"

#if !SANDSTONE_NO_LOGGING

class KeyValuePairLogger : public YamlLogger
{
public:
    KeyValuePairLogger(const struct test *test, std::span<const ChildExitStatus> state)
        : YamlLogger(test, state)
    {
        prepare_line_prefix();
    }

    void print(int tc);

private:
    std::string timestamp_prefix;

    void prepare_line_prefix();
    void print_thread_header(int fd, int device, const char *prefix);
    void print_thread_messages();
    void print_child_stderr();
};

class TapFormatLogger : public YamlLogger
{
public:
    TapFormatLogger(const struct test *test, std::span<const ChildExitStatus> state)
        : YamlLogger(test, state)
    {}

    void print(int tc);

private:
    const char *file_terminator = nullptr;
    const char *stdout_terminator = nullptr;

    static const char *quality_string(const struct test *test);
    void maybe_print_yaml_marker(int fd);
    void print_thread_messages();
    void print_thread_header(int fd, int device, int verbosity);
    void print_child_stderr();
    std::string format_status_code();
};

#endif // !SANDSTONE_NO_LOGGING

#endif // LOGGING_CPU_H
