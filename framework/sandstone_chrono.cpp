/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_chrono.h"
#include "sandstone_utils.h"

#include <charconv>

using namespace std;
using namespace std::chrono;

std::chrono::milliseconds string_to_millisecs(const string &in_string)
{
    std::size_t next_char_ptr;
    if (in_string == "")
        return {};
    try {
        auto value = stoi(in_string, &next_char_ptr, 0);

        if (in_string.substr(next_char_ptr, 2) == "ms")
            return std::chrono::milliseconds(value);
        if (in_string[next_char_ptr] == 's')
            return std::chrono::seconds(value);
        if (in_string[next_char_ptr] == 'm')
            return std::chrono::minutes(value);
        if (in_string[next_char_ptr] == 'h')
            return std::chrono::hours(value);
        return std::chrono::milliseconds(value);
    } catch (const std::exception &) {
        fprintf(stderr, "Invalid time: \"%s\"\n", in_string.c_str());
        exit(EX_USAGE);
    }
}

string format_duration(std::chrono::nanoseconds ns, FormatDurationOptions opts)
{
    using namespace std::chrono;
    std::string result;

    auto us = duration_cast<microseconds>(ns);
    milliseconds ms = duration_cast<milliseconds>(us);
    us -= ms;

    result = std::to_string(ms.count());
    size_t i = result.size();
    result.reserve(i + 7);
    result.resize(i + 4);
    result[i++] = '.';
    if (us.count() < 100)
        result[i++] = '0';
    if (us.count() < 10)
        result[i++] = '0';
    std::to_chars(result.data() + i, result.data() + result.size(), us.count(), 10);
    if (unsigned(opts) & unsigned(FormatDurationOptions::WithUnit))
        result += " ms";
    return result;
}

#ifdef CLOCK_MONOTONIC_COARSE
coarse_steady_clock::time_point coarse_steady_clock::now() noexcept
{
    struct timespec ts;
    get_monotonic_time_now(&ts);
    return time_point(seconds(ts.tv_sec) + nanoseconds(ts.tv_nsec));
}
#endif
