/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_chrono.h"
#include "sandstone_p.h"

#include <charconv>

using namespace std;
using namespace std::chrono;

milliseconds string_to_millisecs(string_view in_string)
{
    if (in_string.size() == 0)
        return {};

    milliseconds::rep value;
    std::from_chars_result r = std::from_chars(in_string.begin(), in_string.end(), value, 10);
    if (r.ec == std::errc{}) {
        string_view suffix = in_string.substr(r.ptr - in_string.data());
        if (suffix == "ms" || suffix.size() == 0)
            return std::chrono::milliseconds(value);
        if (suffix == "s")
            return std::chrono::seconds(value);
        if (suffix == "m" || suffix == "min")
            return std::chrono::minutes(value);
        if (suffix == "h")
            return std::chrono::hours(value);
    }
    fprintf(stderr, "%s: Invalid time: \"%.*s\"\n", program_invocation_name,
            int(in_string.size()), in_string.data());
    exit(EX_USAGE);
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
