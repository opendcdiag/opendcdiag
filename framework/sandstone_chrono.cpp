/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_chrono.h"
#include "sandstone_p.h"

#include <charconv>
#include <optional>

using namespace std;
using namespace std::chrono;

// like std::chrono::duration_cast, but with overflow checking
template <typename To, typename Rep, typename Period> static std::optional<To>
duration_cast_overflow(duration<Rep, Period> from)
{
    using ToRep = typename To::rep;
    using Ratio = std::ratio_divide<Period, typename To::period>;
    static_assert(Ratio::den == 1, "Unsupported conversion, use std::chrono::duration_cast");

    auto value = ToRep(from.count());
    if (value != from.count())
        return std::nullopt;
    if (__builtin_mul_overflow(value, ToRep(Ratio::num), &value))
        return std::nullopt;
    return To(value);
}

ShortDuration string_to_millisecs(string_view in_string)
{
    if (in_string.size() == 0)
        return {};

    const char *error_reason = nullptr;
    ShortDuration::rep value;
    std::from_chars_result r = std::from_chars(in_string.begin(), in_string.end(), value, 10);
    if (r.ec == std::errc{}) {
        string_view suffix = in_string.substr(r.ptr - in_string.data());
        std::optional<ShortDuration> result;
        if (suffix == "ms" || suffix.size() == 0)
            result = duration_cast_overflow<ShortDuration>(milliseconds(value));
        else if (suffix == "s")
            result = duration_cast_overflow<ShortDuration>(seconds(value));
        else if (suffix == "m" || suffix == "min")
            result = duration_cast_overflow<ShortDuration>(minutes(value));
        else if (suffix == "h")
            result = duration_cast_overflow<ShortDuration>(hours(value));
        else
            error_reason = "unknown time unit";

        if (result)
            return *result;
        else if (!error_reason)
            error_reason = "time out of range";
    } else if (r.ec == std::errc::result_out_of_range) {
        error_reason = "time out of range";
    } else if (r.ec == std::errc::invalid_argument) {
        error_reason = "could not parse";   // probably not a number!
    }

    if (error_reason) {
        fprintf(stderr, "%s: invalid time \"%.*s\": %s\n", program_invocation_name,
                int(in_string.size()), in_string.data(), error_reason);
        exit(EX_USAGE);
    }

    return ShortDuration(value);
}

string format_duration(std::chrono::nanoseconds ns, FormatDurationOptions opts)
{
    using namespace std::chrono;
    std::string result;

    if (ns.count() < 0) {
        result += "0.0";
    } else {
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
    }

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
