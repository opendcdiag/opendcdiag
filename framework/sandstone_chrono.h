/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_CHRONO_H
#define SANDSTONE_CHRONO_H

#include <time.h>

/// needs to be async-signal-safe
static inline int get_monotonic_time_now(struct timespec *tv)
{
#if defined(CLOCK_MONOTONIC_COARSE)
    return clock_gettime(CLOCK_MONOTONIC_COARSE, tv);
#elif defined(TIME_MONOTONIC)
    return timespec_get(tv, TIME_MONOTONIC);
#else
    return clock_gettime(CLOCK_MONOTONIC, tv);
#endif
}

#ifdef __cplusplus
#include <chrono>
#include <string>

using Duration = std::chrono::steady_clock::duration;
using ShortDuration = std::chrono::duration<int, std::milli>;   // +/- 24.85 days
using MonotonicTimePoint = std::chrono::steady_clock::time_point;

struct coarse_steady_clock : std::chrono::steady_clock
{
    using time_point = std::chrono::time_point<coarse_steady_clock, duration>;
#ifdef CLOCK_MONOTONIC_COARSE
    static time_point now() noexcept;
#endif
};

enum class FormatDurationOptions {
    WithoutUnit     = 0x00,
    WithUnit        = 0x01,
};

ShortDuration string_to_millisecs(std::string_view in_string);
std::string format_duration(std::chrono::nanoseconds ns,
                            FormatDurationOptions options = FormatDurationOptions::WithUnit);

#endif // __cplusplus
#endif // SANDSTONE_CHRONO_H
