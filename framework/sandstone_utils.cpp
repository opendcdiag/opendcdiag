/*
 * SPDX-License-Identifier: Apache-2.0
 */

// PLEASE READ BEFORE EDITING:
//     This is a clean file, meaning everyrthing in it is properly unit tested
//     Please do not add anything to this file unless it is unit tested.
//     All unit tests should be put in framework/unit-tests/sandstone_utils_tests.cpp

#include <charconv>
#include <stdexcept>
#include <string>
#include "sandstone_utils.h"

#include <immintrin.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

using namespace std;

template <typename T, size_t Size = sizeof(T)> static void format_fp(std::string &buffer, const void *data)
{
    T v;
    if (Size == sizeof(T)) {
        memcpy(&v, data, Size);
    } else {
        // BFloat16, probably; copy it to the high part of the float v
        v = 0;
        memcpy(reinterpret_cast<uint8_t *>(&v + 1) - Size, static_cast<const uint8_t *>(data), Size);
    }

    // everything but long double is simply promoted to double
    const char *fmt = sizeof(T) > sizeof(double) ? " (%La)" : " (%a)";
    buffer += stdprintf(fmt, v);
}

template <typename T> static void format_int(std::string &buffer, const void *data)
{
    T v;
    memcpy(&v, data, sizeof(v));

    // only print decimals if they are within an acceptable range
    int n = 0;
    int cursize = buffer.size();
    if (v <= 4096) {
        buffer.resize(cursize + strlen(" (-4096)"));
        if (std::is_signed_v<T>) {
            if (v >= -4096)
                n = sprintf(buffer.data() + cursize, " (%lld)", (long long)v);
        } else {
            n = sprintf(buffer.data() + cursize, " (%llu)", (unsigned long long)v);
        }
    }
    buffer.resize(cursize + n);
}

template <> void format_fp<Float16, sizeof(Float16)>(std::string &buffer, const void *data)
{
    Float16 v;
    memcpy(&v, data, sizeof(v));
    double d = fromfp16(v);
    return format_fp<double>(buffer, &d);
}

template <typename T> static __attribute__((unused)) void check_type_assumptions()
{
    using namespace SandstoneDataDetails;
    static_assert(TypeToDataType<T>::IsValid);
    static_assert(sizeof(T) == type_size(TypeToDataType<T>::Type));
    static_assert(alignof(T) == type_alignment(TypeToDataType<T>::Type));
    static_assert(sizeof(T) <= MaxDataTypeSize);
}
template void check_type_assumptions<bool>();
template void check_type_assumptions<char>();
template void check_type_assumptions<uint8_t>();
template void check_type_assumptions<uint16_t>();
template void check_type_assumptions<uint32_t>();
template void check_type_assumptions<uint64_t>();
template void check_type_assumptions<__uint128_t>();
template void check_type_assumptions<int8_t>();
template void check_type_assumptions<int16_t>();
template void check_type_assumptions<int32_t>();
template void check_type_assumptions<int64_t>();
template void check_type_assumptions<__int128_t>();
template void check_type_assumptions<float>();
template void check_type_assumptions<double>();
template void check_type_assumptions<long double>();
template void check_type_assumptions<Float16>();
template void check_type_assumptions<BFloat16>();
#ifndef SANDSTONE_FLOAT16_EMULATED
template void check_type_assumptions<__fp16>();
#endif
#ifdef __SIZEOF_FLOAT128__
template void check_type_assumptions<__float128>();
template void check_type_assumptions<Float128>();
#endif

string format_single_type(DataType type, int typeSize, const uint8_t *data, bool detailed)
{
    // add an hex dump of the entry
    string result(typeSize * 2, '\0');
    for (int i = 0; i < typeSize; ++i) {
        // x86 is little-endian
        uint8_t v = data[typeSize - 1 - i];
        result[i * 2 + 0] = "0123456789abcdef"[v >> 4];
        result[i * 2 + 1] = "0123456789abcdef"[v & 0xf];
    }

    if (detailed) {
        switch (type) {
        case UInt8Data:
            format_int<uint8_t>(result, data); break;
        case UInt16Data:
            format_int<uint16_t>(result, data); break;
        case UInt32Data:
            format_int<uint32_t>(result, data); break;
        case UInt64Data:
            format_int<uint64_t>(result, data); break;
        case UInt128Data:
            format_int<__uint128_t>(result, data); break;

        case Int8Data:
            format_int<int8_t>(result, data); break;
        case Int16Data:
            format_int<int16_t>(result, data); break;
        case Int32Data:
            format_int<int32_t>(result, data); break;
        case Int64Data:
            format_int<int64_t>(result, data); break;
        case Int128Data:
            format_int<__int128_t>(result, data); break;

        case Float80Data:
            format_fp<long double>(result, data); break;
        case Float64Data:
            format_fp<double>(result, data); break;
        case Float32Data:
            format_fp<float>(result, data); break;
        case BFloat16Data:
            format_fp<float, 2>(result, data); break;
        case Float16Data:
            format_fp<Float16, 2>(result, data); break;
        case Float128Data:
            break;

            // case DataIsSigned:
        case DataIsFloatingPoint:
            __builtin_unreachable();
        }
    }
    return result;
}

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

std::string vstdprintf(const char *fmt, va_list va)
{
    // estimate how big the string needs to be
    size_t minsize = strlen(fmt);
    for (const char *ptr = fmt; *ptr; ++ptr) {
        if (*ptr == '%')
            minsize += 8;       // just a heuristic, doesn't need to be correct
    }

    // both libstdc++'s and libc++'s std::string have a Small String
    // Optimisation size of 15 characters
    if (minsize < 15)
        minsize = 15;

    std::string result;

    // attempt to sprintf
    do {
        // we need to pass a copy, in case we loop
        va_list va2;
        va_copy(va2, va);

        result.resize(minsize + 1);
        minsize = vsnprintf(result.data(), result.size(), fmt, va2);
    } while (minsize >= result.size());

    result.resize(minsize);
    return result;
}

std::string stdprintf(const char *fmt, ...)
{
    return va_start_and_stdprintf(fmt);
}


coarse_steady_clock::time_point coarse_steady_clock::now() noexcept
{
#ifdef CLOCK_MONOTONIC_COARSE
    using namespace std::chrono;
    struct timespec ts;
    clock_t clk = CLOCK_MONOTONIC;
    clk = CLOCK_MONOTONIC_COARSE;
    clock_gettime(clk, &ts);
    return time_point(seconds(ts.tv_sec) + nanoseconds(ts.tv_nsec));
#else
    return time_point(std::chrono::steady_clock::now().time_since_epoch());
#endif
}
