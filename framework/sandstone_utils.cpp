/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

// PLEASE READ BEFORE EDITING:
//     This is a clean file, meaning everyrthing in it is properly unit tested
//     Please do not add anything to this file unless it is unit tested.
//     All unit tests should be put in framework/unit-tests/sandstone_utils_tests.cpp

#include "sandstone_utils.h"

#include <stdexcept>
#include <string>

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
#ifdef SANDSTONE_FP16_TYPE
template void check_type_assumptions<fp16_t>();
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

std::string cpu_features_to_string(uint64_t f)
{
    std::string result;
    const char *comma = "";
    for (size_t i = 0; i < std::size(x86_locators); ++i) {
        if (f & (UINT64_C(1) << i)) {
            result += comma;
            result += features_string + features_indices[i] + 1;
            comma = ",";
        }
    }
    return result;
}
