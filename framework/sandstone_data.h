/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_DATA_H
#define SANDSTONE_DATA_H

#include <float.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fp_vectors/Floats.h"

#ifdef __F16C__
#  include <immintrin.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum DataType {
    //SizeMask = 0x3f,
    UInt8Data = 0,
    UInt16Data = 1,
    UInt32Data = 3,
    UInt64Data = 7,
    UInt128Data = 15,

    DataIsSigned = 0x80,
    Int8Data = UInt8Data | DataIsSigned,
    Int16Data = UInt16Data | DataIsSigned,
    Int32Data = UInt32Data | DataIsSigned,
    Int64Data = UInt64Data | DataIsSigned,
    Int128Data = UInt128Data | DataIsSigned,

    DataIsFloatingPoint = 0x40,
    Float16Data = UInt16Data | DataIsFloatingPoint,
    BFloat16Data = 2 | DataIsFloatingPoint,
    Float32Data = UInt32Data | DataIsFloatingPoint,
    Float64Data = UInt64Data | DataIsFloatingPoint,
    Float80Data = 9 | DataIsFloatingPoint,
    Float128Data = UInt128Data | DataIsFloatingPoint,
    HFloat8Data,
    BFloat8Data,
};

#ifdef __SIZEOF_FLOAT128__
struct Float128
{
    __float128 payload;

#ifndef __f128
#   define __f128(x) x##q
#endif
#ifdef __cplusplus
    Float128() = default;
    Float128(long double f) : payload(f) {}

    static constexpr int digits = 113;
    static constexpr int digits10 = 33;
    static constexpr int max_digits10 = 6;  // log2(digits)
    static constexpr int min_exponent = -16381;
    static constexpr int min_exponent10 = -4931;
    static constexpr int max_exponent = 16384;
    static constexpr int max_exponent10 = 4932;

    static constexpr bool radix = 2;
    static constexpr bool is_signed = true;
    static constexpr bool is_integer = false;
    static constexpr bool is_exact = false;
    static constexpr bool has_infinity = true;
    static constexpr bool has_quiet_NaN = true;
    static constexpr bool has_signaling_NaN = has_quiet_NaN;
    static constexpr std::float_denorm_style has_denorm = std::denorm_present;
    static constexpr bool has_denorm_loss = false;
    static constexpr bool is_iec559 = true;
    static constexpr bool is_bounded = true;
    static constexpr bool is_modulo = false;
    static constexpr bool traps = false;
    static constexpr bool tinyness_before = false;
    static constexpr std::float_round_style round_style =
            std::round_toward_zero;   // unlike std::numeric_limits<float>::round_style

    static constexpr __float128 min()
    { return __f128(0x1p-16382); }
    static constexpr __float128 max()
    { return __f128(1.18973149535723176508575932662800702e+4932); }
    static constexpr __float128 lowest()
    { return -max(); }
    static constexpr __float128 denorm_min()
    { return __f128(6.47517511943802511092443895822764655e-4966); }
    static constexpr __float128 epsilon()
    { return __f128(1.92592994438723585305597794258492732e-34); }
    static constexpr __float128 round_error()
    { return __f128(0.5); }
    static constexpr __float128 infinity()
    { return __builtin_inff128(); }
    static constexpr __float128 neg_infinity()
    { return -__builtin_inff128(); }
    static constexpr __float128 quiet_NaN()
    { return __builtin_nanf128(""); }
    static constexpr __float128 signaling_NaN()
    { return __builtin_nansf128(""); }
#endif
};
#endif // __FLT128_MAX__

extern Float16 tofp16_emulated(float f);
extern float fromfp16_emulated(Float16 f);
extern BFloat16 tobf16_emulated(float f);

static inline Float16 tofp16(float f)
{
#ifdef __F16C__
    Float16 r;
    r.as_hex = _cvtss_sh(f, _MM_FROUND_TRUNC);
    return r;
#else
    return tofp16_emulated(f);
#endif
}

static inline float fromfp16(Float16 f)
{
#ifdef __F16C__
    return _cvtsh_ss(f.as_hex);
#else
    return fromfp16_emulated(f);
#endif
}

static inline float frombf16_emulated(BFloat16 r)
{
    // we zero-extend, shamelessly
    float f;
    uint32_t x = r.as_hex;
    x <<= 16;
    memcpy(&f, &x, sizeof(f));

#ifndef __FAST_MATH__
    f += 0;     // normalize and quiet any SNaNs
#endif
    return f;
}

#ifdef __cplusplus
} // extern "C"

inline Float16::Float16(float f)
    : Float16(tofp16(f))
{
}

inline BFloat16::BFloat16(float f)
    : BFloat16(tobf16_emulated(f))
{
}

namespace SandstoneDataDetails {
enum { MaxDataTypeSize = 16 };

static constexpr const char *type_name(DataType type)
{
    switch (type) {
    case UInt8Data: return "uint8_t";
    case UInt16Data: return "uint16_t";
    case UInt32Data: return "uint32_t";
    case UInt64Data: return "uint64_t";
    case UInt128Data: return "uint128_t";

    case Int8Data: return "int8_t";
    case Int16Data: return "int16_t";
    case Int32Data: return "int32_t";
    case Int64Data: return "int64_t";
    case Int128Data: return "int128_t";

    case HFloat8Data: return "HFloat8";
    case BFloat8Data: return "BFloat8";
    case Float16Data: return "_Float16";
    case BFloat16Data: return "_BFloat16";
    case Float32Data: return "float";
    case Float64Data: return "double";
    case Float80Data: return "_Float64x";   // long double is IEEE-754 extended precision binary64
    case Float128Data: return "_Float128";

    //case DataIsSigned:
    case DataIsFloatingPoint:
        __builtin_unreachable();
    }
    return nullptr;
}

template <DataType V> struct TypeToDataType_helper
{
    static constexpr DataType Type = V;
    static const char *name() { return type_name(Type); }
    enum { IsValid = true };
};

template <typename T> struct TypeToDataType { enum { IsValid = false }; };
template<> struct TypeToDataType<void>  : TypeToDataType_helper<UInt8Data> {};
template<> struct TypeToDataType<bool>  : TypeToDataType_helper<UInt8Data> {};
template<> struct TypeToDataType<char>  : TypeToDataType_helper<UInt8Data> {};
template<> struct TypeToDataType<uint8_t>  : TypeToDataType_helper<UInt8Data> {};
template<> struct TypeToDataType<uint16_t> : TypeToDataType_helper<UInt16Data> {};
template<> struct TypeToDataType<uint32_t> : TypeToDataType_helper<UInt32Data> {};
template<> struct TypeToDataType<uint64_t> : TypeToDataType_helper<UInt64Data> {};
template<> struct TypeToDataType<__uint128_t> : TypeToDataType_helper<UInt128Data> {};
template<> struct TypeToDataType<int8_t>  : TypeToDataType_helper<Int8Data> {};
template<> struct TypeToDataType<int16_t> : TypeToDataType_helper<Int16Data> {};
template<> struct TypeToDataType<int32_t> : TypeToDataType_helper<Int32Data> {};
template<> struct TypeToDataType<int64_t> : TypeToDataType_helper<Int64Data> {};
template<> struct TypeToDataType<__int128_t> : TypeToDataType_helper<Int128Data> {};

template<> struct TypeToDataType<BFloat8> : TypeToDataType_helper<BFloat8Data> {};
template<> struct TypeToDataType<HFloat8> : TypeToDataType_helper<HFloat8Data> {};
template<> struct TypeToDataType<Float16> : TypeToDataType_helper<Float16Data> {};
template<> struct TypeToDataType<BFloat16> : TypeToDataType_helper<BFloat16Data> {};
template<> struct TypeToDataType<Float32> : TypeToDataType_helper<Float32Data> {};
template<> struct TypeToDataType<Float64> : TypeToDataType_helper<Float64Data> {};
template<> struct TypeToDataType<float> : TypeToDataType_helper<Float32Data> {};
template<> struct TypeToDataType<double> : TypeToDataType_helper<Float64Data> {};
template<> struct TypeToDataType<long double> :
        TypeToDataType_helper<sizeof(long double) == sizeof(double) ? Float64Data : Float80Data> {};
#ifdef __SIZEOF_FLOAT128__
template<> struct TypeToDataType<Float128> : TypeToDataType_helper<Float128Data> {};
template<> struct TypeToDataType<__float128> : TypeToDataType_helper<Float128Data> {};
#endif
#ifdef SANDSTONE_FP16_TYPE
template<> struct TypeToDataType<fp16_t> : TypeToDataType_helper<Float16Data> {};
#endif

static constexpr size_t type_real_size(DataType type)
{
    constexpr unsigned SizeMask = 0x3f;
    switch (type) {
        case HFloat8Data:
        case BFloat8Data:
            return 1;
        case BFloat16Data:
            return 2;
        default:
            return (type & SizeMask) + 1;
    }
}

static constexpr size_t type_size(DataType type)
{
    // special case: long double has 10 bytes of data but occupies 16 bytes
    if (type == Float80Data)
        return sizeof(long double);
    return type_real_size(type);
}

static constexpr size_t type_alignment(DataType type)
{
    return type_size(type);
}
} // namespace SandstoneDataDetails

#else
/* for C mode, we'll have to use _Generic */
#define DATATYPEFORTYPE(X) _Generic((X), \
        _Bool: UInt8Data, \
        char: UInt8Data, \
        uint8_t: UInt8Data, \
        uint16_t: UInt16Data, \
        uint32_t: UInt32Data, \
        unsigned long: (sizeof(unsigned long) == sizeof(unsigned long long) ? UInt64Data : UInt32Data), \
        unsigned long long: UInt64Data, \
        __uint128_t: UInt128Data, \
        int8_t: Int8Data, \
        int16_t: Int16Data, \
        int32_t: Int32Data, \
        long: (sizeof(long) == sizeof(long long) ? Int64Data : Int32Data), \
        long long: Int64Data, \
        __int128_t: Int128Data, \
        HFloat8: HFloat8Data, \
        BFloat8: BFloat8Data, \
        BFloat16: BFloat16Data, \
        Float16: Float16Data, \
        float: Float32Data, \
        double: Float64Data, \
        long double: (sizeof(long double) == sizeof(double) ? Float64Data : Float80Data) \
    )

#endif /* __cplusplus */

#endif /* SANDSTONE_DATA_H */
