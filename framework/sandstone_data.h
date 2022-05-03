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

#ifdef __F16C__
#  include <immintrin.h>
#endif

#ifndef __FLT16_DECIMAL_DIG__
#  define __FLT16_DECIMAL_DIG__ 5
#endif
#ifndef __FLT16_DENORM_MIN__
#  define __FLT16_DENORM_MIN__ 5.96046447753906250000000000000000000e-8f
#endif
#ifndef __FLT16_DIG__
#  define __FLT16_DIG__ 3
#endif
#ifndef __FLT16_EPSILON__
#  define __FLT16_EPSILON__ 9.76562500000000000000000000000000000e-4f
#endif
#ifndef __FLT16_HAS_DENORM__
#  define __FLT16_HAS_DENORM__ 1
#endif
#ifndef __FLT16_HAS_INFINITY__
#  define __FLT16_HAS_INFINITY__ 1
#endif
#ifndef __FLT16_HAS_QUIET_NAN__
#  define __FLT16_HAS_QUIET_NAN__ 1
#endif
#ifndef __FLT16_MANT_DIG__
#  define __FLT16_MANT_DIG__ 11
#endif
#ifndef __FLT16_MAX_10_EXP__
#  define __FLT16_MAX_10_EXP__ 4
#endif
#ifndef __FLT16_MAX__
#  define SANDSTONE_FLOAT16_EMULATED
#  define __FLT16_MAX__ 6.55040000000000000000000000000000000e+4f
#endif
#ifndef __FLT16_MAX_EXP__
#  define __FLT16_MAX_EXP__ 16
#endif
#ifndef __FLT16_MIN_10_EXP__
#  define __FLT16_MIN_10_EXP__ (-4)
#endif
#ifndef __FLT16_MIN__
#  define __FLT16_MIN__ 6.10351562500000000000000000000000000e-5f
#endif
#ifndef __FLT16_MIN_EXP__
#  define __FLT16_MIN_EXP__ (-13)
#endif
#ifndef __FLT16_NORM_MAX__
#  define __FLT16_NORM_MAX__ 6.55040000000000000000000000000000000e+4f
#endif
#ifndef __FLT128_DECIMAL_DIG__
#  define __FLT128_DECIMAL_DIG__ 36
#endif
#ifndef __FLT128_DENORM_MIN__
#  define __FLT128_DENORM_MIN__ 6.47517511943802511092443895822764655e-4966F128
#endif

#define BFLT16_DECIMAL_DIG      3
#define BFLT16_DENORM_MIN       (0x1p-133)
#define BFLT16_DIG              2
#define BFLT16_EPSILON          (FLT_EPSILON * 65536)
#define BFLT16_HAS_DENORM       1
#define BFLT16_HAS_INFINITY     1
#define BFLT16_HAS_QUIET_NAN    1
#define BFLT16_MANT_DIG         (FLT_MANT_DIG - 16)
#define BFLT16_MAX_10_EXP       FLT_MAX_10_EXP
#define BFLT16_MAX_EXP          FLT_MAX_EXP
#define BFLT16_MAX              (0x1.fep+127f)
#define BFLT16_MIN_10_EXP       FLT_MIN_10_EXP
#define BFLT16_MIN_EXP          FLT_MIN_EXP
#define BFLT16_MIN              (0x1p-126f)
#define BFLT16_NORM_MAX         BFLT16_MAX

#ifdef __cplusplus
#include <limits>
extern "C" {
#endif

typedef struct Float16 Float16;
typedef struct BFloat16 BFloat16;

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
    Float128Data = UInt128Data | DataIsFloatingPoint
};

struct Float16
{
    uint16_t payload;

#ifdef __cplusplus
    Float16() = default;
    inline Float16(float f);

    static constexpr int digits = __FLT16_MANT_DIG__;
    static constexpr int digits10 = __FLT16_DIG__;
    static constexpr int max_digits10 = 6;  // log2(digits)
    static constexpr int min_exponent = __FLT16_MIN_EXP__;
    static constexpr int min_exponent10 = __FLT16_MIN_10_EXP__;
    static constexpr int max_exponent = __FLT16_MAX_EXP__;
    static constexpr int max_exponent10 = __FLT16_MAX_10_EXP__;

    static constexpr bool radix = 2;
    static constexpr bool is_signed = true;
    static constexpr bool is_integer = false;
    static constexpr bool is_exact = false;
    static constexpr bool has_infinity = __FLT16_HAS_INFINITY__;
    static constexpr bool has_quiet_NaN = __FLT16_HAS_QUIET_NAN__;
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

    static constexpr Float16 min()              { return Float16(Holder{0x0400}); }
    static constexpr Float16 max()              { return Float16(Holder{0x7bff}); }
    static constexpr Float16 lowest()           { return Float16(Holder{0xfbff}); }
    static constexpr Float16 denorm_min()       { return Float16(Holder{0x0001}); }
    static constexpr Float16 epsilon()          { return Float16(Holder{0x1400}); }
    static constexpr Float16 round_error()      { return Float16(Holder{0x3800}); }
    static constexpr Float16 infinity()         { return Float16(Holder{0x7c00}); }
    static constexpr Float16 neg_infinity()     { return Float16(Holder{0xfc00}); }
    static constexpr Float16 quiet_NaN()        { return Float16(Holder{0x7e00}); }
    static constexpr Float16 signaling_NaN()    { return Float16(Holder{0x7d00}); }

private:
    struct Holder { uint16_t payload; };
    explicit constexpr Float16(Holder h) : payload(h.payload) {}
#endif
};

struct BFloat16
{
    uint16_t payload;

#ifdef __cplusplus
    BFloat16() = default;
    inline BFloat16(float f);

    // same API as std::numeric_limits:
    static constexpr int digits = BFLT16_MANT_DIG;
    static constexpr int digits10 = BFLT16_DIG;
    static constexpr int max_digits10 = 3;  // log2(digits)
    static constexpr int min_exponent = std::numeric_limits<float>::min_exponent;
    static constexpr int min_exponent10 = std::numeric_limits<float>::min_exponent10;
    static constexpr int max_exponent = std::numeric_limits<float>::max_exponent;
    static constexpr int max_exponent10 = std::numeric_limits<float>::max_exponent10;

    static constexpr bool radix = 2;
    static constexpr bool is_signed = true;
    static constexpr bool is_integer = false;
    static constexpr bool is_exact = false;
    static constexpr bool has_infinity = std::numeric_limits<float>::has_infinity;
    static constexpr bool has_quiet_NaN = std::numeric_limits<float>::has_quiet_NaN;
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

    static constexpr BFloat16 max()           { return BFloat16(Holder{0x7f7f}); }
    static constexpr BFloat16 min()           { return BFloat16(Holder{0x0080}); }
    static constexpr BFloat16 lowest()        { return BFloat16(Holder{0xff7f}); }
    static constexpr BFloat16 denorm_min()    { return BFloat16(Holder{0x0001}); }
    static constexpr BFloat16 epsilon()       { return BFloat16(Holder{0x3c00}); }
    static constexpr BFloat16 round_error()   { return BFloat16(Holder{0x3f00}); }
    static constexpr BFloat16 infinity()      { return BFloat16(Holder{0x7f80}); }
    static constexpr BFloat16 neg_infinity()  { return BFloat16(Holder{0xff80}); }
    static constexpr BFloat16 quiet_NaN()     { return BFloat16(Holder{0x7fc0}); }
    static constexpr BFloat16 signaling_NaN() { return BFloat16(Holder{0x7fa0}); }

    // extra
    static constexpr float epsilon_v()        { return std::numeric_limits<float>::epsilon() * 65536; }
private:
    struct Holder { uint16_t payload; };
    explicit constexpr BFloat16(Holder h) : payload(h.payload) {}
#endif
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

    static constexpr int digits = __FLT128_MANT_DIG__;
    static constexpr int digits10 = __FLT128_DIG__;
    static constexpr int max_digits10 = 6;  // log2(digits)
    static constexpr int min_exponent = __FLT128_MIN_EXP__;
    static constexpr int min_exponent10 = __FLT128_MIN_10_EXP__;
    static constexpr int max_exponent = __FLT128_MAX_EXP__;
    static constexpr int max_exponent10 = __FLT128_MAX_10_EXP__;

    static constexpr bool radix = 2;
    static constexpr bool is_signed = true;
    static constexpr bool is_integer = false;
    static constexpr bool is_exact = false;
    static constexpr bool has_infinity = __FLT128_HAS_INFINITY__;
    static constexpr bool has_quiet_NaN = __FLT128_HAS_QUIET_NAN__;
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
    r.payload = _cvtss_sh(f, _MM_FROUND_TRUNC);
    return r;
#else
    return tofp16_emulated(f);
#endif
}

static inline float fromfp16(Float16 f)
{
#ifdef __F16C__
    return _cvtsh_ss(f.payload);
#else
    return fromfp16_emulated(f);
#endif
}

static inline float frombf16_emulated(BFloat16 r)
{
    // we zero-extend, shamelessly
    float f;
    uint32_t x = r.payload;
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

template<> struct TypeToDataType<Float16> : TypeToDataType_helper<Float16Data> {};
template<> struct TypeToDataType<BFloat16> : TypeToDataType_helper<BFloat16Data> {};
template<> struct TypeToDataType<float> : TypeToDataType_helper<Float32Data> {};
template<> struct TypeToDataType<double> : TypeToDataType_helper<Float64Data> {};
template<> struct TypeToDataType<long double> :
        TypeToDataType_helper<sizeof(long double) == sizeof(double) ? Float64Data : Float80Data> {};
#ifdef __SIZEOF_FLOAT128__
template<> struct TypeToDataType<Float128> : TypeToDataType_helper<Float128Data> {};
template<> struct TypeToDataType<__float128> : TypeToDataType_helper<Float128Data> {};
#endif
#ifndef SANDSTONE_FLOAT16_EMULATED
template<> struct TypeToDataType<__fp16> : TypeToDataType_helper<Float16Data> {};
#endif

static constexpr size_t type_real_size(DataType type)
{
    constexpr unsigned SizeMask = 0x3f;
    if (type == BFloat16Data)
        return 2;               // exception
    return (type & SizeMask) + 1;
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
        BFloat16: BFloat16Data, \
        Float16: Float16Data, \
        float: Float32Data, \
        double: Float64Data, \
        long double: (sizeof(long double) == sizeof(double) ? Float64Data : Float80Data) \
    )

#endif /* __cplusplus */

#endif /* SANDSTONE_DATA_H */
