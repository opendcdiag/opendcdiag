/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef FRAMEWORK_FP_VECTORS_FLOATS_H
#define FRAMEWORK_FP_VECTORS_FLOATS_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
#include <cfloat>
#include <limits>
#endif

// GCC supports _Float16 on x86 and __fp16 on AArch64, in both cases it
// only supports IEEE-754 format.
// https://gcc.gnu.org/onlinedocs/gcc/Half-Precision.html
#ifdef SANDSTONE_FP16_TYPE
typedef SANDSTONE_FP16_TYPE fp16_t;
#else
#  define SANDSTONE_FLOAT16_EMULATED
#endif

#ifndef __FLT128_DECIMAL_DIG__
#  define __FLT128_DECIMAL_DIG__ 36
#endif
#ifndef __FLT128_DENORM_MIN__
#  define __FLT128_DENORM_MIN__ 6.47517511943802511092443895822764655e-4966F128
#endif

#define BFLOAT8_EXPONENT_MASK  0x1fu
#define HFLOAT8_EXPONENT_MASK  0xfu
#define FLOAT16_EXPONENT_MASK  0x1fu
#define BFLOAT16_EXPONENT_MASK 0xffu
#define FLOAT32_EXPONENT_MASK  0xffu
#define FLOAT64_EXPONENT_MASK  0x7ffu
#define FLOAT80_EXPONENT_MASK  0x7fffu

#define BFLOAT8_INFINITY_EXPONENT  0x1fu
#define HFLOAT8_INF_NAN_EXPONENT   0xfu
#define FLOAT16_INFINITY_EXPONENT  0x1fu
#define BFLOAT16_INFINITY_EXPONENT 0xffu
#define FLOAT32_INFINITY_EXPONENT  0xffu
#define FLOAT64_INFINITY_EXPONENT  0x7ffu
#define FLOAT80_INFINITY_EXPONENT  0x7fffu

#define BFLOAT8_NAN_EXPONENT  0x1fu
#define FLOAT16_NAN_EXPONENT  0x1fu
#define BFLOAT16_NAN_EXPONENT 0xffu
#define FLOAT32_NAN_EXPONENT  0xffu
#define FLOAT64_NAN_EXPONENT  0x7ffu
#define FLOAT80_NAN_EXPONENT  0x7fffu

#define BFLOAT8_DENORM_EXPONENT  0x00
#define HFLOAT8_DENORM_EXPONENT  0x00
#define FLOAT16_DENORM_EXPONENT  0x00
#define BFLOAT16_DENORM_EXPONENT 0x00
#define FLOAT32_DENORM_EXPONENT  0x00
#define FLOAT64_DENORM_EXPONENT  0x00
#define FLOAT80_DENORM_EXPONENT  0x00

#define BFLOAT8_EXPONENT_BIAS  0xfu
#define HFLOAT8_EXPONENT_BIAS  0x7u
#define FLOAT16_EXPONENT_BIAS  0x0fu
#define BFLOAT16_EXPONENT_BIAS 0x7fu
#define FLOAT32_EXPONENT_BIAS  0x7fu
#define FLOAT64_EXPONENT_BIAS  0x3ffu
#define FLOAT80_EXPONENT_BIAS  0x3fffu

#define BFLOAT8_MANTISSA_MASK  0x3u
#define HFLOAT8_MANTISSA_MASK  0x7u
#define FLOAT16_MANTISSA_MASK  0x3ffu
#define BFLOAT16_MANTISSA_MASK 0x7fu
#define FLOAT32_MANTISSA_MASK  0x7fffffu
#define FLOAT64_MANTISSA_MASK  0xfffffffffffffu
#define FLOAT80_MANTISSA_MASK  0x7fffffffffffffffu

#define FLOAT16_MANTISSA_QUIET_NAN_MASK  0x200u
#define BFLOAT16_MANTISSA_QUIET_NAN_MASK 0x40u
#define FLOAT32_MANTISSA_QUIET_NAN_MASK  0x400000u
#define FLOAT64_MANTISSA_QUIET_NAN_MASK  0x8000000000000u
#define FLOAT80_MANTISSA_QUIET_NAN_MASK  0x4000000000000000u

#define BFLOAT8_SIGN_BITS        1
#define BFLOAT8_EXPONENT_BITS    5
#define BFLOAT8_MANTISSA_BITS    2
#define BFLOAT8_INF_AT_INPUT_MANTISSA   0b00
#define BFLOAT8_OVERFLOW_MANTISSA       0b01
#define BFLOAT8_SNAN_AT_INPUT_MANTISSA  0b10
#define BFLOAT8_QNAN_AT_INPUT_MANTISSA  0b11

#define HFLOAT8_SIGN_BITS          1
#define HFLOAT8_EXPONENT_BITS      4
#define HFLOAT8_MANTISSA_BITS      3
#define HFLOAT8_NAN_INF_VALUE            0x7f
#define HFLOAT8_SATURATED_OVERFLOW_VALUE 0x7e

#define FLOAT16_SIGN_BITS        1
#define FLOAT16_EXPONENT_BITS    5
#define FLOAT16_MANTISSA_BITS    10
#define FLOAT16_QUIET_BITS       1

#define BFLOAT16_SIGN_BITS      1
#define BFLOAT16_EXPONENT_BITS  8
#define BFLOAT16_MANTISSA_BITS  7
#define BFLOAT16_QUIET_BITS     1

#define FLOAT32_SIGN_BITS     1
#define FLOAT32_EXPONENT_BITS 8
#define FLOAT32_MANTISSA_BITS 23
#define FLOAT32_QUIET_BITS    1

#define FLOAT64_SIGN_BITS     1
#define FLOAT64_EXPONENT_BITS 11
#define FLOAT64_MANTISSA_BITS 52
#define FLOAT64_QUIET_BITS    1

#define FLOAT80_SIGN_BITS     1
#define FLOAT80_EXPONENT_BITS 15
#define FLOAT80_JBIT_BITS     1
#define FLOAT80_MANTISSA_BITS 63
#define FLOAT80_QUIET_BITS    1

#define FLOAT16_DECIMAL_DIG        5
#define FLOAT16_DENORM_MIN         5.96046447753906250000000000000000000e-8
#define FLOAT16_DIG                3
#define FLOAT16_EPSILON            9.76562500000000000000000000000000000e-4
#define FLOAT16_HAS_DENORM         1
#define FLOAT16_HAS_INFINITY       1
#define FLOAT16_HAS_QUIET_NAN      1
#define FLOAT16_MANT_DIG           11
#define FLOAT16_MAX_10_EXP         4
#define FLOAT16_MAX                6.55040000000000000000000000000000000e+4
#define FLOAT16_MAX_EXP            16
#define FLOAT16_MIN_10_EXP         (-4)
#define FLOAT16_MIN                6.10351562500000000000000000000000000e-5
#define FLOAT16_MIN_EXP            (-13)
#define FLOAT16_NORM_MAX           6.55040000000000000000000000000000000e+4

#define BFLOAT16_DECIMAL_DIG      3
#define BFLOAT16_DENORM_MIN       (0x1p-133)
#define BFLOAT16_DIG              2
#define BFLOAT16_EPSILON          (FLT_EPSILON * 65536)
#define BFLOAT16_HAS_DENORM       1
#define BFLOAT16_HAS_INFINITY     1
#define BFLOAT16_HAS_QUIET_NAN    1
#define BFLOAT16_MANT_DIG         (FLT_MANT_DIG - 16)
#define BFLOAT16_MAX_10_EXP       FLT_MAX_10_EXP
#define BFLOAT16_MAX_EXP          FLT_MAX_EXP
#define BFLOAT16_MAX              (0x1.fep+127f)
#define BFLOAT16_MIN_10_EXP       FLT_MIN_10_EXP
#define BFLOAT16_MIN_EXP          FLT_MIN_EXP
#define BFLOAT16_MIN              (0x1p-126f)
#define BFLOAT16_NORM_MAX         BFLOAT16_MAX

#ifdef __cplusplus
extern "C" {
#endif

struct BFloat8
{
    union {
        struct __attribute__((packed)) {
            uint8_t mantissa : BFLOAT8_MANTISSA_BITS;
            uint8_t exponent : BFLOAT8_EXPONENT_BITS;
            uint8_t sign     : BFLOAT8_SIGN_BITS;
        };
        struct __attribute__((packed)) {
            uint8_t value: (BFLOAT8_MANTISSA_BITS + BFLOAT8_EXPONENT_BITS);
            uint8_t signv: BFLOAT8_SIGN_BITS;
        };

        uint8_t as_hex;
        uint8_t payload;
    };

#ifdef __cplusplus
    constexpr inline BFloat8() = default;
    constexpr inline BFloat8(float f);
    constexpr inline BFloat8(uint8_t h): payload{h} { }

    constexpr inline BFloat8(uint8_t s, uint8_t e, uint8_t m): mantissa{m}, exponent{e}, sign{s} { }
    constexpr inline BFloat8(uint8_t s, uint8_t v): value{v}, signv{s} { }

    static constexpr BFloat8 min()      { return BFloat8{ static_cast<uint8_t>(0b0'00001'00) }; }
    static constexpr BFloat8 max()      { return BFloat8{ static_cast<uint8_t>(0b0'11110'11) }; }
    static constexpr BFloat8 infinity() { return BFloat8{ static_cast<uint8_t>(0b0'11111'00) }; }

    constexpr inline bool is_negative() const { return (sign != 0); }
    constexpr inline bool is_zero() const     { return (value == 0); }
    constexpr inline bool is_denormal() const { return (exponent == BFLOAT8_DENORM_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_valid() const    { return (exponent != BFLOAT8_NAN_EXPONENT); }
    constexpr inline bool is_inf() const      { return (exponent == BFLOAT8_INFINITY_EXPONENT) && (mantissa == 0); }
    constexpr inline bool is_overflow() const { return (exponent == BFLOAT8_EXPONENT_MASK) && (mantissa == BFLOAT8_OVERFLOW_MANTISSA); }
    constexpr inline bool is_nan() const      { return (exponent == BFLOAT8_NAN_EXPONENT) && ((mantissa == BFLOAT8_SNAN_AT_INPUT_MANTISSA) || (mantissa == BFLOAT8_QNAN_AT_INPUT_MANTISSA)); }
    constexpr inline bool is_snan() const     { return (exponent == BFLOAT8_NAN_EXPONENT) && (mantissa == BFLOAT8_SNAN_AT_INPUT_MANTISSA); }
    constexpr inline bool is_qnan() const     { return (exponent == BFLOAT8_NAN_EXPONENT) && (mantissa == BFLOAT8_QNAN_AT_INPUT_MANTISSA); }

    constexpr inline BFloat8 operator-() const {
        return { (uint8_t) (sign ^ 1), exponent, mantissa };
    }
#endif
};
typedef struct BFloat8 BFloat8;

// C interface
static inline bool BFloat8_is_negative(BFloat8 f) { return (f.sign != 0); }
static inline bool BFloat8_is_zero(BFloat8 f)     { return (f.value == 0); }
static inline bool BFloat8_is_denormal(BFloat8 f) { return (f.exponent == BFLOAT8_DENORM_EXPONENT) && (f.mantissa != 0); }
static inline bool BFloat8_is_valid(BFloat8 f)    { return (f.exponent != BFLOAT8_NAN_EXPONENT); }
static inline bool BFloat8_is_inf(BFloat8 f)      { return (f.exponent == BFLOAT8_INFINITY_EXPONENT) && (f.mantissa == 0); }
static inline bool BFloat8_is_overflow(BFloat8 f) { return (f.exponent == BFLOAT8_NAN_EXPONENT) && (f.mantissa == BFLOAT8_OVERFLOW_MANTISSA); }
static inline bool BFloat8_is_nan(BFloat8 f)      { return (f.exponent == BFLOAT8_NAN_EXPONENT) && ((f.mantissa == BFLOAT8_SNAN_AT_INPUT_MANTISSA) || (f.mantissa == BFLOAT8_QNAN_AT_INPUT_MANTISSA)); }
static inline bool BFloat8_is_snan(BFloat8 f)     { return (f.exponent == BFLOAT8_NAN_EXPONENT) && (f.mantissa == BFLOAT8_SNAN_AT_INPUT_MANTISSA); }
static inline bool BFloat8_is_qnan(BFloat8 f)     { return (f.exponent == BFLOAT8_NAN_EXPONENT) && (f.mantissa == BFLOAT8_QNAN_AT_INPUT_MANTISSA); }

#ifdef __cplusplus
extern "C" {
#endif
BFloat8 to_bfloat8_emulated(float f32);
float from_bfloat8_emulated(BFloat8 f8);
#ifdef __cplusplus
}
#endif

static inline BFloat8 to_bfloat8(float f32) {
    return to_bfloat8_emulated(f32);
}
static inline float from_bfloat8(BFloat8 f8) {
    return from_bfloat8_emulated(f8);
}

#ifdef __cplusplus
constexpr BFloat8::BFloat8(float f):
    payload{to_bfloat8(f).payload}
{}
#endif


struct HFloat8
{
    union {
        struct __attribute__((packed)) {
            uint8_t mantissa : HFLOAT8_MANTISSA_BITS;
            uint8_t exponent : HFLOAT8_EXPONENT_BITS;
            uint8_t sign     : HFLOAT8_SIGN_BITS;
        };
        struct __attribute__((packed)) {
            uint8_t value: (HFLOAT8_MANTISSA_BITS + HFLOAT8_EXPONENT_BITS);
            uint8_t signv: HFLOAT8_SIGN_BITS;
        };

        uint8_t as_hex;
        uint8_t payload;
    };

#ifdef __cplusplus
    constexpr inline HFloat8() = default;
    constexpr inline HFloat8(float f);
    constexpr inline HFloat8(uint8_t h): payload{h} { }

    constexpr inline HFloat8(uint8_t s, uint8_t e, uint8_t m): mantissa{m}, exponent{e}, sign{s} { }
    constexpr inline HFloat8(uint8_t s, uint8_t v): value{v}, signv{s} { }

    static constexpr HFloat8 min()      { return HFloat8{ static_cast<uint8_t>(0b0'0001'000) }; }
    static constexpr HFloat8 max()      { return HFloat8{ static_cast<uint8_t>(0b0'1111'101) }; }
    static constexpr HFloat8 max1()     { return HFloat8{ static_cast<uint8_t>(0b0'1111'000) }; }
    static constexpr HFloat8 infinity() { return HFloat8{ static_cast<uint8_t>(0b0'1111'111) }; }

    constexpr inline bool is_negative() const { return (sign != 0); }
    constexpr inline bool is_zero() const     { return (value == 0); }
    constexpr inline bool is_denormal() const { return (exponent == HFLOAT8_DENORM_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_valid() const    { return (value != HFLOAT8_NAN_INF_VALUE) && (value != HFLOAT8_SATURATED_OVERFLOW_VALUE); }
    constexpr inline bool is_nan_inf() const  { return value == HFLOAT8_NAN_INF_VALUE; }
    constexpr inline bool is_overflow() const { return value == HFLOAT8_SATURATED_OVERFLOW_VALUE; }

    constexpr inline HFloat8 operator-() const {
        return { (uint8_t) (sign ^ 1), exponent, mantissa };
    }
#endif
};
typedef struct HFloat8 HFloat8;

// C interface
static inline bool HFloat8_is_negative(HFloat8 f) { return (f.sign != 0); }
static inline bool HFloat8_is_zero(HFloat8 f)     { return (f.value == 0); }
static inline bool HFloat8_is_denormal(HFloat8 f) { return (f.exponent == HFLOAT8_DENORM_EXPONENT) && (f.mantissa != 0); }
static inline bool HFloat8_is_valid(HFloat8 f)    { return (f.value != HFLOAT8_NAN_INF_VALUE) && (f.value != HFLOAT8_SATURATED_OVERFLOW_VALUE); }
static inline bool HFloat8_is_nan_inf(HFloat8 f)  { return (f.value == HFLOAT8_NAN_INF_VALUE); }
static inline bool HFloat8_is_overflow(HFloat8 f) { return (f.value == HFLOAT8_SATURATED_OVERFLOW_VALUE); }

#ifdef __cplusplus
extern "C" {
#endif
HFloat8 to_hfloat8_emulated(float f32);
float from_hfloat8_emulated(HFloat8 f8);
#ifdef __cplusplus
}
#endif

static inline HFloat8 to_hfloat8(float f32) {
    return to_hfloat8_emulated(f32);
}
static inline float from_hfloat8(HFloat8 f8) {
    return from_hfloat8_emulated(f8);
}

#ifdef __cplusplus
constexpr HFloat8::HFloat8(float f):
    payload{to_hfloat8(f).payload}
{}
#endif

struct Float16
{
    union {
        struct __attribute__((packed)) {
            uint16_t mantissa : FLOAT16_MANTISSA_BITS;
            uint16_t exponent : FLOAT16_EXPONENT_BITS;
            uint16_t sign     : FLOAT16_SIGN_BITS;
        };
        struct __attribute__((packed)) {
            uint16_t payload  : FLOAT16_MANTISSA_BITS - FLOAT16_QUIET_BITS;
            uint16_t quiet    : FLOAT16_QUIET_BITS;
            uint16_t exponent : FLOAT16_EXPONENT_BITS;
            uint16_t sign     : FLOAT16_SIGN_BITS;
        } as_nan;

        uint16_t as_hex;
#ifdef SANDSTONE_FP16_TYPE
        fp16_t as_float;
#endif
        uint16_t payload;
    };

#ifdef __cplusplus
    constexpr inline Float16() = default;
    constexpr inline Float16(float f);
    constexpr inline Float16(uint16_t h): payload{h} { }

    constexpr inline Float16(uint16_t s, uint16_t e, uint16_t m): mantissa{m}, exponent{e}, sign{s} { }

    static constexpr int digits = FLOAT16_MANT_DIG;
    static constexpr int digits10 = FLOAT16_DIG;
    static constexpr int max_digits10 = 6;  // log2(digits)
    static constexpr int min_exponent = FLOAT16_MIN_EXP;
    static constexpr int min_exponent10 = FLOAT16_MIN_10_EXP;
    static constexpr int max_exponent = FLOAT16_MAX_EXP;
    static constexpr int max_exponent10 = FLOAT16_MAX_10_EXP;

    static constexpr bool radix = 2;
    static constexpr bool is_signed = true;
    static constexpr bool is_integer = false;
    static constexpr bool is_exact = false;
    static constexpr bool has_infinity = FLOAT16_HAS_INFINITY;
    static constexpr bool has_quiet_NaN = FLOAT16_HAS_QUIET_NAN;
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

    static constexpr Float16 min()              { return Float16{ static_cast<uint16_t>(0x0400) }; }
    static constexpr Float16 max()              { return Float16{ static_cast<uint16_t>(0x7bff) }; }
    static constexpr Float16 lowest()           { return Float16{ static_cast<uint16_t>(0xfbff) }; }
    static constexpr Float16 denorm_min()       { return Float16{ static_cast<uint16_t>(0x0001) }; }
    static constexpr Float16 epsilon()          { return Float16{ static_cast<uint16_t>(0x1400) }; }
    static constexpr Float16 round_error()      { return Float16{ static_cast<uint16_t>(0x3800) }; }
    static constexpr Float16 infinity()         { return Float16{ static_cast<uint16_t>(0x7c00) }; }
    static constexpr Float16 neg_infinity()     { return Float16{ static_cast<uint16_t>(0xfc00) }; }
    static constexpr Float16 quiet_NaN()        { return Float16{ static_cast<uint16_t>(0x7e00) }; }
    static constexpr Float16 signaling_NaN()    { return Float16{ static_cast<uint16_t>(0x7d00) }; }

    constexpr inline bool     is_negative() const         { return sign != 0; }
    constexpr inline bool     is_zero() const             { return (exponent == FLOAT16_DENORM_EXPONENT) && (mantissa == 0); }
    constexpr inline bool     is_denormal() const         { return (exponent == FLOAT16_DENORM_EXPONENT) && (mantissa != 0); }
    constexpr inline bool     is_inf() const              { return (exponent == FLOAT16_INFINITY_EXPONENT) && (mantissa == 0); }

    constexpr inline bool     is_nan() const              { return (exponent == FLOAT16_NAN_EXPONENT) && (mantissa != 0); }
    constexpr inline bool     is_snan() const             { return is_nan() && ((mantissa & FLOAT16_MANTISSA_QUIET_NAN_MASK) == 0); }
    constexpr inline bool     is_qnan() const             { return is_nan() && ((mantissa & FLOAT16_MANTISSA_QUIET_NAN_MASK) != 0); }
    constexpr inline bool     is_valid() const            { return exponent != FLOAT16_NAN_EXPONENT; }

    constexpr inline uint16_t get_nan_payload() const     { return mantissa & (~FLOAT16_MANTISSA_QUIET_NAN_MASK); }
#endif
};
typedef struct Float16 Float16;

// C interface
static inline bool     Float16_is_negative(Float16 f)         { return f.sign != 0; }
static inline bool     Float16_is_zero(Float16 f)             { return (f.exponent == FLOAT16_DENORM_EXPONENT) && (f.mantissa == 0); }
static inline bool     Float16_is_denormal(Float16 f)         { return (f.exponent == FLOAT16_DENORM_EXPONENT) && (f.mantissa != 0); }
static inline bool     Float16_is_inf(Float16 f)              { return (f.exponent == FLOAT16_INFINITY_EXPONENT) && (f.mantissa == 0); }

static inline bool     Float16_is_nan(Float16 f)              { return (f.exponent == FLOAT16_NAN_EXPONENT) && (f.mantissa != 0); }
static inline bool     Float16_is_snan(Float16 f)             { return Float16_is_nan(f) && (f.as_nan.quiet == 0); }
static inline bool     Float16_is_qnan(Float16 f)             { return Float16_is_nan(f) && (f.as_nan.quiet != 0); }
static inline bool     Float16_is_valid(Float16 f)            { return f.exponent != FLOAT16_NAN_EXPONENT; }

static inline uint16_t Float16_get_nan_payload(Float16 f)     { return f.as_nan.payload; }


struct BFloat16
{
    union {
        struct __attribute__((packed)) {
            uint16_t mantissa : BFLOAT16_MANTISSA_BITS;
            uint16_t exponent : BFLOAT16_EXPONENT_BITS;
            uint16_t sign     : BFLOAT16_SIGN_BITS;
        };
        struct __attribute__((packed)) {
            uint16_t payload  : BFLOAT16_MANTISSA_BITS - BFLOAT16_QUIET_BITS;
            uint16_t quiet    : BFLOAT16_QUIET_BITS;
            uint16_t exponent : BFLOAT16_EXPONENT_BITS;
            uint16_t sign     : BFLOAT16_SIGN_BITS;
        } as_nan;
        uint16_t as_hex;
        uint16_t payload;
    };

#ifdef __cplusplus
    constexpr inline BFloat16() = default;
    constexpr inline BFloat16(float f);
    constexpr inline BFloat16(uint16_t h): payload{h} {}
    constexpr inline BFloat16(uint16_t s, uint16_t e, uint16_t m): mantissa{m}, exponent{e}, sign{s} { }

    // same API as std::numeric_limits:
    static constexpr int digits = BFLOAT16_MANT_DIG;
    static constexpr int digits10 = BFLOAT16_DIG;
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

    static constexpr BFloat16 max()           { return BFloat16{ static_cast<uint16_t>(0x7f7f) }; }
    static constexpr BFloat16 min()           { return BFloat16{ static_cast<uint16_t>(0x0080) }; }
    static constexpr BFloat16 lowest()        { return BFloat16{ static_cast<uint16_t>(0xff7f) }; }
    static constexpr BFloat16 denorm_min()    { return BFloat16{ static_cast<uint16_t>(0x0001) }; }
    static constexpr BFloat16 epsilon()       { return BFloat16{ static_cast<uint16_t>(0x3c00) }; }
    static constexpr BFloat16 round_error()   { return BFloat16{ static_cast<uint16_t>(0x3f00) }; }
    static constexpr BFloat16 infinity()      { return BFloat16{ static_cast<uint16_t>(0x7f80) }; }
    static constexpr BFloat16 neg_infinity()  { return BFloat16{ static_cast<uint16_t>(0xff80) }; }
    static constexpr BFloat16 quiet_NaN()     { return BFloat16{ static_cast<uint16_t>(0x7fc0) }; }
    static constexpr BFloat16 signaling_NaN() { return BFloat16{ static_cast<uint16_t>(0x7fa0) }; }

    // extra
    static constexpr float epsilon_v()        { return std::numeric_limits<float>::epsilon() * 65536; }

    constexpr inline bool     is_negative() const       { return sign != 0; }
    constexpr inline bool     is_zero() const           { return (exponent == BFLOAT16_DENORM_EXPONENT) && (mantissa == 0); }
    constexpr inline bool     is_denormal() const       { return (exponent == BFLOAT16_DENORM_EXPONENT) && (mantissa != 0); }
    constexpr inline bool     is_inf() const            { return (exponent == BFLOAT16_INFINITY_EXPONENT) && (mantissa == 0); }

    // NaNs
    constexpr inline bool     is_nan() const            { return  (exponent == BFLOAT16_NAN_EXPONENT) && (mantissa != 0); }
    constexpr inline bool     is_snan() const           { return is_nan() && ((mantissa & BFLOAT16_MANTISSA_QUIET_NAN_MASK) == 0); }
    constexpr inline bool     is_qnan() const           { return is_nan() && ((mantissa & BFLOAT16_MANTISSA_QUIET_NAN_MASK) != 0); }

    constexpr inline uint16_t get_nan_payload() const   { return mantissa & (~BFLOAT16_MANTISSA_QUIET_NAN_MASK); }
#endif
};
typedef struct BFloat16 BFloat16;

// C interface
static inline bool     BFloat16_is_negative(BFloat16 f)         { return f.sign != 0; }
static inline bool     BFloat16_is_zero(BFloat16 f)             { return (f.exponent == BFLOAT16_DENORM_EXPONENT) && (f.mantissa == 0); }
static inline bool     BFloat16_is_denormal(BFloat16 f)         { return (f.exponent == BFLOAT16_DENORM_EXPONENT) && (f.mantissa != 0); }
static inline bool     BFloat16_is_inf(BFloat16 f)              { return (f.exponent == BFLOAT16_INFINITY_EXPONENT) && (f.mantissa == 0); }

static inline bool     BFloat16_is_nan(BFloat16 f)              { return (f.exponent == BFLOAT16_NAN_EXPONENT) && (f.mantissa != 0); }
static inline bool     BFloat16_is_snan(BFloat16 f)             { return BFloat16_is_nan(f) && (f.as_nan.quiet == 0); }
static inline bool     BFloat16_is_qnan(BFloat16 f)             { return BFloat16_is_nan(f) && (f.as_nan.quiet != 0); }

static inline uint16_t BFloat16_get_nan_payload(BFloat16 f)     { return f.as_nan.payload; }


struct Float32 {
    union {
        struct {
            uint32_t mantissa : FLOAT32_MANTISSA_BITS;
            uint32_t exponent : FLOAT32_EXPONENT_BITS;
            uint32_t sign     : FLOAT32_SIGN_BITS;
        };
        struct {
            uint32_t payload  : FLOAT32_MANTISSA_BITS - FLOAT32_QUIET_BITS;
            uint32_t quiet    : FLOAT32_QUIET_BITS;
            uint32_t exponent : FLOAT32_EXPONENT_BITS;
            uint32_t sign     : FLOAT32_SIGN_BITS;
        } as_nan;
        float as_float;
        uint32_t as_hex;
    };

#ifdef __cplusplus
    constexpr inline Float32() = default;
    constexpr inline Float32(float f) : as_float{f} { }
    constexpr inline Float32(uint32_t s, uint32_t e, uint32_t m): mantissa{m}, exponent{e}, sign{s} { }
#endif
};
typedef struct Float32 Float32;

struct Float64 {
    union {
        struct {
            uint64_t mantissa : FLOAT64_MANTISSA_BITS;
            uint64_t exponent : FLOAT64_EXPONENT_BITS;
            uint64_t sign     : FLOAT64_SIGN_BITS;
        };
        struct {
            uint64_t payload  : FLOAT64_MANTISSA_BITS - FLOAT64_QUIET_BITS;
            uint64_t quiet    : FLOAT64_QUIET_BITS;
            uint64_t exponent : FLOAT64_EXPONENT_BITS;
            uint64_t sign     : FLOAT64_SIGN_BITS;
        } as_nan;
        struct {
            uint32_t low32;
            uint32_t high32;
        } as_hex32;
        double as_float;
        uint64_t as_hex;
    };

#ifdef __cplusplus
    constexpr inline Float64() = default;
    constexpr inline Float64(float f) : as_float{f} { }
    constexpr inline Float64(uint64_t s, uint64_t e, uint64_t m): mantissa{m}, exponent{e}, sign{s} { }
#endif
};
typedef struct Float64 Float64;

struct Float80 {
    union {
        struct {
            uint64_t mantissa : FLOAT80_MANTISSA_BITS;
            uint64_t jbit     : FLOAT80_JBIT_BITS;
            uint64_t exponent : FLOAT80_EXPONENT_BITS;
            uint64_t sign     : FLOAT80_SIGN_BITS;
        };
        struct {
            uint64_t payload  : FLOAT80_MANTISSA_BITS - FLOAT80_QUIET_BITS;
            uint64_t quiet    : FLOAT80_QUIET_BITS;
            uint64_t jbit     : FLOAT80_JBIT_BITS;
            uint64_t exponent : FLOAT80_EXPONENT_BITS;
            uint64_t sign     : FLOAT80_SIGN_BITS;
        } as_nan;
        struct {
            uint64_t low64;
            uint16_t high16;
        } as_hex;
        struct {
            uint32_t low32;
            uint32_t high32;
            uint16_t extra16;
        } as_hex32;
        long double as_float;
    };

#ifdef __cplusplus
    constexpr inline Float80() = default;
    constexpr inline Float80(long double f) : as_float{f} { }
    constexpr inline Float80(uint64_t s, uint64_t e, uint64_t j, uint64_t m): mantissa{m}, jbit{j}, exponent{e}, sign{s} { }
#endif
};
typedef struct Float80 Float80;

/**
 * @brief C/C++ builders (inlined)
 *
 * "variadic" C/C++ builders, either constructor (C++) or direct struct initialization (C)
 *
 * @{
 */

#ifdef __cplusplus
#define STATIC_INLINE static inline constexpr
#else
#define STATIC_INLINE static inline
#endif

STATIC_INLINE BFloat8 new_bfloat8(uint8_t sign, uint8_t exponent, uint8_t mantissa)
{
#ifdef __cplusplus
    return BFloat8 { sign, exponent, mantissa };
#else
    return (BFloat8) {{{ .sign = sign, .exponent = exponent, .mantissa = mantissa }}};
#endif
}

STATIC_INLINE HFloat8 new_hfloat8(uint8_t sign, uint8_t exponent, uint8_t mantissa)
{
#ifdef __cplusplus
    return HFloat8 { sign, exponent, mantissa };
#else
    return (HFloat8) {{{ .sign = sign, .exponent = exponent, .mantissa = mantissa }}};
#endif
}

STATIC_INLINE Float16 new_float16(uint16_t sign, uint16_t exponent, uint16_t mantissa)
{
#ifdef __cplusplus
    return Float16 { sign, exponent, mantissa };
#else
    return (Float16) {{{ .sign = sign, .exponent = exponent, .mantissa = mantissa }}};
#endif
}

STATIC_INLINE BFloat16 new_bfloat16(uint16_t sign, uint16_t exponent, uint16_t mantissa)
{
#ifdef __cplusplus
    return BFloat16 { sign, exponent, mantissa };
#else
    return (BFloat16) {{{ .sign = sign, .exponent = exponent, .mantissa = mantissa }}};
#endif
}

STATIC_INLINE Float32 new_float32(uint32_t sign, uint32_t exponent, uint32_t mantissa)
{
#ifdef __cplusplus
    return Float32 { sign, exponent, mantissa };
#else
    return (Float32) {{{ .sign = sign, .exponent = exponent, .mantissa = mantissa }}};
#endif
}

STATIC_INLINE Float64 new_float64(uint64_t sign, uint64_t exponent, uint64_t mantissa)
{
#ifdef __cplusplus
    return Float64 { sign, exponent, mantissa };
#else
    return (Float64) {{{ .sign = sign, .exponent = exponent, .mantissa = mantissa }}};
#endif
}

STATIC_INLINE Float80 new_float80(uint64_t sign, uint64_t exponent, uint64_t jbit, uint64_t mantissa)
{
#ifdef __cplusplus
    return Float80 { sign, exponent, jbit, mantissa };
#else
    return (Float80) {{{ .sign = sign, .exponent = exponent, .jbit = jbit, .mantissa = mantissa }}};
#endif
}
/** @} */

Float16 new_random_float16();
BFloat16 new_random_bfloat16();
Float32 new_random_float32();
static inline float new_random_float() {
    return new_random_float32().as_float;
}
Float64 new_random_float64();
static inline double new_random_double() {
    return new_random_float64().as_float;
}
Float80 new_random_float80();

#define SET_RANDOM(v) \
    v = \
    _Generic((v),\
        Float16: new_random_float16,\
        BFloat16: new_random_bfloat16,\
        float: new_random_float,\
        Float32: new_random_float32,\
        double: new_random_double,\
        Float64: new_random_float64,\
        Float80: new_random_float80\
    )()

#define IS_NEGATIVE(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_negative,\
        HFloat8: HFloat8_is_negative,\
        Float16: Float16_is_negative,\
        BFloat16: BFloat16_is_negative\
    )(v)
#define IS_ZERO(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_zero,\
        HFloat8: HFloat8_is_zero,\
        Float16: Float16_is_zero,\
        BFloat16: BFloat16_is_zero\
    )(v)
#define IS_DENORMAL(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_denormal,\
        HFloat8: HFloat8_is_denormal,\
        Float16: Float16_is_denormal,\
        BFloat16: BFloat16_is_denormal\
    )(v)
#define IS_VALID(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_valid,\
        HFloat16: HFloat8_is_valid,\
        Float16: Float16_is_valid,\
        BFloat16: BFloat16_is_valid\
    )(v)
#define IS_INF(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_inf,\
        Float16: Float16_is_inf,\
        BFloat16: BFloat16_is_inf\
    )(v)
#define IS_NAN(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_nan,\
        Float16: Float16_is_nan,\
        BFloat16: BFloat16_is_nan\
    )(v)
#define IS_SNAN(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_snan,\
        Float16: Float16_is_snan,\
        BFloat16: BFloat16_is_snan\
    )(v)
#define IS_QNAN(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_qnan,\
        Float16: Float16_is_qnan,\
        BFloat16: BFloat16_is_qnan\
    )(v)

#define GET_NAN_PAYLOAD(v) \
    _Generic((v),\
        Float16: Float16_get_nan_payload,\
        BFloat16: BFloat16_get_nan_payload\
    )(v)

#ifdef __cplusplus
} // extern "C"
#endif

#endif //FRAMEWORK_FP_VECTORS_FLOATS_H
