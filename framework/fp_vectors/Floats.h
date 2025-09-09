/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef FRAMEWORK_FP_VECTORS_FLOATS_H
#define FRAMEWORK_FP_VECTORS_FLOATS_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
#include <cfloat>
#include <limits>
#endif

#ifdef __F16C__
#include <immintrin.h>
#endif

#ifdef __cplusplus
#define STATIC_INLINE static inline constexpr
#else
#define STATIC_INLINE static inline
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
#define HFLOAT8_INF_NAN_VALUE            0x7f
#define HFLOAT8_SATURATED_OVERFLOW_VALUE 0x7e
#define HFLOAT8_MAX_VALUE                0x7d

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
    using base_type = uint8_t;

    inline BFloat8() = default;
    inline BFloat8(float f);

    constexpr inline BFloat8(uint8_t s, uint8_t e, uint8_t m): mantissa(m), exponent(e), sign(s) { }
    constexpr inline BFloat8(uint8_t s, uint8_t v): value(v), signv(s) { }

    inline float to_float() const;

    static constexpr inline BFloat8 min()      { return BFloat8(Holder{ 0b0'00001'00 }); }
    static constexpr inline BFloat8 max()      { return BFloat8(Holder{ 0b0'11110'11 }); }
    static constexpr inline BFloat8 infinity() { return BFloat8(Holder{ 0b0'11111'00 }); }
    static constexpr inline BFloat8 overflow() { return BFloat8(Holder{ 0b0'11111'01 }); }
    static constexpr inline BFloat8 snan()     { return BFloat8(Holder{ 0b0'11111'10 }); }
    static constexpr inline BFloat8 qnan()     { return BFloat8(Holder{ 0b0'11111'11 }); }

    constexpr inline bool is_negative() const { return (sign != 0); }
    constexpr inline bool is_zero() const     { return (value == 0); }
    constexpr inline bool is_denormal() const { return (exponent == BFLOAT8_DENORM_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_valid() const    { return (exponent != BFLOAT8_NAN_EXPONENT); }
    constexpr inline bool is_inf() const      { return (exponent == BFLOAT8_INFINITY_EXPONENT) && (mantissa == 0); }
    constexpr inline bool is_overflow() const { return (exponent == BFLOAT8_EXPONENT_MASK) && (mantissa == BFLOAT8_OVERFLOW_MANTISSA); }
    constexpr inline bool is_nan() const      { return (exponent == BFLOAT8_NAN_EXPONENT) && ((mantissa == BFLOAT8_SNAN_AT_INPUT_MANTISSA) || (mantissa == BFLOAT8_QNAN_AT_INPUT_MANTISSA)); }
    constexpr inline bool is_snan() const     { return (exponent == BFLOAT8_NAN_EXPONENT) && (mantissa == BFLOAT8_SNAN_AT_INPUT_MANTISSA); }
    constexpr inline bool is_qnan() const     { return (exponent == BFLOAT8_NAN_EXPONENT) && (mantissa == BFLOAT8_QNAN_AT_INPUT_MANTISSA); }
    constexpr inline bool is_max() const      { return (exponent == BFLOAT8_INFINITY_EXPONENT - 1) && (mantissa == BFLOAT8_MANTISSA_MASK); }

    static constexpr inline uint32_t mantissa_bits() { return BFLOAT8_MANTISSA_BITS; }
    static constexpr inline uint32_t exponent_bits() { return BFLOAT8_EXPONENT_BITS; }

    constexpr inline BFloat8 operator-() const {
        return { (uint8_t) (sign ^ 1), exponent, mantissa };
    }

private:
    struct Holder { uint8_t payload; };
    explicit constexpr BFloat8(Holder h) : payload(h.payload) {}
#endif
};
typedef struct BFloat8 BFloat8;

// C interface
STATIC_INLINE bool BFloat8_is_negative(BFloat8 f) { return (f.sign != 0); }
STATIC_INLINE bool BFloat8_is_zero(BFloat8 f)     { return (f.value == 0); }
STATIC_INLINE bool BFloat8_is_denormal(BFloat8 f) { return (f.exponent == BFLOAT8_DENORM_EXPONENT) && (f.mantissa != 0); }
STATIC_INLINE bool BFloat8_is_valid(BFloat8 f)    { return (f.exponent != BFLOAT8_NAN_EXPONENT); }
STATIC_INLINE bool BFloat8_is_inf(BFloat8 f)      { return (f.exponent == BFLOAT8_INFINITY_EXPONENT) && (f.mantissa == 0); }
STATIC_INLINE bool BFloat8_is_overflow(BFloat8 f) { return (f.exponent == BFLOAT8_NAN_EXPONENT) && (f.mantissa == BFLOAT8_OVERFLOW_MANTISSA); }
STATIC_INLINE bool BFloat8_is_nan(BFloat8 f)      { return (f.exponent == BFLOAT8_NAN_EXPONENT) && ((f.mantissa == BFLOAT8_SNAN_AT_INPUT_MANTISSA) || (f.mantissa == BFLOAT8_QNAN_AT_INPUT_MANTISSA)); }
STATIC_INLINE bool BFloat8_is_snan(BFloat8 f)     { return (f.exponent == BFLOAT8_NAN_EXPONENT) && (f.mantissa == BFLOAT8_SNAN_AT_INPUT_MANTISSA); }
STATIC_INLINE bool BFloat8_is_qnan(BFloat8 f)     { return (f.exponent == BFLOAT8_NAN_EXPONENT) && (f.mantissa == BFLOAT8_QNAN_AT_INPUT_MANTISSA); }
STATIC_INLINE bool BFloat8_is_max(BFloat8 f)      { return (f.exponent == BFLOAT8_INFINITY_EXPONENT - 1) && (f.mantissa == BFLOAT8_MANTISSA_MASK); }

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
inline BFloat8::BFloat8(float f):
    payload(to_bfloat8(f).payload)
{}
inline float BFloat8::to_float() const {
    return from_bfloat8(*this);
}
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
    using base_type = uint8_t;
    inline HFloat8() = default;
    inline HFloat8(float f);

    constexpr inline HFloat8(uint8_t s, uint8_t e, uint8_t m): mantissa(m), exponent(e), sign(s) { }
    constexpr inline HFloat8(uint8_t s, uint8_t v): value(v), signv(s) { }

    inline float to_float() const;

    static constexpr inline HFloat8 min()      { return HFloat8(Holder{ 0b0'0001'000 }); }
    static constexpr inline HFloat8 max()      { return HFloat8(Holder{ 0b0'1111'101 }); }
    static constexpr inline HFloat8 max1()     { return HFloat8(Holder{ 0b0'1111'000 }); }
    static constexpr inline HFloat8 inf_nan()  { return HFloat8(Holder{ 0b0'1111'111 }); }
    static constexpr inline HFloat8 overflow() { return HFloat8(Holder{ 0b0'1111'110 }); }

    constexpr inline bool is_negative() const { return (sign != 0); }
    constexpr inline bool is_zero() const     { return (value == 0); }
    constexpr inline bool is_denormal() const { return (exponent == HFLOAT8_DENORM_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_inf_nan() const  { return value == HFLOAT8_INF_NAN_VALUE; }
    constexpr inline bool is_overflow() const { return value == HFLOAT8_SATURATED_OVERFLOW_VALUE; }
    constexpr inline bool is_valid() const    { return !is_inf_nan() && !is_overflow(); }
    constexpr inline bool is_max() const      { return value == HFLOAT8_MAX_VALUE; }

    static constexpr inline uint32_t mantissa_bits() { return HFLOAT8_MANTISSA_BITS; }
    static constexpr inline uint32_t exponent_bits() { return HFLOAT8_EXPONENT_BITS; }

    constexpr inline HFloat8 operator-() const {
        return { (uint8_t) (sign ^ 1), exponent, mantissa };
    }

private:
    struct Holder { uint8_t payload; };
    explicit constexpr HFloat8(Holder h) : payload(h.payload) {}
#endif
};
typedef struct HFloat8 HFloat8;

// C interface
STATIC_INLINE bool HFloat8_is_negative(HFloat8 f) { return (f.sign != 0); }
STATIC_INLINE bool HFloat8_is_zero(HFloat8 f)     { return (f.value == 0); }
STATIC_INLINE bool HFloat8_is_denormal(HFloat8 f) { return (f.exponent == HFLOAT8_DENORM_EXPONENT) && (f.mantissa != 0); }
STATIC_INLINE bool HFloat8_is_inf_nan(HFloat8 f)  { return (f.value == HFLOAT8_INF_NAN_VALUE); }
STATIC_INLINE bool HFloat8_is_overflow(HFloat8 f) { return (f.value == HFLOAT8_SATURATED_OVERFLOW_VALUE); }
STATIC_INLINE bool HFloat8_is_valid(HFloat8 f)    { return !HFloat8_is_inf_nan(f) && !HFloat8_is_overflow(f); }
STATIC_INLINE bool HFloat8_is_max(HFloat8 f)      { return f.value == HFLOAT8_MAX_VALUE; }

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
HFloat8::HFloat8(float f):
    payload(to_hfloat8(f).payload)
{}
inline float HFloat8::to_float() const {
    return from_hfloat8(*this);
}
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
    using base_type = uint16_t;
    inline Float16() = default;
    inline Float16(float f);

    constexpr inline Float16(uint16_t s, uint16_t e, uint16_t m): mantissa(m), exponent(e), sign(s) { }

    inline float to_float() const;

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

    static constexpr inline Float16 min()           { return Float16(Holder{0x0400}); }
    static constexpr inline Float16 max()           { return Float16(Holder{0x7bff}); }
    static constexpr inline Float16 lowest()        { return Float16(Holder{0xfbff}); }
    static constexpr inline Float16 denorm_min()    { return Float16(Holder{0x0001}); }
    static constexpr inline Float16 epsilon()       { return Float16(Holder{0x1400}); }
    static constexpr inline Float16 round_error()   { return Float16(Holder{0x3800}); }
    static constexpr inline Float16 infinity()      { return Float16(Holder{0x7c00}); }
    static constexpr inline Float16 neg_infinity()  { return Float16(Holder{0xfc00}); }
    static constexpr inline Float16 quiet_NaN()     { return Float16(Holder{0x7e00}); }
    static constexpr inline Float16 signaling_NaN() { return Float16(Holder{0x7d00}); }

    constexpr inline bool is_negative() const { return sign != 0; }
    constexpr inline bool is_zero() const     { return (exponent == FLOAT16_DENORM_EXPONENT) && (mantissa == 0); }
    constexpr inline bool is_denormal() const { return (exponent == FLOAT16_DENORM_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_valid() const    { return exponent != FLOAT16_NAN_EXPONENT; }
    constexpr inline bool is_inf() const      { return (exponent == FLOAT16_INFINITY_EXPONENT) && (mantissa == 0); }
    constexpr inline bool is_nan() const      { return (exponent == FLOAT16_NAN_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_snan() const     { return is_nan() && ((mantissa & FLOAT16_MANTISSA_QUIET_NAN_MASK) == 0); }
    constexpr inline bool is_qnan() const     { return is_nan() && ((mantissa & FLOAT16_MANTISSA_QUIET_NAN_MASK) != 0); }
    constexpr inline bool is_max() const      { return (exponent == FLOAT16_INFINITY_EXPONENT - 1) && (mantissa == FLOAT16_MANTISSA_MASK); }

    constexpr inline uint16_t get_nan_payload() const     { return mantissa & (~FLOAT16_MANTISSA_QUIET_NAN_MASK); }

    static constexpr inline uint32_t mantissa_bits() { return FLOAT16_MANTISSA_BITS; }
    static constexpr inline uint32_t exponent_bits() { return FLOAT16_EXPONENT_BITS; }

    constexpr inline Float16 operator-() const {
        return { (uint16_t) (sign ^ 1), exponent, mantissa };
    }

private:
    struct Holder { uint16_t payload; };
    explicit constexpr Float16(Holder h) : as_hex(h.payload) {}
#endif
};
typedef struct Float16 Float16;

// C interface
STATIC_INLINE bool Float16_is_negative(Float16 f) { return f.sign != 0; }
STATIC_INLINE bool Float16_is_zero(Float16 f)     { return (f.exponent == FLOAT16_DENORM_EXPONENT) && (f.mantissa == 0); }
STATIC_INLINE bool Float16_is_denormal(Float16 f) { return (f.exponent == FLOAT16_DENORM_EXPONENT) && (f.mantissa != 0); }
STATIC_INLINE bool Float16_is_valid(Float16 f)    { return f.exponent != FLOAT16_NAN_EXPONENT; }
STATIC_INLINE bool Float16_is_inf(Float16 f)      { return (f.exponent == FLOAT16_INFINITY_EXPONENT) && (f.mantissa == 0); }
STATIC_INLINE bool Float16_is_nan(Float16 f)      { return (f.exponent == FLOAT16_NAN_EXPONENT) && (f.mantissa != 0); }
STATIC_INLINE bool Float16_is_snan(Float16 f)     { return Float16_is_nan(f) && (f.as_nan.quiet == 0); }
STATIC_INLINE bool Float16_is_qnan(Float16 f)     { return Float16_is_nan(f) && (f.as_nan.quiet != 0); }
STATIC_INLINE bool Float16_is_max(Float16 f)      { return (f.exponent == FLOAT16_INFINITY_EXPONENT - 1) && (f.mantissa == FLOAT16_MANTISSA_MASK); }

STATIC_INLINE uint16_t Float16_get_nan_payload(Float16 f)     { return f.as_nan.payload; }

#ifdef __cplusplus
extern "C" {
#endif
extern Float16 tofp16_emulated(float f);
extern float fromfp16_emulated(Float16 f);
#ifdef __cplusplus
}
#endif

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

#ifdef __cplusplus
inline Float16::Float16(float f)
    : Float16(tofp16(f))
{
}
inline float Float16::to_float() const {
    return fromfp16(*this);
}
#endif

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
    using base_type = uint16_t;
    inline BFloat16() = default;
    inline BFloat16(float f);
    constexpr inline BFloat16(uint16_t s, uint16_t e, uint16_t m): mantissa(m), exponent(e), sign(s) { }

    inline float to_float() const;

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

    static constexpr inline BFloat16 max()           { return BFloat16(Holder{0x7f7f}); }
    static constexpr inline BFloat16 min()           { return BFloat16(Holder{0x0080}); }
    static constexpr inline BFloat16 lowest()        { return BFloat16(Holder{0xff7f}); }
    static constexpr inline BFloat16 denorm_min()    { return BFloat16(Holder{0x0001}); }
    static constexpr inline BFloat16 epsilon()       { return BFloat16(Holder{0x3c00}); }
    static constexpr inline BFloat16 round_error()   { return BFloat16(Holder{0x3f00}); }
    static constexpr inline BFloat16 infinity()      { return BFloat16(Holder{0x7f80}); }
    static constexpr inline BFloat16 neg_infinity()  { return BFloat16(Holder{0xff80}); }
    static constexpr inline BFloat16 quiet_NaN()     { return BFloat16(Holder{0x7fc0}); }
    static constexpr inline BFloat16 signaling_NaN() { return BFloat16(Holder{0x7fa0}); }

    // extra
    static constexpr float epsilon_v()        { return std::numeric_limits<float>::epsilon() * 65536; }

    constexpr inline bool is_negative() const { return sign != 0; }
    constexpr inline bool is_zero() const     { return (exponent == BFLOAT16_DENORM_EXPONENT) && (mantissa == 0); }
    constexpr inline bool is_denormal() const { return (exponent == BFLOAT16_DENORM_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_valid() const    { return exponent != BFLOAT16_NAN_EXPONENT; }
    constexpr inline bool is_inf() const      { return (exponent == BFLOAT16_INFINITY_EXPONENT) && (mantissa == 0); }
    constexpr inline bool is_nan() const      { return  (exponent == BFLOAT16_NAN_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_snan() const     { return is_nan() && ((mantissa & BFLOAT16_MANTISSA_QUIET_NAN_MASK) == 0); }
    constexpr inline bool is_qnan() const     { return is_nan() && ((mantissa & BFLOAT16_MANTISSA_QUIET_NAN_MASK) != 0); }
    constexpr inline bool is_max() const      { return (exponent == BFLOAT16_INFINITY_EXPONENT - 1) && (mantissa == BFLOAT16_MANTISSA_MASK); }

    constexpr inline uint16_t get_nan_payload() const { return mantissa & (~BFLOAT16_MANTISSA_QUIET_NAN_MASK); }

    static constexpr inline uint32_t mantissa_bits() { return BFLOAT16_MANTISSA_BITS; }
    static constexpr inline uint32_t exponent_bits() { return BFLOAT16_EXPONENT_BITS; }

    constexpr inline BFloat16 operator-() const {
        return { (uint16_t) (sign ^ 1), exponent, mantissa };
    }

private:
    struct Holder { uint16_t payload; };
    explicit constexpr BFloat16(Holder h) : as_hex(h.payload) {}
#endif
};
typedef struct BFloat16 BFloat16;

// C interface
STATIC_INLINE bool BFloat16_is_negative(BFloat16 f) { return f.sign != 0; }
STATIC_INLINE bool BFloat16_is_zero(BFloat16 f)     { return (f.exponent == BFLOAT16_DENORM_EXPONENT) && (f.mantissa == 0); }
STATIC_INLINE bool BFloat16_is_denormal(BFloat16 f) { return (f.exponent == BFLOAT16_DENORM_EXPONENT) && (f.mantissa != 0); }
STATIC_INLINE bool BFloat16_is_inf(BFloat16 f)      { return (f.exponent == BFLOAT16_INFINITY_EXPONENT) && (f.mantissa == 0); }
STATIC_INLINE bool BFloat16_is_valid(BFloat16 f)    { return f.exponent != BFLOAT16_NAN_EXPONENT; }
STATIC_INLINE bool BFloat16_is_nan(BFloat16 f)      { return (f.exponent == BFLOAT16_NAN_EXPONENT) && (f.mantissa != 0); }
STATIC_INLINE bool BFloat16_is_snan(BFloat16 f)     { return BFloat16_is_nan(f) && (f.as_nan.quiet == 0); }
STATIC_INLINE bool BFloat16_is_qnan(BFloat16 f)     { return BFloat16_is_nan(f) && (f.as_nan.quiet != 0); }
STATIC_INLINE bool BFloat16_is_max(BFloat16 f)      { return (f.exponent == BFLOAT16_INFINITY_EXPONENT - 1) && (f.mantissa == BFLOAT16_MANTISSA_MASK); }

STATIC_INLINE uint16_t BFloat16_get_nan_payload(BFloat16 f) { return f.as_nan.payload; }

#ifdef __cplusplus
extern "C" {
#endif
extern BFloat16 tobf16_emulated(float f);
#ifdef __cplusplus
}
#endif

static inline float frombf16_emulated(BFloat16 r) {
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

static inline float from_bf16(BFloat16 r) {
    return frombf16_emulated(r);
}

#ifdef __cplusplus
inline BFloat16::BFloat16(float f)
    : BFloat16(tobf16_emulated(f))
{
}
inline float BFloat16::to_float() const {
    return from_bf16(*this);
}
#endif

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
    using base_type = uint32_t;
    inline Float32() = default;
    constexpr inline Float32(float f) : as_float(f) { }
    constexpr inline Float32(uint32_t s, uint32_t e, uint32_t m): mantissa(m), exponent(e), sign(s) { }

    inline float to_float() const {
        return as_float;
    }

    static constexpr inline Float32 max()     { return { 0, FLOAT32_INFINITY_EXPONENT - 1, FLOAT32_MANTISSA_MASK }; }

    constexpr inline bool is_negative() const { return sign != 0; }
    constexpr inline bool is_zero() const     { return (exponent == FLOAT32_DENORM_EXPONENT) && (mantissa == 0); }
    constexpr inline bool is_denormal() const { return (exponent == FLOAT32_DENORM_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_valid() const    { return exponent != FLOAT32_NAN_EXPONENT; }
    constexpr inline bool is_inf() const      { return (exponent == FLOAT32_INFINITY_EXPONENT) && (mantissa == 0); }
    constexpr inline bool is_nan() const      { return  (exponent == FLOAT32_NAN_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_snan() const     { return is_nan() && ((mantissa & FLOAT32_MANTISSA_QUIET_NAN_MASK) == 0); }
    constexpr inline bool is_qnan() const     { return is_nan() && ((mantissa & FLOAT32_MANTISSA_QUIET_NAN_MASK) != 0); }
    constexpr inline bool is_max() const      { return (exponent == FLOAT32_INFINITY_EXPONENT - 1) && (mantissa == FLOAT32_MANTISSA_MASK); }

    static constexpr inline uint32_t mantissa_bits() { return FLOAT32_MANTISSA_BITS; }
    static constexpr inline uint32_t exponent_bits() { return FLOAT32_EXPONENT_BITS; }

    constexpr inline Float32 operator-() const {
        return { (uint32_t) (sign ^ 1), exponent, mantissa };
    }

#endif
};
typedef struct Float32 Float32;

STATIC_INLINE bool Float32_is_negative(Float32 f) { return f.sign != 0; }
STATIC_INLINE bool Float32_is_zero(Float32 f)     { return (f.exponent == FLOAT32_DENORM_EXPONENT) && (f.mantissa == 0); }
STATIC_INLINE bool Float32_is_denormal(Float32 f) { return (f.exponent == FLOAT32_DENORM_EXPONENT) && (f.mantissa != 0); }
STATIC_INLINE bool Float32_is_valid(Float32 f)    { return f.exponent != FLOAT32_NAN_EXPONENT; }
STATIC_INLINE bool Float32_is_inf(Float32 f)      { return (f.exponent == FLOAT32_INFINITY_EXPONENT) && (f.mantissa == 0); }
STATIC_INLINE bool Float32_is_nan(Float32 f)      { return (f.exponent == FLOAT32_NAN_EXPONENT) && (f.mantissa != 0); }
STATIC_INLINE bool Float32_is_snan(Float32 f)     { return Float32_is_nan(f) && ((f.mantissa & FLOAT32_QUIET_BITS) == 0); }
STATIC_INLINE bool Float32_is_qnan(Float32 f)     { return Float32_is_nan(f) && ((f.mantissa & FLOAT32_QUIET_BITS) != 0); }
STATIC_INLINE bool Float32_is_max(Float32 f)      { return (f.exponent == FLOAT32_INFINITY_EXPONENT - 1) && (f.mantissa == FLOAT32_MANTISSA_MASK); }

STATIC_INLINE float from_float32(Float32 f) { return f.as_float; }
STATIC_INLINE float from_float(float f) { return f; }

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
    using base_type = uint64_t;
    inline Float64() = default;
    constexpr inline Float64(double f) : as_float(f) { }
    constexpr inline Float64(uint64_t s, uint64_t e, uint64_t m): mantissa(m), exponent(e), sign(s) { }

    inline double to_float() const {
        return as_float;
    }

    static constexpr inline Float64 max()     { return { 0, FLOAT64_INFINITY_EXPONENT - 1, FLOAT64_MANTISSA_MASK }; }

    constexpr inline bool is_negative() const { return sign != 0; }
    constexpr inline bool is_zero() const     { return (exponent == FLOAT64_DENORM_EXPONENT) && (mantissa == 0); }
    constexpr inline bool is_denormal() const { return (exponent == FLOAT64_DENORM_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_valid() const    { return exponent != FLOAT64_NAN_EXPONENT; }
    constexpr inline bool is_inf() const      { return (exponent == FLOAT64_INFINITY_EXPONENT) && (mantissa == 0); }
    constexpr inline bool is_nan() const      { return  (exponent == FLOAT64_NAN_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_snan() const     { return is_nan() && ((mantissa & FLOAT64_MANTISSA_QUIET_NAN_MASK) == 0); }
    constexpr inline bool is_qnan() const     { return is_nan() && ((mantissa & FLOAT64_MANTISSA_QUIET_NAN_MASK) != 0); }
    constexpr inline bool is_max() const      { return (exponent == FLOAT64_INFINITY_EXPONENT - 1) && (mantissa == FLOAT64_MANTISSA_MASK); }

    static constexpr inline uint32_t mantissa_bits() { return FLOAT64_MANTISSA_BITS; }
    static constexpr inline uint32_t exponent_bits() { return FLOAT64_EXPONENT_BITS; }

    constexpr inline Float64 operator-() const {
        return { (uint64_t) (sign ^ 1), exponent, mantissa };
    }
#endif
};
typedef struct Float64 Float64;

STATIC_INLINE bool Float64_is_negative(Float64 f) { return f.sign != 0; }
STATIC_INLINE bool Float64_is_zero(Float64 f)     { return (f.exponent == FLOAT64_DENORM_EXPONENT) && (f.mantissa == 0); }
STATIC_INLINE bool Float64_is_denormal(Float64 f) { return (f.exponent == FLOAT64_DENORM_EXPONENT) && (f.mantissa != 0); }
STATIC_INLINE bool Float64_is_valid(Float64 f)    { return f.exponent != FLOAT64_NAN_EXPONENT; }
STATIC_INLINE bool Float64_is_inf(Float64 f)      { return (f.exponent == FLOAT64_INFINITY_EXPONENT) && (f.mantissa == 0); }
STATIC_INLINE bool Float64_is_nan(Float64 f)      { return (f.exponent == FLOAT64_NAN_EXPONENT) && (f.mantissa != 0); }
STATIC_INLINE bool Float64_is_snan(Float64 f)     { return Float64_is_nan(f) && ((f.mantissa & FLOAT64_QUIET_BITS) == 0); }
STATIC_INLINE bool Float64_is_qnan(Float64 f)     { return Float64_is_nan(f) && ((f.mantissa & FLOAT64_QUIET_BITS) != 0); }
STATIC_INLINE bool Float64_is_max(Float64 f)      { return (f.exponent == FLOAT64_INFINITY_EXPONENT - 1) && (f.mantissa == FLOAT64_MANTISSA_MASK); }

STATIC_INLINE double from_float64(Float64 f) { return f.as_float; }
STATIC_INLINE double from_double(double f) { return f; }

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
    using base_type = uint64_t;
    inline Float80() = default;
    constexpr inline Float80(long double f) : as_float(f) { }
    constexpr inline Float80(uint64_t s, uint64_t e, uint64_t j, uint64_t m): mantissa(m), jbit(j), exponent(e), sign(s) { }
    constexpr inline Float80(uint64_t s, uint64_t e, uint64_t m): mantissa(m), jbit(e == 0 ? 0 : 1), exponent(e), sign(s) { }

    inline long double to_float() const {
        return as_float;
    }

    static constexpr inline Float80 max()     { return { 0, FLOAT80_INFINITY_EXPONENT - 1, FLOAT80_MANTISSA_MASK }; }

    constexpr inline bool is_negative() const { return sign != 0; }
    constexpr inline bool is_zero() const     { return (exponent == FLOAT80_DENORM_EXPONENT) && (jbit == 0) && (mantissa == 0); }
    constexpr inline bool is_valid() const    { return exponent != FLOAT80_NAN_EXPONENT; }
    constexpr inline bool is_max() const      { return (exponent == FLOAT80_INFINITY_EXPONENT - 1) && (jbit == 1) && (mantissa == FLOAT80_MANTISSA_MASK); }

    static constexpr inline uint32_t mantissa_bits() { return FLOAT80_MANTISSA_BITS; }
    static constexpr inline uint32_t exponent_bits() { return FLOAT80_EXPONENT_BITS; }

    constexpr inline Float80 operator-() const {
        return { (uint64_t) (sign ^ 1), exponent, jbit, mantissa };
    }
#endif
};
typedef struct Float80 Float80;

STATIC_INLINE bool Float80_is_negative(Float80 f) { return f.sign != 0; }
STATIC_INLINE bool Float80_is_zero(Float80 f) { return (f.exponent == FLOAT80_DENORM_EXPONENT) && (f.jbit == 0) && (f.mantissa == 0); }
STATIC_INLINE bool Float80_is_valid(Float80 f) { return f.exponent != FLOAT80_NAN_EXPONENT; }
STATIC_INLINE bool Float80_is_max(Float80 f)   { return (f.exponent == FLOAT80_INFINITY_EXPONENT - 1) && (f.jbit == 1) && (f.mantissa == FLOAT80_MANTISSA_MASK); }

STATIC_INLINE long double from_float80(Float80 f) { return f.as_float; }

#ifdef __SIZEOF_FLOAT128__
struct Float128
{
    union {
        struct {
            uint64_t mantissa_low;
            uint64_t mantissa_high: (112 - 64);
            uint64_t exponent : 15;
            uint64_t sign : 1;
        };
        __float128 payload;
    };

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

/**
 * @brief C/C++ builders (inlined)
 * @{
 */

STATIC_INLINE BFloat8 new_bfloat8(uint8_t sign, uint8_t exponent, uint8_t mantissa)
{
#ifdef __cplusplus
    return BFloat8(sign, exponent, mantissa);
#else
    return (BFloat8) {{{ .sign = sign, .exponent = exponent, .mantissa = mantissa }}};
#endif
}

STATIC_INLINE HFloat8 new_hfloat8(uint8_t sign, uint8_t exponent, uint8_t mantissa)
{
#ifdef __cplusplus
    return HFloat8(sign, exponent, mantissa);
#else
    return (HFloat8) {{{ .sign = sign, .exponent = exponent, .mantissa = mantissa }}};
#endif
}

STATIC_INLINE Float16 new_float16(uint16_t sign, uint16_t exponent, uint16_t mantissa)
{
#ifdef __cplusplus
    return Float16(sign, exponent, mantissa);
#else
    return (Float16) {{{ .sign = sign, .exponent = exponent, .mantissa = mantissa }}};
#endif
}

STATIC_INLINE BFloat16 new_bfloat16(uint16_t sign, uint16_t exponent, uint16_t mantissa)
{
#ifdef __cplusplus
    return BFloat16(sign, exponent, mantissa);
#else
    return (BFloat16) {{{ .sign = sign, .exponent = exponent, .mantissa = mantissa }}};
#endif
}

STATIC_INLINE Float32 new_float32(uint32_t sign, uint32_t exponent, uint32_t mantissa)
{
#ifdef __cplusplus
    return Float32(sign, exponent, mantissa);
#else
    return (Float32) {{{ .sign = sign, .exponent = exponent, .mantissa = mantissa }}};
#endif
}

STATIC_INLINE Float64 new_float64(uint64_t sign, uint64_t exponent, uint64_t mantissa)
{
#ifdef __cplusplus
    return Float64(sign, exponent, mantissa);
#else
    return (Float64) {{{ .sign = sign, .exponent = exponent, .mantissa = mantissa }}};
#endif
}

STATIC_INLINE Float80 new_float80(uint64_t sign, uint64_t exponent, uint64_t jbit, uint64_t mantissa)
{
#ifdef __cplusplus
    return Float80(sign, exponent, jbit, mantissa);
#else
    return (Float80) {{{ .sign = sign, .exponent = exponent, .jbit = jbit, .mantissa = mantissa }}};
#endif
}
/** @} */

/**
 * @brief C/C++ unified predicates (inlined)
 * @{
 */

#ifdef __cplusplus
template<typename T>
constexpr inline bool IS_NEGATIVE(T v) {
    return v.is_negative();
}
template<>
constexpr inline bool IS_NEGATIVE(float v) {
    return IS_NEGATIVE(Float32(v));
}
template<>
constexpr inline bool IS_NEGATIVE(double v) {
    return IS_NEGATIVE(Float64(v));
}
#else
STATIC_INLINE bool float_is_negative(float f) { Float32 tmp; tmp.as_float = f; return Float32_is_negative(tmp); }
STATIC_INLINE bool double_is_negative(double d) { Float64 tmp; tmp.as_float = d; return Float64_is_negative(tmp); }
#define IS_NEGATIVE(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_negative,\
        HFloat8: HFloat8_is_negative,\
        Float16: Float16_is_negative,\
        BFloat16: BFloat16_is_negative,\
        Float32: Float32_is_negative,\
        float: float_is_negative,\
        Float64: Float64_is_negative,\
        double: double_is_negative,\
        Float80: Float80_is_negative\
    )(v)
#endif

#ifdef __cplusplus
template<typename T>
constexpr inline bool IS_ZERO(T v) {
    return v.is_zero();
}
template<>
constexpr inline bool IS_ZERO(float v) {
    return IS_ZERO(Float32(v));
}
template<>
constexpr inline bool IS_ZERO(double v) {
    return IS_ZERO(Float64(v));
}
#else
STATIC_INLINE bool float_is_zero(float f) { Float32 tmp; tmp.as_float = f; return Float32_is_zero(tmp); }
STATIC_INLINE bool double_is_zero(double d) { Float64 tmp; tmp.as_float = d; return Float64_is_zero(tmp); }
#define IS_ZERO(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_zero,\
        HFloat8: HFloat8_is_zero,\
        Float16: Float16_is_zero,\
        BFloat16: BFloat16_is_zero,\
        Float32: Float32_is_zero,\
        float: float_is_zero,\
        Float64: Float64_is_zero,\
        double: double_is_zero,\
        Float80: Float80_is_zero\
    )(v)
#endif

#ifdef __cplusplus
#define IS_DENORMAL(v) \
    ((v).is_denormal())
#else
#define IS_DENORMAL(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_denormal,\
        HFloat8: HFloat8_is_denormal,\
        Float16: Float16_is_denormal,\
        BFloat16: BFloat16_is_denormal,\
        Float32: Float32_is_denormal,\
        Float64: Float64_is_denormal\
    )(v)
#endif

#ifdef __cplusplus
template<typename T>
constexpr inline bool IS_VALID(T v) {
    return v.is_valid();
}
template<>
constexpr inline bool IS_VALID(float v) {
    return IS_VALID(Float32(v));
}
template<>
constexpr inline bool IS_VALID(double v) {
    return IS_VALID(Float64(v));
}
#else
STATIC_INLINE bool float_is_valid(float f) { Float32 tmp; tmp.as_float = f; return Float32_is_valid(tmp); }
STATIC_INLINE bool double_is_valid(double d) { Float64 tmp; tmp.as_float = d; return Float64_is_valid(tmp); }
#define IS_VALID(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_valid,\
        HFloat8: HFloat8_is_valid,\
        Float16: Float16_is_valid,\
        BFloat16: BFloat16_is_valid,\
        Float32: Float32_is_valid,\
        float: float_is_valid,\
        Float64: Float64_is_valid,\
        double: double_is_valid,\
        Float80: Float80_is_valid\
    )(v)
#endif

#ifdef __cplusplus
#define IS_INF_NAN(v) \
    ((v).is_inf_nan())
#else
#define IS_INF_NAN(v) \
    _Generic((v),\
        HFloat8: HFloat8_is_inf_nan\
    )(v)
#endif

#ifdef __cplusplus
#define IS_OVERFLOW(v) \
    ((v).is_overflow())
#else
#define IS_OVERFLOW(v) \
    _Generic((v),\
        HFloat8: HFloat8_is_overflow,\
        BFloat8: BFloat8_is_overflow\
    )(v)
#endif

#ifdef __cplusplus
#define IS_INF(v) \
    ((v).is_inf())
#else
#define IS_INF(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_inf,\
        Float16: Float16_is_inf,\
        BFloat16: BFloat16_is_inf,\
        Float32: Float32_is_inf,\
        Float64: Float64_is_inf\
    )(v)
#endif

#ifdef __cplusplus
#define IS_NAN(v) \
    ((v).is_nan())
#else
#define IS_NAN(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_nan,\
        Float16: Float16_is_nan,\
        BFloat16: BFloat16_is_nan,\
        Float32: Float32_is_nan,\
        Float64: Float64_is_nan\
    )(v)
#endif

#ifdef __cplusplus
#define IS_SNAN(v) \
    ((v).is_snan())
#else
#define IS_SNAN(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_snan,\
        Float16: Float16_is_snan,\
        BFloat16: BFloat16_is_snan,\
        Float32: Float32_is_snan,\
        Float64: Float64_is_snan\
    )(v)
#endif

#ifdef __cplusplus
#define IS_QNAN(v) \
    ((v).is_qnan())
#else
#define IS_QNAN(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_qnan,\
        Float16: Float16_is_qnan,\
        BFloat16: BFloat16_is_qnan,\
        Float32: Float32_is_qnan,\
        Float64: Float64_is_qnan\
    )(v)
#endif

#ifdef __cplusplus
#define GET_NAN_PAYLOAD(v) \
    ((v).get_nan_payload())
#else
#define GET_NAN_PAYLOAD(v) \
    _Generic((v),\
        Float16: Float16_get_nan_payload,\
        BFloat16: BFloat16_get_nan_payload\
    )(v)
#endif

/** @} */

enum RANDOM_GEN_FLAGS {
    // mantissa generation
    RANDOM_GEN_FLAGS_FLOAT_MANTISSA_MASK       = 0x7,
    RANDOM_GEN_FLAGS_FLOAT_MANTISSA_BITS       = 0x0, // fetch appropriate number of bits from the "factory"
    RANDOM_GEN_FLAGS_FLOAT_MANTISSA_RANDOM     = 0x1, // random32()/random64()
    RANDOM_GEN_FLAGS_FLOAT_MANTISSA_VECTOR     = 0x4, // get_float_vector(random_vector_index)
    RANDOM_GEN_FLAGS_FLOAT_MANTISSA_PATTERNED  = 0x5, // set_random_bits()
    RANDOM_GEN_FLAGS_FLOAT_MANTISSA_ZERO       = 0x7, // zero

    // exponent generation
    RANDOM_GEN_FLAGS_FLOAT_EXPONENT_MASK      = 0xf0,
    RANDOM_GEN_FLAGS_FLOAT_EXPONENT_BITS      = 0x00, // fetch appropriate number of bits from the "factory", flat distribution
    RANDOM_GEN_FLAGS_FLOAT_EXPONENT_RANDOM    = 0x10, // random32()
    RANDOM_GEN_FLAGS_FLOAT_EXPONENT_GAUSSIAN2 = 0x20, // n/2 + n/2 gaussian bell distribution, bits from the "factory"
    RANDOM_GEN_FLAGS_FLOAT_EXPONENT_GAUSSIAN4 = 0x30, // n/2 + n/4 + n/4 gaussian bell distribution
    RANDOM_GEN_FLAGS_FLOAT_EXPONENT_GAUSSIAN8 = 0x40, // n/2 + n/4 + n/8 + n/8 gaussian bell distribution
    RANDOM_GEN_FLAGS_FLOAT_EXPONENT_VECTOR    = 0x50, // get_float_vector(random_vector_index)

    // special values for exponent (with special mantissa handling)
    RANDOM_GEN_FLAGS_FLOAT_VALUE_ZERO         = 0x70, // zero, mantissa eq zero forced
    RANDOM_GEN_FLAGS_FLOAT_VALUE_DENORMAL     = 0x80, // denormal number, 0s excluded (random bit is set to 1 if zero in mantissa)
    RANDOM_GEN_FLAGS_FLOAT_VALUE_INF          = 0x90, // infinity, zero in the mantissa implied/forced
    RANDOM_GEN_FLAGS_FLOAT_VALUE_OVERFLOW     = 0xa0, // overflow
    RANDOM_GEN_FLAGS_FLOAT_VALUE_NAN          = 0xb0, // any NaN, Inf excluded (random bit is set to 1 if zero in mantissa)
    RANDOM_GEN_FLAGS_FLOAT_VALUE_SNAN         = 0xc0, // signalling NaN, Q bit is cleared
    RANDOM_GEN_FLAGS_FLOAT_VALUE_QNAN         = 0xd0, // quiet NaN, Q bit is set

    // special values for exponent
    RANDOM_GEN_FLAGS_FLOAT_EXPONENT_ZERO      = 0x60, // zero exponent, no assumption on the mantissa (denormal/zero)
    RANDOM_GEN_FLAGS_FLOAT_EXPONENT_MAX       = 0xe0, // max possible exponent, no assumption on the mantissa (Inf/NaN/overflow/large value, depending on the type), will skip some HFloat8 values!
    RANDOM_GEN_FLAGS_FLOAT_EXPONENT_BIAS      = 0xf0, // exponent equal BIAS, t.i. values [1..2), forced when NORMALIZE_VALUE

    // sign generation
    RANDOM_GEN_FLAGS_FLOAT_SIGN_MASK          = 0x300,
    RANDOM_GEN_FLAGS_FLOAT_SIGN_BITS          = 0x000, // fetch appropriate number of bits from the "factory"
    RANDOM_GEN_FLAGS_FLOAT_SIGN_POSITIVE      = 0x100, // forced 0
    RANDOM_GEN_FLAGS_FLOAT_SIGN_NEGATIVE      = 0x200, // forced 1
    RANDOM_GEN_FLAGS_FLOAT_SIGN_RANDOM        = 0x300, // random32()

    // extra
    RANDOM_GEN_FLAGS_EXTRA_FAST_MEMSET        = 0x10000000, // value initialized with "memset_random()"
    RANDOM_GEN_FLAGS_FLOAT_FORCE_FINITE       = 0x20000000, // finite number, Inf/NaNs/overflow excluded

    // short aliases
    POSITIVE = RANDOM_GEN_FLAGS_FLOAT_SIGN_POSITIVE,
    NEGATIVE = RANDOM_GEN_FLAGS_FLOAT_SIGN_NEGATIVE,
    VALUE_ZERO = RANDOM_GEN_FLAGS_FLOAT_VALUE_ZERO,
    VALUE_INF = RANDOM_GEN_FLAGS_FLOAT_VALUE_INF,
    VALUE_DENORMAL = RANDOM_GEN_FLAGS_FLOAT_VALUE_DENORMAL,
    VALUE_NAN = RANDOM_GEN_FLAGS_FLOAT_VALUE_NAN,
    VALUE_SNAN = RANDOM_GEN_FLAGS_FLOAT_VALUE_SNAN,
    VALUE_QNAN = RANDOM_GEN_FLAGS_FLOAT_VALUE_QNAN,

    FAST_MEMSET = RANDOM_GEN_FLAGS_EXTRA_FAST_MEMSET,
    PATTERNED = RANDOM_GEN_FLAGS_FLOAT_MANTISSA_PATTERNED | RANDOM_GEN_FLAGS_FLOAT_EXPONENT_RANDOM | RANDOM_GEN_FLAGS_FLOAT_SIGN_RANDOM,
    STATIC_VECTOR = RANDOM_GEN_FLAGS_FLOAT_MANTISSA_VECTOR | RANDOM_GEN_FLAGS_FLOAT_EXPONENT_VECTOR | RANDOM_GEN_FLAGS_FLOAT_SIGN_POSITIVE,
    VALUE_RANGE12 = RANDOM_GEN_FLAGS_FLOAT_EXPONENT_BIAS | RANDOM_GEN_FLAGS_FLOAT_SIGN_POSITIVE,
};

// C delegates to the template to generate the value of particular type. These
// will be defined in C++ with the use of the shared impl template.
// Make both available for C and C++ (not mangled version only!)
#ifdef __cplusplus
extern "C" {
#endif
HFloat8  gen_random_hfloat8 (uint32_t flags);
BFloat8  gen_random_bfloat8 (uint32_t flags);
Float16  gen_random_float16 (uint32_t flags);
BFloat16 gen_random_bfloat16(uint32_t flags);
Float32  gen_random_float32 (uint32_t flags);
float    gen_random_float   (uint32_t flags);
Float64  gen_random_float64 (uint32_t flags);
double   gen_random_double  (uint32_t flags);
Float80  gen_random_float80 (uint32_t flags);

HFloat8  normalize_hfloat8 (HFloat8 val,  float v1, float v2, uint32_t flags);
BFloat8  normalize_bfloat8 (BFloat8 val,  float v1, float v2, uint32_t flags);
Float16  normalize_float16 (Float16 val,  float v1, float v2, uint32_t flags);
BFloat16 normalize_bfloat16(BFloat16 val, float v1, float v2, uint32_t flags);
Float32  normalize_float32 (Float32 val,  float v1, float v2, uint32_t flags);
float    normalize_float   (float val,    float v1, float v2, uint32_t flags);
Float64  normalize_float64 (Float64 val,  float v1, float v2, uint32_t flags);
double   normalize_double  (double val,   float v1, float v2, uint32_t flags);
Float80  normalize_float80 (Float80 val,  float v1, float v2, uint32_t flags);

#ifdef __cplusplus
}
#endif

#ifndef __cplusplus
// "C" interface
#define NEW_RANDOM2(type, flags) \
    ({ type val; SET_RANDOM2(val, flags); val; })
#define SET_RANDOM2(val, flags) \
    val = _Generic((val),\
        HFloat8:  gen_random_hfloat8,\
        BFloat8:  gen_random_bfloat8,\
        Float16:  gen_random_float16,\
        BFloat16: gen_random_bfloat16,\
        Float32:  gen_random_float32,\
        float:    gen_random_float,\
        Float64:  gen_random_float64,\
        double:   gen_random_double,\
        Float80:  gen_random_float80\
    )(flags)
#define NORMALIZE(val, v1, v2, flags) \
    _Generic((val),\
        HFloat8:  normalize_hfloat8,\
        BFloat8:  normalize_bfloat8,\
        Float16:  normalize_float16,\
        BFloat16: normalize_bfloat16,\
        Float32:  normalize_float32,\
        float:    normalize_float,\
        Float64:  normalize_float64,\
        double:   normalize_double,\
        Float80:  normalize_float80\
    )(val, v1, v2, flags)

// val must be single expression, comma-expressions are not handled here properly
#define TO_FLOAT(val) \
    _Generic((val),\
        HFloat8:  from_hfloat8,\
        BFloat8:  from_bfloat8,\
        Float16:  fromfp16,\
        BFloat16: from_bf16,\
        Float32:  from_float32,\
        float:    from_float,\
        Float64:  from_float64,\
        double:   from_double,\
        Float80:  from_float80\
    )(val)
#else
// "C++" interface
namespace {

template<typename T>
struct NotImplementedFor: std::is_same<T, void> {
};

// template to handle bits in sign/exponent/mantissa according given T
template<typename T>
inline T gen_random_tmpl(uint32_t flags) {
    static_assert(NotImplementedFor<T>::value, "type not handled");
    return T{};
}
template<> inline HFloat8  gen_random_tmpl(uint32_t flags) { return gen_random_hfloat8(flags); }
template<> inline BFloat8  gen_random_tmpl(uint32_t flags) { return gen_random_bfloat8(flags); }
template<> inline Float16  gen_random_tmpl(uint32_t flags) { return gen_random_float16(flags); }
template<> inline BFloat16 gen_random_tmpl(uint32_t flags) { return gen_random_bfloat16(flags); }
template<> inline Float32  gen_random_tmpl(uint32_t flags) { return gen_random_float32(flags); }
template<> inline float    gen_random_tmpl(uint32_t flags) { return gen_random_float(flags); }
template<> inline Float64  gen_random_tmpl(uint32_t flags) { return gen_random_float64(flags); }
template<> inline double   gen_random_tmpl(uint32_t flags) { return gen_random_double(flags); }
template<> inline Float80  gen_random_tmpl(uint32_t flags) { return gen_random_float80(flags); }

template<typename T>
inline T normalize_tmpl(T val, float v1, float v2, uint32_t flags) {
    static_assert(NotImplementedFor<T>::value, "type not handled");
    return val;
}
template<> inline HFloat8 normalize_tmpl(HFloat8 val, float v1, float v2, uint32_t flags) {
    return normalize_hfloat8(val, v1, v2, flags);
}
template<> inline BFloat8 normalize_tmpl(BFloat8 val, float v1, float v2, uint32_t flags) {
    return normalize_bfloat8(val, v1, v2, flags);
}
template<> inline Float16 normalize_tmpl(Float16 val, float v1, float v2, uint32_t flags) {
    return normalize_float16(val, v1, v2, flags);
}
template<> inline BFloat16 normalize_tmpl(BFloat16 val, float v1, float v2, uint32_t flags) {
    return normalize_bfloat16(val, v1, v2, flags);
}
template<> inline Float32 normalize_tmpl(Float32 val, float v1, float v2, uint32_t flags) {
    return normalize_float32(val, v1, v2, flags);
}
template<> inline float normalize_tmpl(float val, float v1, float v2, uint32_t flags) {
    return normalize_float(val, v1, v2, flags);
}
template<> inline Float64 normalize_tmpl(Float64 val, float v1, float v2, uint32_t flags) {
    return normalize_float64(val, v1, v2, flags);
}
template<> inline double normalize_tmpl(double val, float v1, float v2, uint32_t flags) {
    return normalize_double(val, v1, v2, flags);
}
template<> inline Float80 normalize_tmpl(Float80 val, float v1, float v2, uint32_t flags) {
    return normalize_float80(val, v1, v2, flags);
}

#define NEW_RANDOM2(type, flags) gen_random_tmpl<type>(flags)
#define SET_RANDOM2(val, flags) ({ val = gen_random_tmpl<decltype(val)>(flags); })
#define NORMALIZE(val, v1, v2, flags) normalize_tmpl(val, v1, v2, flags)


template<typename F>
inline float to_float_tmpl(F f) {
    return f.to_float();
}
template<> inline float to_float_tmpl(float f) {
    return f;
}
template<> inline float to_float_tmpl(double f) {
    return f;
}
template<> inline float to_float_tmpl(long double f) {
    return f;
}
// "constructed in place" expressions (e.g. `Float16{ 1, 2, 3 }`) are allowed here
// (C-preprocessor split into coma separated "math" expressions, only '()' are used to make single expression)
#define TO_FLOAT(...) to_float_tmpl(__VA_ARGS__)

#define SET_FLOAT(val, f) ({ val = decltype(val)(f); })

} // anonymous namespace
#endif // C/C++ interface

#define SET_RANDOM1(val) SET_RANDOM2(val, 0)
// SET_RANDOM2(val, flags) is defined on per-language basis (C/C++)
#define SET_RANDOM(...) OVERLOAD(SET_RANDOM, NARGS(__VA_ARGS__))(__VA_ARGS__)

#define NEW_RANDOM1(type)                  NEW_RANDOM2(type, PATTERNED)
// NEW_RANDOM2(type, flags) is defined on per-language basis (C/C++)

// Run the generation with normalization. Normalization must be aware of the flags used
// to generate the value, so it is passed to it as well.
#define NEW_RANDOM3(type, v1, v2)        NORMALIZE(NEW_RANDOM2(type, RANDOM_GEN_FLAGS_FLOAT_SIGN_POSITIVE | RANDOM_GEN_FLAGS_FLOAT_EXPONENT_BIAS), v1, v2, 0)
#define NEW_RANDOM4(type, flags, v1, v2) NORMALIZE(NEW_RANDOM2(type, flags), v1, v2, flags)
#define NEW_RANDOM(...)                  OVERLOAD(NEW_RANDOM, NARGS(__VA_ARGS__))(__VA_ARGS__)

#define new_random(type, ...)    NEW_RANDOM(type,     ##__VA_ARGS__)
#define new_random_hfloat8(...)  NEW_RANDOM(HFloat8,  ##__VA_ARGS__)
#define new_random_bfloat8(...)  NEW_RANDOM(BFloat8,  ##__VA_ARGS__)
#define new_random_float16(...)  NEW_RANDOM(Float16,  ##__VA_ARGS__)
#define new_random_bfloat16(...) NEW_RANDOM(BFloat16, ##__VA_ARGS__)
#define new_random_float32(...)  NEW_RANDOM(Float32,  ##__VA_ARGS__)
#define new_random_float(...)    NEW_RANDOM(float,    ##__VA_ARGS__)
#define new_random_float64(...)  NEW_RANDOM(Float64,  ##__VA_ARGS__)
#define new_random_double(...)   NEW_RANDOM(double,   ##__VA_ARGS__)
#define new_random_float80(...)  NEW_RANDOM(Float80,  ##__VA_ARGS__)

#endif //FRAMEWORK_FP_VECTORS_FLOATS_H
