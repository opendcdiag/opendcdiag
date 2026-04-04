/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef FRAMEWORK_FP_VECTORS_FLOATS_H
#define FRAMEWORK_FP_VECTORS_FLOATS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
#include <cfloat>
#include <limits>
#include <type_traits>
#endif

#ifdef __F16C__
#include <immintrin.h>
#endif

#ifdef __cplusplus
#define STATIC_INLINE static inline constexpr
#else
#define STATIC_INLINE static inline
#endif

#ifndef OVERLOAD
/// Variadic macros to count the number of arguments passed to other macro.
/// @see OVERLOAD()
#define NARGN(\
            em, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10,n11,n12,n13,n14,n15,n16,n17,n18,n19,n20,n21,n22,n23,n24,n25,n26,n27,n28,n29,n30,n31,\
            n32,n33,n34,n35,n36,n37,n38,n39,n40,n41,n42,n43,n44,n45,n46,n47,n48,n49,n50,n51,n52,n53,n54,n55,n56,n57,n58,n59,n60,n61,n62,n63,\
            N, ...) \
        N

#define APPEND_NON_EMPTY(...) ,##__VA_ARGS__
#define NARG_(...) NARGN(__VA_ARGS__)
#define NARGS(...) NARG_( \
            -1 APPEND_NON_EMPTY(__VA_ARGS__),\
            63,62,61,60,59,58,57,56,55,54,53,52,51,50,49,48,47,46,45,44,43,42,41,40,39,38,37,36,35,34,33,32,\
            31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define OVERLOAD_(name, nargs) name##nargs
#define OVERLOAD(name, nargs) OVERLOAD_(name, nargs)
#endif

#ifdef __cplusplus
template<typename T>
struct NotImplementedFor: std::is_same<T, void> {
};
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

    constexpr inline BFloat8() = default;
    inline BFloat8(float f);

    constexpr inline BFloat8(uint8_t s, uint8_t e, uint8_t m): mantissa(m), exponent(e), sign(s) { }
    constexpr inline BFloat8(uint8_t s, uint8_t v): value(v), signv(s) { }

    inline float as_fp() const;

    static constexpr inline BFloat8 min()        { return BFloat8(Holder{ 0b0'00001'00 }); }
    static constexpr inline BFloat8 max()        { return BFloat8(Holder{ 0b0'11110'11 }); }
    static constexpr inline BFloat8 denorm_min() { return BFloat8(Holder{ 0b0'00000'01 }); }
    static constexpr inline BFloat8 infinity()   { return BFloat8(Holder{ 0b0'11111'00 }); }
    static constexpr inline BFloat8 overflow()   { return BFloat8(Holder{ 0b0'11111'01 }); }
    static constexpr inline BFloat8 snan()       { return BFloat8(Holder{ 0b0'11111'10 }); }
    static constexpr inline BFloat8 qnan()       { return BFloat8(Holder{ 0b0'11111'11 }); }

    constexpr inline bool is_negative() const { return (sign != 0); }
    constexpr inline bool is_zero() const     { return (value == 0); }
    constexpr inline bool is_denormal() const { return (exponent == BFLOAT8_DENORM_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_finite() const   { return (exponent != BFLOAT8_NAN_EXPONENT); }
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
STATIC_INLINE bool BFloat8_is_finite(BFloat8 f)   { return (f.exponent != BFLOAT8_NAN_EXPONENT); }
STATIC_INLINE bool BFloat8_is_inf(BFloat8 f)      { return (f.exponent == BFLOAT8_INFINITY_EXPONENT) && (f.mantissa == 0); }
STATIC_INLINE bool BFloat8_is_overflow(BFloat8 f) { return (f.exponent == BFLOAT8_NAN_EXPONENT) && (f.mantissa == BFLOAT8_OVERFLOW_MANTISSA); }
STATIC_INLINE bool BFloat8_is_nan(BFloat8 f)      { return (f.exponent == BFLOAT8_NAN_EXPONENT) && ((f.mantissa == BFLOAT8_SNAN_AT_INPUT_MANTISSA) || (f.mantissa == BFLOAT8_QNAN_AT_INPUT_MANTISSA)); }
STATIC_INLINE bool BFloat8_is_snan(BFloat8 f)     { return (f.exponent == BFLOAT8_NAN_EXPONENT) && (f.mantissa == BFLOAT8_SNAN_AT_INPUT_MANTISSA); }
STATIC_INLINE bool BFloat8_is_qnan(BFloat8 f)     { return (f.exponent == BFLOAT8_NAN_EXPONENT) && (f.mantissa == BFLOAT8_QNAN_AT_INPUT_MANTISSA); }
STATIC_INLINE bool BFloat8_is_max(BFloat8 f)      { return (f.exponent == BFLOAT8_INFINITY_EXPONENT - 1) && (f.mantissa == BFLOAT8_MANTISSA_MASK); }

#ifdef __cplusplus
extern "C" {
#endif
extern BFloat8 to_bfloat8_emulated(float f32);
extern float from_bfloat8_emulated(BFloat8 f8);
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
inline float BFloat8::as_fp() const {
    return from_bfloat8(*this);
}
#endif

static inline float BFloat8_as_fp(BFloat8 f) { return from_bfloat8(f); }

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
    constexpr inline HFloat8() = default;
    inline HFloat8(float f);

    constexpr inline HFloat8(uint8_t s, uint8_t e, uint8_t m): mantissa(m), exponent(e), sign(s) { }
    constexpr inline HFloat8(uint8_t s, uint8_t v): value(v), signv(s) { }

    inline float as_fp() const;

    static constexpr inline HFloat8 min()        { return HFloat8(Holder{ 0b0'0001'000 }); }
    static constexpr inline HFloat8 max()        { return HFloat8(Holder{ 0b0'1111'101 }); }
    static constexpr inline HFloat8 max1()       { return HFloat8(Holder{ 0b0'1111'000 }); }
    static constexpr inline HFloat8 denorm_min() { return HFloat8(Holder{ 0b0'0000'001 }); }
    static constexpr inline HFloat8 inf_nan()    { return HFloat8(Holder{ 0b0'1111'111 }); }
    static constexpr inline HFloat8 overflow()   { return HFloat8(Holder{ 0b0'1111'110 }); }

    constexpr inline bool is_negative() const { return (sign != 0); }
    constexpr inline bool is_zero() const     { return (value == 0); }
    constexpr inline bool is_denormal() const { return (exponent == HFLOAT8_DENORM_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_finite() const   { return (value != HFLOAT8_INF_NAN_VALUE) && (value != HFLOAT8_SATURATED_OVERFLOW_VALUE); }
    constexpr inline bool is_inf_nan() const  { return value == HFLOAT8_INF_NAN_VALUE; }
    constexpr inline bool is_overflow() const { return value == HFLOAT8_SATURATED_OVERFLOW_VALUE; }
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
STATIC_INLINE bool HFloat8_is_finite(HFloat8 f)   { return (f.value != HFLOAT8_INF_NAN_VALUE) && (f.value != HFLOAT8_SATURATED_OVERFLOW_VALUE); }
STATIC_INLINE bool HFloat8_is_inf_nan(HFloat8 f)  { return (f.value == HFLOAT8_INF_NAN_VALUE); }
STATIC_INLINE bool HFloat8_is_overflow(HFloat8 f) { return (f.value == HFLOAT8_SATURATED_OVERFLOW_VALUE); }
STATIC_INLINE bool HFloat8_is_max(HFloat8 f)      { return f.value == HFLOAT8_MAX_VALUE; }

#ifdef __cplusplus
extern "C" {
#endif
extern HFloat8 to_hfloat8_emulated(float f32);
extern float from_hfloat8_emulated(HFloat8 f8);
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
inline float HFloat8::as_fp() const {
    return from_hfloat8(*this);
}
#endif

static inline float HFloat8_as_fp(HFloat8 f) { return from_hfloat8(f); }

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
    constexpr inline Float16() = default;
    inline Float16(float f);

    constexpr inline Float16(uint16_t s, uint16_t e, uint16_t m): mantissa(m), exponent(e), sign(s) { }
    inline float as_fp() const;

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

    static constexpr inline Float16 min()              { return Float16(Holder{0x0400}); }
    static constexpr inline Float16 max()              { return Float16(Holder{0x7bff}); }
    static constexpr inline Float16 lowest()           { return Float16(Holder{0xfbff}); }
    static constexpr inline Float16 denorm_min()       { return Float16(Holder{0x0001}); }
    static constexpr inline Float16 epsilon()          { return Float16(Holder{0x1400}); }
    static constexpr inline Float16 round_error()      { return Float16(Holder{0x3800}); }
    static constexpr inline Float16 infinity()         { return Float16(Holder{0x7c00}); }
    static constexpr inline Float16 neg_infinity()     { return Float16(Holder{0xfc00}); }
    static constexpr inline Float16 quiet_NaN()        { return Float16(Holder{0x7e00}); }
    static constexpr inline Float16 signaling_NaN()    { return Float16(Holder{0x7d00}); }

    constexpr inline bool     is_negative() const         { return sign != 0; }
    constexpr inline bool     is_zero() const             { return (exponent == FLOAT16_DENORM_EXPONENT) && (mantissa == 0); }
    constexpr inline bool     is_denormal() const         { return (exponent == FLOAT16_DENORM_EXPONENT) && (mantissa != 0); }
    constexpr inline bool     is_inf() const              { return (exponent == FLOAT16_INFINITY_EXPONENT) && (mantissa == 0); }
    constexpr inline bool     is_nan() const              { return (exponent == FLOAT16_NAN_EXPONENT) && (mantissa != 0); }
    constexpr inline bool     is_snan() const             { return is_nan() && ((mantissa & FLOAT16_MANTISSA_QUIET_NAN_MASK) == 0); }
    constexpr inline bool     is_qnan() const             { return is_nan() && ((mantissa & FLOAT16_MANTISSA_QUIET_NAN_MASK) != 0); }
    constexpr inline bool     is_finite() const           { return exponent != FLOAT16_NAN_EXPONENT; }
    constexpr inline bool     is_max() const              { return (exponent == FLOAT16_INFINITY_EXPONENT - 1) && (mantissa == FLOAT16_MANTISSA_MASK); }

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
STATIC_INLINE bool Float16_is_finite(Float16 f)   { return f.exponent != FLOAT16_NAN_EXPONENT; }
STATIC_INLINE bool Float16_is_inf(Float16 f)      { return (f.exponent == FLOAT16_INFINITY_EXPONENT) && (f.mantissa == 0); }
STATIC_INLINE bool Float16_is_nan(Float16 f)      { return (f.exponent == FLOAT16_NAN_EXPONENT) && (f.mantissa != 0); }
STATIC_INLINE bool Float16_is_snan(Float16 f)     { return Float16_is_nan(f) && (f.as_nan.quiet == 0); }
STATIC_INLINE bool Float16_is_qnan(Float16 f)     { return Float16_is_nan(f) && (f.as_nan.quiet != 0); }
STATIC_INLINE bool Float16_is_max(Float16 f)      { return (f.exponent == FLOAT16_INFINITY_EXPONENT - 1) && (f.mantissa == FLOAT16_MANTISSA_MASK); }

STATIC_INLINE uint16_t Float16_get_nan_payload(Float16 f) { return f.as_nan.payload; }

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
inline float Float16::as_fp() const {
    return fromfp16(*this);
}
#endif

static inline float Float16_as_fp(Float16 f) { return fromfp16(f); }

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
    constexpr inline BFloat16() = default;
    inline BFloat16(float f);
    constexpr inline BFloat16(uint16_t s, uint16_t e, uint16_t m): mantissa(m), exponent(e), sign(s) { }

    inline float as_fp() const;

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
    constexpr inline bool is_max() const      { return (exponent == BFLOAT16_INFINITY_EXPONENT - 1) && (mantissa == BFLOAT16_MANTISSA_MASK); }
    constexpr inline bool is_denormal() const { return (exponent == BFLOAT16_DENORM_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_finite() const   { return exponent != BFLOAT16_NAN_EXPONENT; }
    constexpr inline bool is_inf() const      { return (exponent == BFLOAT16_INFINITY_EXPONENT) && (mantissa == 0); }
    constexpr inline bool is_nan() const      { return  (exponent == BFLOAT16_NAN_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_snan() const     { return is_nan() && ((mantissa & BFLOAT16_MANTISSA_QUIET_NAN_MASK) == 0); }
    constexpr inline bool is_qnan() const     { return is_nan() && ((mantissa & BFLOAT16_MANTISSA_QUIET_NAN_MASK) != 0); }

    constexpr inline uint16_t get_nan_payload() const   { return mantissa & (~BFLOAT16_MANTISSA_QUIET_NAN_MASK); }

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
STATIC_INLINE bool BFloat16_is_finite(BFloat16 f)   { return (f.exponent != BFLOAT16_NAN_EXPONENT); }
STATIC_INLINE bool BFloat16_is_inf(BFloat16 f)      { return (f.exponent == BFLOAT16_INFINITY_EXPONENT) && (f.mantissa == 0); }
STATIC_INLINE bool BFloat16_is_nan(BFloat16 f)      { return (f.exponent == BFLOAT16_NAN_EXPONENT) && (f.mantissa != 0); }
STATIC_INLINE bool BFloat16_is_snan(BFloat16 f)     { return BFloat16_is_nan(f) && (f.as_nan.quiet == 0); }
STATIC_INLINE bool BFloat16_is_qnan(BFloat16 f)     { return BFloat16_is_nan(f) && (f.as_nan.quiet != 0); }

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
    union {
        float f;
        uint32_t x;
    } v;
    v.x = r.as_hex;
    v.x <<= 16;
#ifndef __FAST_MATH__
    v.f += 0;     // normalize and quiet any SNaNs
#endif
    return v.f;
}

/* TODO handle with _mm_cvtneps_pbh */
static inline BFloat16 tobf16(float f) {
    return tobf16_emulated(f);
}
static inline float frombf16(BFloat16 r) {
    return frombf16_emulated(r);
}

#ifdef __cplusplus
inline BFloat16::BFloat16(float f)
    : BFloat16(tobf16(f))
{
}
inline float BFloat16::as_fp() const {
    return frombf16(*this);
}
#endif

static inline float BFloat16_as_fp(BFloat16 f) { return frombf16(f); }

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
    constexpr inline Float32() = default;
    constexpr inline Float32(float f) : as_float(f) { }
    constexpr inline Float32(uint32_t s, uint32_t e, uint32_t m): mantissa(m), exponent(e), sign(s) { }

    constexpr inline float as_fp() const {
        return as_float;
    }

    static constexpr inline Float32 max()     { return { 0, FLOAT32_INFINITY_EXPONENT - 1, FLOAT32_MANTISSA_MASK }; }

    constexpr inline bool is_negative() const { return sign != 0; }
    constexpr inline bool is_zero() const     { return (exponent == FLOAT32_DENORM_EXPONENT) && (mantissa == 0); }
    constexpr inline bool is_denormal() const { return (exponent == FLOAT32_DENORM_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_finite() const   { return exponent != FLOAT32_NAN_EXPONENT; }
    constexpr inline bool is_inf() const      { return (exponent == FLOAT32_INFINITY_EXPONENT) && (mantissa == 0); }
    constexpr inline bool is_nan() const      { return  (exponent == FLOAT32_NAN_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_snan() const     { return is_nan() && ((mantissa & FLOAT32_MANTISSA_QUIET_NAN_MASK) == 0); }
    constexpr inline bool is_qnan() const     { return is_nan() && ((mantissa & FLOAT32_MANTISSA_QUIET_NAN_MASK) != 0); }
    constexpr inline bool is_max() const      { return (exponent == FLOAT32_INFINITY_EXPONENT - 1) && (mantissa == FLOAT32_MANTISSA_MASK); }

    constexpr inline uint32_t get_nan_payload() const   { return mantissa & (~FLOAT32_MANTISSA_QUIET_NAN_MASK); }

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
STATIC_INLINE bool Float32_is_finite(Float32 f)   { return f.exponent != FLOAT32_NAN_EXPONENT; }
STATIC_INLINE bool Float32_is_inf(Float32 f)      { return (f.exponent == FLOAT32_INFINITY_EXPONENT) && (f.mantissa == 0); }
STATIC_INLINE bool Float32_is_nan(Float32 f)      { return (f.exponent == FLOAT32_NAN_EXPONENT) && (f.mantissa != 0); }
STATIC_INLINE bool Float32_is_snan(Float32 f)     { return Float32_is_nan(f) && ((f.mantissa & FLOAT32_QUIET_BITS) == 0); }
STATIC_INLINE bool Float32_is_qnan(Float32 f)     { return Float32_is_nan(f) && ((f.mantissa & FLOAT32_QUIET_BITS) != 0); }
STATIC_INLINE bool Float32_is_max(Float32 f)      { return (f.exponent == FLOAT32_INFINITY_EXPONENT - 1) && (f.mantissa == FLOAT32_MANTISSA_MASK); }

STATIC_INLINE uint32_t Float32_get_nan_payload(Float32 f) { return f.as_nan.payload; }
STATIC_INLINE float Float32_as_fp(Float32 f) { return f.as_float; }

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
    constexpr inline Float64() = default;
    constexpr inline Float64(double f) : as_float(f) { }
    constexpr inline Float64(uint64_t s, uint64_t e, uint64_t m): mantissa(m), exponent(e), sign(s) { }

    constexpr inline double as_fp() const {
        return as_float;
    }

    static constexpr inline Float64 max()     { return { 0, FLOAT64_INFINITY_EXPONENT - 1, FLOAT64_MANTISSA_MASK }; }

    constexpr inline bool is_negative() const { return sign != 0; }
    constexpr inline bool is_zero() const     { return (exponent == FLOAT64_DENORM_EXPONENT) && (mantissa == 0); }
    constexpr inline bool is_denormal() const { return (exponent == FLOAT64_DENORM_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_finite() const   { return exponent != FLOAT64_NAN_EXPONENT; }
    constexpr inline bool is_inf() const      { return (exponent == FLOAT64_INFINITY_EXPONENT) && (mantissa == 0); }
    constexpr inline bool is_nan() const      { return  (exponent == FLOAT64_NAN_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_snan() const     { return is_nan() && ((mantissa & FLOAT64_MANTISSA_QUIET_NAN_MASK) == 0); }
    constexpr inline bool is_qnan() const     { return is_nan() && ((mantissa & FLOAT64_MANTISSA_QUIET_NAN_MASK) != 0); }
    constexpr inline bool is_max() const      { return (exponent == FLOAT64_INFINITY_EXPONENT - 1) && (mantissa == FLOAT64_MANTISSA_MASK); }

    constexpr inline uint64_t get_nan_payload() const   { return mantissa & (~FLOAT64_MANTISSA_QUIET_NAN_MASK); }

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
STATIC_INLINE bool Float64_is_finite(Float64 f)   { return f.exponent != FLOAT64_NAN_EXPONENT; }
STATIC_INLINE bool Float64_is_inf(Float64 f)      { return (f.exponent == FLOAT64_INFINITY_EXPONENT) && (f.mantissa == 0); }
STATIC_INLINE bool Float64_is_nan(Float64 f)      { return (f.exponent == FLOAT64_NAN_EXPONENT) && (f.mantissa != 0); }
STATIC_INLINE bool Float64_is_snan(Float64 f)     { return Float64_is_nan(f) && ((f.mantissa & FLOAT64_QUIET_BITS) == 0); }
STATIC_INLINE bool Float64_is_qnan(Float64 f)     { return Float64_is_nan(f) && ((f.mantissa & FLOAT64_QUIET_BITS) != 0); }
STATIC_INLINE bool Float64_is_max(Float64 f)      { return (f.exponent == FLOAT64_INFINITY_EXPONENT - 1) && (f.mantissa == FLOAT64_MANTISSA_MASK); }

STATIC_INLINE uint64_t Float64_get_nan_payload(Float64 f) { return f.as_nan.payload; }
STATIC_INLINE double Float64_as_fp(Float64 f) { return f.as_float; }

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
    constexpr inline Float80() = default;
    constexpr inline Float80(long double f) : as_float(f) { }
    constexpr inline Float80(uint64_t s, uint64_t e, uint64_t j, uint64_t m): mantissa(m), jbit(j), exponent(e), sign(s) { }
    constexpr inline Float80(uint64_t s, uint64_t e, uint64_t m): mantissa(m), jbit(e == 0 ? 0 : 1), exponent(e), sign(s) { }

    constexpr inline long double as_fp() const {
        return as_float;
    }

    static constexpr inline Float80 max()     { return { 0, FLOAT80_INFINITY_EXPONENT - 1, FLOAT80_MANTISSA_MASK }; }

    constexpr inline bool is_negative() const { return sign != 0; }
    constexpr inline bool is_zero() const     { return (jbit == 0) && (mantissa == 0); }
    constexpr inline bool is_denormal() const { return (jbit == 0) && (mantissa != 0); }
    constexpr inline bool is_finite() const   { return exponent != FLOAT80_NAN_EXPONENT; }
    constexpr inline bool is_max() const      { return (exponent == FLOAT80_INFINITY_EXPONENT - 1) && (jbit == 1) && (mantissa == FLOAT80_MANTISSA_MASK); }
    constexpr inline bool is_inf() const      { return (exponent == FLOAT80_INFINITY_EXPONENT) && (mantissa == 0); }
    constexpr inline bool is_nan() const      { return  (exponent == FLOAT80_NAN_EXPONENT) && (mantissa != 0); }
    constexpr inline bool is_snan() const     { return is_nan() && ((mantissa & FLOAT80_MANTISSA_QUIET_NAN_MASK) == 0); }
    constexpr inline bool is_qnan() const     { return is_nan() && ((mantissa & FLOAT80_MANTISSA_QUIET_NAN_MASK) != 0); }
    constexpr inline uint64_t get_nan_payload() const   { return mantissa & (~FLOAT80_MANTISSA_QUIET_NAN_MASK); }

    static constexpr inline uint32_t mantissa_bits() { return FLOAT80_MANTISSA_BITS; }
    static constexpr inline uint32_t exponent_bits() { return FLOAT80_EXPONENT_BITS; }

    constexpr inline Float80 operator-() const {
        return { (uint64_t) (sign ^ 1), exponent, jbit, mantissa };
    }
#endif
};
typedef struct Float80 Float80;

STATIC_INLINE bool Float80_is_negative(Float80 f) { return f.sign != 0; }
STATIC_INLINE bool Float80_is_zero(Float80 f)     { return (f.jbit == 0) && (f.mantissa == 0); }
STATIC_INLINE bool Float80_is_denormal(Float80 f) { return (f.jbit == 0) && (f.mantissa != 0); }
STATIC_INLINE bool Float80_is_finite(Float80 f)   { return f.exponent != FLOAT80_NAN_EXPONENT; }
STATIC_INLINE bool Float80_is_max(Float80 f)      { return (f.exponent == FLOAT80_INFINITY_EXPONENT - 1) && (f.jbit == 1) && (f.mantissa == FLOAT80_MANTISSA_MASK); }
STATIC_INLINE bool Float80_is_inf(Float80 f)      { return (f.exponent == FLOAT80_INFINITY_EXPONENT) && (f.jbit == 1) && (f.mantissa == 0); }
STATIC_INLINE bool Float80_is_nan(Float80 f)      { return (f.exponent == FLOAT80_NAN_EXPONENT) && (f.mantissa != 0); }
STATIC_INLINE bool Float80_is_snan(Float80 f)     { return Float80_is_nan(f) && ((f.mantissa & FLOAT80_QUIET_BITS) == 0); }
STATIC_INLINE bool Float80_is_qnan(Float80 f)     { return Float80_is_nan(f) && ((f.mantissa & FLOAT80_QUIET_BITS) != 0); }

STATIC_INLINE uint64_t Float80_get_nan_payload(Float80 f) { return f.as_nan.payload; }
STATIC_INLINE long double Float80_as_fp(Float80 f) { return f.as_float; }

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

STATIC_INLINE bool float_is_negative(float f) { Float32 tmp; tmp.as_float = f; return Float32_is_negative(tmp); }
STATIC_INLINE bool double_is_negative(double d) { Float64 tmp; tmp.as_float = d; return Float64_is_negative(tmp); }

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
#define IS_NEGATIVE(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_negative,\
        HFloat8: HFloat8_is_negative,\
        Float16: Float16_is_negative,\
        BFloat16: BFloat16_is_negative,\
        Float32: Float32_is_negative,\
        Float64: Float64_is_negative,\
        Float80: Float80_is_negative,\
        double: double_is_negative,\
        float: float_is_negative\
    )(v)
#endif

STATIC_INLINE bool float_is_zero(float f) { Float32 tmp; tmp.as_float = f; return Float32_is_zero(tmp); }
STATIC_INLINE bool double_is_zero(double d) { Float64 tmp; tmp.as_float = d; return Float64_is_zero(tmp); }

#ifdef __cplusplus
template<typename T>
constexpr inline bool IS_ZERO(T v) {
    return v.is_zero();
}
template<>
constexpr inline bool IS_ZERO(float v) {
    return Float32(v).is_zero();
}
template<>
constexpr inline bool IS_ZERO(double v) {
    return Float64(v).is_zero();
}
#else
#define IS_ZERO(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_zero,\
        HFloat8: HFloat8_is_zero,\
        Float16: Float16_is_zero,\
        BFloat16: BFloat16_is_zero,\
        Float32: Float32_is_zero,\
        Float64: Float64_is_zero,\
        Float80: Float80_is_zero,\
        double: double_is_zero,\
        float: float_is_zero\
    )(v)
#endif

STATIC_INLINE bool float_is_denormal(float f) { Float32 tmp; tmp.as_float = f; return Float32_is_denormal(tmp); }
STATIC_INLINE bool double_is_denormal(double d) { Float64 tmp; tmp.as_float = d; return Float64_is_denormal(tmp); }

#ifdef __cplusplus
template<typename T>
constexpr inline bool IS_DENORMAL(T v) {
    return v.is_denormal();
}
template<>
constexpr inline bool IS_DENORMAL(float v) {
    return Float32(v).is_denormal();
}
template<>
constexpr inline bool IS_DENORMAL(double v) {
    return Float64(v).is_denormal();
}
#else
#define IS_DENORMAL(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_denormal,\
        HFloat8: HFloat8_is_denormal,\
        Float16: Float16_is_denormal,\
        BFloat16: BFloat16_is_denormal,\
        Float32: Float32_is_denormal,\
        Float64: Float64_is_denormal,\
        Float80: Float80_is_denormal,\
        double: double_is_denormal,\
        float: float_is_denormal\
    )(v)
#endif

STATIC_INLINE bool float_is_finite(float f) { Float32 tmp; tmp.as_float = f; return Float32_is_finite(tmp); }
STATIC_INLINE bool double_is_finite(double d) { Float64 tmp; tmp.as_float = d; return Float64_is_finite(tmp); }

#ifdef __cplusplus
template<typename T>
constexpr inline bool IS_FINITE(T v) {
    return v.is_finite();
}
template<>
constexpr inline bool IS_FINITE(float v) {
    return Float32(v).is_finite();
}
template<>
constexpr inline bool IS_FINITE(double v) {
    return Float64(v).is_finite();
}
#else
#define IS_FINITE(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_finite,\
        HFloat8: HFloat8_is_finite,\
        Float16: Float16_is_finite,\
        BFloat16: BFloat16_is_finite,\
        Float32: Float32_is_finite,\
        Float64: Float64_is_finite,\
        Float80: Float80_is_finite,\
        double: double_is_finite,\
        float: float_is_finite\
    )(v)
#endif

#ifdef __cplusplus
template<typename T>
constexpr inline bool IS_INF_NAN(T v) {
    static_assert(NotImplementedFor<T>::value, "type does not have single INF_NAN value");
    return false;
}
template<>
constexpr inline bool IS_INF_NAN(HFloat8 v) {
    return v.is_inf_nan();
}
#else
#define IS_INF_NAN(v) \
    _Generic((v),\
        HFloat8: HFloat8_is_inf_nan\
    )(v)
#endif

#ifdef __cplusplus
template<typename T>
constexpr inline bool IS_OVERFLOW(T v) {
    static_assert(NotImplementedFor<T>::value, "type does not have single OVERFLOW value");
    return false;
}
template<>
constexpr inline bool IS_OVERFLOW(HFloat8 v) {
    return v.is_overflow();
}
template<>
constexpr inline bool IS_OVERFLOW(BFloat8 v) {
    return v.is_overflow();
}
#else
#define IS_OVERFLOW(v) \
    _Generic((v),\
        HFloat8: HFloat8_is_overflow,\
        BFloat8: BFloat8_is_overflow\
    )(v)
#endif

STATIC_INLINE bool float_is_inf(float f) { Float32 tmp; tmp.as_float = f; return Float32_is_inf(tmp); }
STATIC_INLINE bool double_is_inf(double d) { Float64 tmp; tmp.as_float = d; return Float64_is_inf(tmp); }

#ifdef __cplusplus
template<typename T>
constexpr inline bool IS_INF(T v) {
    return v.is_inf();
}
template<>
constexpr inline bool IS_INF(float v) {
    return Float32(v).is_inf();
}
template<>
constexpr inline bool IS_INF(double v) {
    return Float64(v).is_inf();
}
#else
#define IS_INF(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_inf,\
        Float16: Float16_is_inf,\
        BFloat16: BFloat16_is_inf,\
        Float32: Float32_is_inf,\
        Float64: Float64_is_inf,\
        Float80: Float80_is_inf,\
        double: double_is_inf,\
        float: float_is_inf\
    )(v)
#endif

STATIC_INLINE bool float_is_nan(float f) { Float32 tmp; tmp.as_float = f; return Float32_is_nan(tmp); }
STATIC_INLINE bool double_is_nan(double d) { Float64 tmp; tmp.as_float = d; return Float64_is_nan(tmp); }

#ifdef __cplusplus
template<typename T>
constexpr inline bool IS_NAN(T v) {
    return v.is_nan();
}
template<>
constexpr inline bool IS_NAN(float v) {
    return Float32(v).is_nan();
}
template<>
constexpr inline bool IS_NAN(double v) {
    return Float64(v).is_nan();
}
#else
#define IS_NAN(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_nan,\
        Float16: Float16_is_nan,\
        BFloat16: BFloat16_is_nan,\
        Float32: Float32_is_nan,\
        Float64: Float64_is_nan,\
        Float80: Float80_is_nan,\
        double: double_is_nan,\
        float: float_is_nan\
    )(v)
#endif

STATIC_INLINE bool float_is_snan(float f) { Float32 tmp; tmp.as_float = f; return Float32_is_snan(tmp); }
STATIC_INLINE bool double_is_snan(double d) { Float64 tmp; tmp.as_float = d; return Float64_is_snan(tmp); }

#ifdef __cplusplus
template<typename T>
constexpr inline bool IS_SNAN(T v) {
    return v.is_snan();
}
template<>
constexpr inline bool IS_SNAN(float v) {
    return Float32(v).is_snan();
}
template<>
constexpr inline bool IS_SNAN(double v) {
    return Float64(v).is_snan();
}
#else
#define IS_SNAN(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_snan,\
        Float16: Float16_is_snan,\
        BFloat16: BFloat16_is_snan,\
        Float32: Float32_is_snan,\
        Float64: Float64_is_snan,\
        Float80: Float80_is_snan,\
        double: double_is_snan,\
        float: float_is_snan\
    )(v)
#endif

STATIC_INLINE bool float_is_qnan(float f) { Float32 tmp; tmp.as_float = f; return Float32_is_qnan(tmp); }
STATIC_INLINE bool double_is_qnan(double d) { Float64 tmp; tmp.as_float = d; return Float64_is_qnan(tmp); }

#ifdef __cplusplus
template<typename T>
constexpr inline bool IS_QNAN(T v) {
    return v.is_qnan();
}
template<>
constexpr inline bool IS_QNAN(float v) {
    return Float32(v).is_qnan();
}
template<>
constexpr inline bool IS_QNAN(double v) {
    return Float64(v).is_qnan();
}
#else
#define IS_QNAN(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_qnan,\
        Float16: Float16_is_qnan,\
        BFloat16: BFloat16_is_qnan,\
        Float32: Float32_is_qnan,\
        Float64: Float64_is_qnan,\
        Float80: Float80_is_qnan,\
        double: double_is_qnan,\
        float: float_is_qnan\
    )(v)
#endif

STATIC_INLINE bool float_is_max(float f) { Float32 tmp; tmp.as_float = f; return Float32_is_max(tmp); }
STATIC_INLINE bool double_is_max(double d) { Float64 tmp; tmp.as_float = d; return Float64_is_max(tmp); }

#ifdef __cplusplus
template<typename T>
constexpr inline bool IS_MAX(T v) {
    return v.is_max();
}
template<>
constexpr inline bool IS_MAX(float v) {
    return Float32(v).is_max();
}
template<>
constexpr inline bool IS_MAX(double v) {
    return Float64(v).is_max();
}
#else
#define IS_MAX(v) \
    _Generic((v),\
        BFloat8: BFloat8_is_max,\
        Float16: Float16_is_max,\
        BFloat16: BFloat16_is_max,\
        Float32: Float32_is_max,\
        Float64: Float64_is_max,\
        Float80: Float80_is_max,\
        double: double_is_max,\
        float: float_is_max\
    )(v)
#endif

STATIC_INLINE uint32_t float_get_nan_payload(float f) { Float32 tmp; tmp.as_float = f; return Float32_get_nan_payload(tmp); }
STATIC_INLINE uint64_t double_get_nan_payload(double d) { Float64 tmp; tmp.as_float = d; return Float64_get_nan_payload(tmp); }

#ifdef __cplusplus
template<typename T>
constexpr inline int GET_NAN_PAYLOAD(T v) {
    static_assert(NotImplementedFor<T>::value, "type does not have NaN payload");
    return 0;
}
constexpr inline uint16_t GET_NAN_PAYLOAD(Float16 v) {
    return v.get_nan_payload();
}
constexpr inline uint16_t GET_NAN_PAYLOAD(BFloat16 v) {
    return v.get_nan_payload();
}
constexpr inline uint32_t GET_NAN_PAYLOAD(Float32 v) {
    return v.get_nan_payload();
}
constexpr inline uint32_t GET_NAN_PAYLOAD(float v) {
    return Float32(v).get_nan_payload();
}
constexpr inline uint64_t GET_NAN_PAYLOAD(Float64 v) {
    return v.get_nan_payload();
}
constexpr inline uint64_t GET_NAN_PAYLOAD(double v) {
    return Float64(v).get_nan_payload();
}
constexpr inline uint64_t GET_NAN_PAYLOAD(Float80 v) {
    return v.get_nan_payload();
}
#else
#define GET_NAN_PAYLOAD(v) \
    _Generic((v),\
        Float16: Float16_get_nan_payload,\
        BFloat16: BFloat16_get_nan_payload,\
        Float32: Float32_get_nan_payload,\
        Float64: Float64_get_nan_payload,\
        Float80: Float80_get_nan_payload,\
        double: double_get_nan_payload,\
        float: float_get_nan_payload\
    )(v)
#endif

STATIC_INLINE float float_as_fp(float f) { return f; }
STATIC_INLINE double double_as_fp(double d) { return d; }

#ifdef __cplusplus
template<typename F>
inline float AS_FP(F f) {
    return f.as_fp();
}
template<>
inline float AS_FP(float f) {
    return f;
}
template<>
inline float AS_FP(double d) {
    return d;
}
template<>
inline float AS_FP(long double d) {
    return d;
}
#else
#define AS_FP(v) \
    _Generic((v),\
        HFloat8:  HFloat8_as_fp,\
        BFloat8:  BFloat8_as_fp,\
        Float16:  Float16_as_fp,\
        BFloat16: BFloat16_as_fp,\
        Float32:  Float32_as_fp,\
        Float64:  Float64_as_fp,\
        Float80:  Float80_as_fp,\
        double:   double_as_fp,\
        float:    float_as_fp\
    )(v)
#endif

/** @} */

#if defined(OBSOLETE_RANDOM_GENERATORS)
// TODO remove when new approach is accepted
// previous simple random generators

#ifdef __cplusplus
extern "C" {
#endif

HFloat8 new_random_hfloat8();
BFloat8 new_random_bfloat8();
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

#ifdef __cplusplus
}
#endif

#elif !defined(OBSOLETE_RANDOM_GENERATORS)
// new random generators with flags

enum FP_GEN_RANDOM_FLAGS {
    // select predefined value or generate according other flags with given probability
    FP_GEN_PCT_VEC_SELECTOR_VAL_MASK        = 0x0000007f,
    FP_GEN_PCT_VEC_SELECTOR                 = 0x00000080,
    // helper to build predefined/random percentage "flags"
    #define FP_GEN_PCT_VEC(pct) (FP_GEN_PCT_VEC_SELECTOR | ((pct) & FP_GEN_PCT_VEC_SELECTOR_VAL_MASK))

    // mantissa generation
    FP_GEN_RANDOM_FLAGS_MANTISSA_MASK       = 0x00070000,
    FP_GEN_RANDOM_FLAGS_MANTISSA_BITS       = 0x00000000, // fetch appropriate number of bits from the "factory"
    FP_GEN_RANDOM_FLAGS_MANTISSA_PATTERNED  = 0x00010000, // set_random_bits(), compatibility with previous generators
    FP_GEN_RANDOM_FLAGS_MANTISSA_VECTOR     = 0x00020000, // get_float_vector(random_vector_index)
    FP_GEN_RANDOM_FLAGS_MANTISSA_RANDOM     = 0x00030000, // sufficient random()/random32()/random64()/...
    FP_GEN_RANDOM_FLAGS_MANTISSA_UNHANDLED1 = 0x00040000,
    FP_GEN_RANDOM_FLAGS_MANTISSA_UNHANDLED2 = 0x00050000,
    FP_GEN_RANDOM_FLAGS_MANTISSA_UNHANDLED3 = 0x00060000,
    FP_GEN_RANDOM_FLAGS_MANTISSA_ZERO       = 0x00070000, // zero

    // random exponent generation
    FP_GEN_RANDOM_FLAGS_EXPONENT_MASK       = 0x00f00000,
    FP_GEN_RANDOM_FLAGS_EXPONENT_BITS       = 0x00000000, // fetch appropriate number of bits from the "factory", flat distribution
    FP_GEN_RANDOM_FLAGS_EXPONENT_GAUSSIAN2  = 0x00100000, // n/2 + n/2 gaussian bell distribution, bits from the "factory"
    FP_GEN_RANDOM_FLAGS_EXPONENT_GAUSSIAN4  = 0x00200000, // n/2 + n/4 + n/4 gaussian bell distribution
    FP_GEN_RANDOM_FLAGS_EXPONENT_GAUSSIAN8  = 0x00300000, // n/2 + n/4 + n/8 + n/8 gaussian bell distribution
    // special values for exponent
    FP_GEN_RANDOM_FLAGS_EXPONENT_RANDOM     = 0x00400000, // random()
    FP_GEN_RANDOM_FLAGS_EXPONENT_VECTOR     = 0x00800000, // get_float_vector(random_vector_index)
    FP_GEN_RANDOM_FLAGS_EXPONENT_ZERO       = 0x00d00000, // zero exponent, no assumption on the mantissa (ti denormal/zero are expected)
    FP_GEN_RANDOM_FLAGS_EXPONENT_MAX        = 0x00e00000, // max possible exponent, no assumption on the mantissa (Inf/NaN/overflow/large value, depending on the type), will skip some HFloat8 values!
    FP_GEN_RANDOM_FLAGS_EXPONENT_BIAS       = 0x00f00000, // exponent equal BIAS, i.e. values [1..2), forced when NORMALIZE_FP
    // special values for exponent (with special mantissa handling done in next steps)
    FP_GEN_RANDOM_FLAGS_VALUE_ZERO          = 0x00500000, // zero, both exponent and mantissa zeroed
    FP_GEN_RANDOM_FLAGS_VALUE_DENORMAL      = 0x00600000, // denormal number, 0s excluded (random bit is set to 1 if zero in mantissa)
    FP_GEN_RANDOM_FLAGS_VALUE_INF           = 0x00700000, // infinity, zero in the mantissa implied/forced
    FP_GEN_RANDOM_FLAGS_VALUE_OVERFLOW      = 0x00900000, // overflow
    FP_GEN_RANDOM_FLAGS_VALUE_NAN           = 0x00a00000, // any NaN, Inf excluded (random bit is set to 1 if zero in mantissa)
    FP_GEN_RANDOM_FLAGS_VALUE_SNAN          = 0x00b00000, // signalling NaN, Q bit is cleared
    FP_GEN_RANDOM_FLAGS_VALUE_QNAN          = 0x00c00000, // quiet NaN, Q bit is set

    // sign generation
    FP_GEN_RANDOM_FLAGS_SIGN_MASK           = 0x03000000,
    FP_GEN_RANDOM_FLAGS_SIGN_BITS           = 0x00000000, // fetch appropriate number of bits from the "factory"
    FP_GEN_RANDOM_FLAGS_SIGN_NEGATIVE       = 0x01000000, // forced sign=1
    FP_GEN_RANDOM_FLAGS_SIGN_POSITIVE       = 0x02000000, // forced sign=0
    FP_GEN_RANDOM_FLAGS_SIGN_RANDOM         = 0x03000000, // random()

    // enforcement flags
    FP_GEN_RANDOM_FLAGS_FORCE_FINITE        = 0x04000000, // must be a finite number, Inf/NaNs/overflow excluded
    FP_GEN_RANDOM_FLAGS_NO_SUBNORMALS       = 0x08000000, // must not be a subnormal number, use with _FINITE to get normal number

    // normalize values to given range [v1,v2)
    FP_GEN_NORMALIZE                        = 0x10000000,

    // extra scenarios (expected without any other flags), NORMALIZE bit cannot be used here (only "even" values)
    FP_GEN_FAST_ZERO                        = 0x20000000, // zero initialization
    FP_GEN_FAST_MEMSET_ZERO                 = 0x40000000, // whole value initialized with "memzero()"
    FP_GEN_FAST_MEMSET_RANDOM               = 0x60000000, // whole value initialized with "memset_random()"
    FP_GEN_COMPATIBILITY_GENERATOR          = 0x80000000, // obsolete simple random generator

    // short aliases
    FP_GEN_POSITIVE = FP_GEN_RANDOM_FLAGS_SIGN_POSITIVE,
    FP_GEN_NEGATIVE = FP_GEN_RANDOM_FLAGS_SIGN_NEGATIVE,
    FP_GEN_FINITE = FP_GEN_RANDOM_FLAGS_FORCE_FINITE,
    FP_GEN_ZERO = FP_GEN_RANDOM_FLAGS_VALUE_ZERO,
    FP_GEN_INF = FP_GEN_RANDOM_FLAGS_VALUE_INF,
    FP_GEN_DENORMAL = FP_GEN_RANDOM_FLAGS_VALUE_DENORMAL,
    FP_GEN_OVERFLOW = FP_GEN_RANDOM_FLAGS_VALUE_OVERFLOW,
    FP_GEN_NAN = FP_GEN_RANDOM_FLAGS_VALUE_NAN,
    FP_GEN_SNAN = FP_GEN_RANDOM_FLAGS_VALUE_SNAN,
    FP_GEN_QNAN = FP_GEN_RANDOM_FLAGS_VALUE_QNAN,
    FP_GEN_RANGE12 = FP_GEN_RANDOM_FLAGS_SIGN_POSITIVE | FP_GEN_RANDOM_FLAGS_EXPONENT_BIAS,

    #define FP_GEN_CMATH_CLASS(c) \
        ({\
            uint32_t flags;\
            switch ((c)) {\
                case FP_NORMAL:\
                    flags = FP_GEN_RANDOM_FLAGS_FORCE_FINITE | FP_GEN_RANDOM_FLAGS_NO_SUBNORMALS;\
                    break;\
                case FP_SUBNORMAL:\
                    flags = FP_GEN_RANDOM_FLAGS_VALUE_DENORMAL;\
                    break;\
                case FP_ZERO:\
                    flags = FP_GEN_RANDOM_FLAGS_VALUE_ZERO;\
                    break;\
                case FP_INFINITE:\
                    flags = FP_GEN_RANDOM_FLAGS_VALUE_INF;\
                    break;\
                case FP_NAN:\
                    flags = FP_GEN_RANDOM_FLAGS_VALUE_NAN;\
                    break;\
                default:\
                    assert(false && "unsupported cmath classification");\
                    flags = 0;\
                    break;\
            }\
            flags;\
        })

    // value from predefined vectors
    FP_GEN_STATIC_VECTOR = FP_GEN_RANDOM_FLAGS_SIGN_POSITIVE | FP_GEN_RANDOM_FLAGS_EXPONENT_VECTOR | FP_GEN_RANDOM_FLAGS_MANTISSA_VECTOR,

    // optimized random generation
    FP_GEN_RANDOM = FP_GEN_RANDOM_FLAGS_SIGN_BITS | FP_GEN_RANDOM_FLAGS_EXPONENT_BITS | FP_GEN_RANDOM_FLAGS_MANTISSA_BITS,
};

#ifdef __cplusplus
extern "C" {
#endif

void set_random_hfloat8 (HFloat8*  ptr, size_t num, uint32_t flags, float v1, float v2);
void set_random_bfloat8 (BFloat8*  ptr, size_t num, uint32_t flags, float v1, float v2);
void set_random_float16 (Float16*  ptr, size_t num, uint32_t flags, float v1, float v2);
void set_random_bfloat16(BFloat16* ptr, size_t num, uint32_t flags, float v1, float v2);
void set_random_float32 (Float32*  ptr, size_t num, uint32_t flags, float v1, float v2);
void set_random_float   (float*    ptr, size_t num, uint32_t flags, float v1, float v2);
void set_random_float64 (Float64*  ptr, size_t num, uint32_t flags, float v1, float v2);
void set_random_double  (double*   ptr, size_t num, uint32_t flags, float v1, float v2);
void set_random_float80 (Float80*  ptr, size_t num, uint32_t flags, float v1, float v2);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
template<typename F>
inline void set_random_gen(F* ptr, size_t num, uint32_t flags, float v1, float v2) {
    static_assert(NotImplementedFor<F>::value, "Type not supported for set_random()");
}
template<>
inline void set_random_gen(HFloat8* ptr, size_t num, uint32_t flags, float v1, float v2) {
    set_random_hfloat8(ptr, num, flags, v1, v2);
}
template<>
inline void set_random_gen(BFloat8* ptr, size_t num, uint32_t flags, float v1, float v2) {
    set_random_bfloat8(ptr, num, flags, v1, v2);
}
template<>
inline void set_random_gen(Float16* ptr, size_t num, uint32_t flags, float v1, float v2) {
    set_random_float16(ptr, num, flags, v1, v2);
}
template<>
inline void set_random_gen(BFloat16* ptr, size_t num, uint32_t flags, float v1, float v2) {
    set_random_bfloat16(ptr, num, flags, v1, v2);
}
template<>
inline void set_random_gen(Float32* ptr, size_t num, uint32_t flags, float v1, float v2) {
    set_random_float32(ptr, num, flags, v1, v2);
}
template<>
inline void set_random_gen(float* ptr, size_t num, uint32_t flags, float v1, float v2) {
    set_random_float(ptr, num, flags, v1, v2);
}
template<>
inline void set_random_gen(Float64* ptr, size_t num, uint32_t flags, float v1, float v2) {
    set_random_float64(ptr, num, flags, v1, v2);
}
template<>
inline void set_random_gen(double* ptr, size_t num, uint32_t flags, float v1, float v2) {
    set_random_double(ptr, num, flags, v1, v2);
}
template<>
inline void set_random_gen(Float80* ptr, size_t num, uint32_t flags, float v1, float v2) {
    set_random_float80(ptr, num, flags, v1, v2);
}
#else
#define set_random_gen(ptr, num, flags, v1, v2)\
    _Generic(*(ptr),\
        HFloat8:  set_random_hfloat8,\
        BFloat8:  set_random_bfloat8,\
        Float16:  set_random_float16,\
        BFloat16: set_random_bfloat16,\
        Float32:  set_random_float32,\
        float:    set_random_float,\
        Float64:  set_random_float64,\
        double:   set_random_double,\
        Float80:  set_random_float80\
    )((ptr), (num), (flags), (v1), (v2))
#endif

#define CHECK_NORMALIZATION(flags) ({\
    assert((((flags) & FP_GEN_NORMALIZE) == 0) && "FP_GEN_NORMALIZE requires a range");\
    (flags);\
})

#define set_random(...)                      OVERLOAD(set_random, NARGS(__VA_ARGS__))(__VA_ARGS__)
#define set_random2(ptr, num)                set_random_gen((ptr), (num), FP_GEN_RANDOM, -1.0f, FLT_MAX)
#define set_random3(ptr, num, flags)         set_random_gen((ptr), (num), CHECK_NORMALIZATION((flags)), -1.0f, FLT_MAX)
#define set_random4(ptr, num, v1, v2)        set_random_gen((ptr), (num), FP_GEN_RANDOM | FP_GEN_NORMALIZE, (v1), (v2))
#define set_random5(ptr, num, flags, v1, v2) set_random_gen((ptr), (num), (flags) | FP_GEN_NORMALIZE, (v1), (v2))

#define SET_RANDOM(var, ...) set_random(&var, 1, ##__VA_ARGS__)
#define SET_RANDOM_PTR(ptr, num, ...) set_random((ptr), (num), ##__VA_ARGS__)
#define SET_RANDOM_ARR(arr, ...) set_random((arr), sizeof(arr) / sizeof((arr)[0]), ##__VA_ARGS__)

// backward compatibility with existing code
#define new_random_gen(type, flags, v1, v2)\
    ({ type val; set_random_gen(&val, 1, (flags), (v1), (v2)); val; })

#define new_random(...)                  OVERLOAD(new_random, NARGS(__VA_ARGS__))(__VA_ARGS__)
#define new_random1(type)                new_random_gen(type, FP_GEN_COMPATIBILITY_GENERATOR, -1.0f, FLT_MAX)
#define new_random2(type, flags)         new_random_gen(type, CHECK_NORMALIZATION((flags)), -1.0f, FLT_MAX)
#define new_random3(type, v1, v2)        new_random_gen(type, FP_GEN_RANDOM | FP_GEN_NORMALIZE, (v1), (v2))
#define new_random4(type, flags, v1, v2) new_random_gen(type, (flags) | FP_GEN_NORMALIZE, (v1), (v2))

#define new_random_hfloat8(...)  new_random(HFloat8,  ##__VA_ARGS__)
#define new_random_bfloat8(...)  new_random(BFloat8,  ##__VA_ARGS__)
#define new_random_float16(...)  new_random(Float16,  ##__VA_ARGS__)
#define new_random_bfloat16(...) new_random(BFloat16, ##__VA_ARGS__)
#define new_random_float32(...)  new_random(Float32,  ##__VA_ARGS__)
#define new_random_float(...)    new_random(float,    ##__VA_ARGS__)
#define new_random_float64(...)  new_random(Float64,  ##__VA_ARGS__)
#define new_random_double(...)   new_random(double,   ##__VA_ARGS__)
#define new_random_float80(...)  new_random(Float80,  ##__VA_ARGS__)

#endif // NEW/OBSOLETE_RANDOM_GENERATORS

#undef STATIC_INLINE
#endif //FRAMEWORK_FP_VECTORS_FLOATS_H
