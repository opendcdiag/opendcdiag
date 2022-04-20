/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __FP_VECTORS_H
#define __FP_VECTORS_H

#include <assert.h>
#include <stdint.h>

// GCC supports _Float16 on x86 and __fp16 on AArch64, in both cases it
// only supports IEEE-754 format.
// https://gcc.gnu.org/onlinedocs/gcc/Half-Precision.html
#if defined(SANDSTONE_HAS_FLOAT16_TYPE)
typedef _Float16 fp16_t;
#elif defined(SANDSTONE_HAS__FP16_TYPE)
typedef __fp16 fp16_t;
#endif

#if !defined(SANDSTONE_HAS_FLOAT16_TYPE) && !defined(SANDSTONE_HAS__FP16_TYPE)
#  define SANDSTONE_FLOAT16_EMULATED
#endif

#ifndef __FLT128_DECIMAL_DIG__
#  define __FLT128_DECIMAL_DIG__ 36
#endif
#ifndef __FLT128_DENORM_MIN__
#  define __FLT128_DENORM_MIN__ 6.47517511943802511092443895822764655e-4966F128
#endif

#define FLOAT16_EXPONENT_MASK  0x1fu
#define FLOAT32_EXPONENT_MASK  0xffu
#define FLOAT64_EXPONENT_MASK  0x7ffu
#define FLOAT80_EXPONENT_MASK  0x7fffu

#define FLOAT16_INFINITY_EXPONENT  0x1fu
#define FLOAT32_INFINITY_EXPONENT  0xffu
#define FLOAT64_INFINITY_EXPONENT  0x7ffu
#define FLOAT80_INFINITY_EXPONENT  0x7fffu

#define FLOAT16_NAN_EXPONENT  0x1fu
#define FLOAT32_NAN_EXPONENT  0xffu
#define FLOAT64_NAN_EXPONENT  0x7ffu
#define FLOAT80_NAN_EXPONENT  0x7fffu

#define FLOAT16_EXPONENT_BIAS  0x0fu
#define FLOAT32_EXPONENT_BIAS  0x7fu
#define FLOAT64_EXPONENT_BIAS  0x3ffu
#define FLOAT80_EXPONENT_BIAS  0x3fffu

#define FLOAT16_MANTISSA_MASK  0x3ffu
#define FLOAT32_MANTISSA_MASK  0x7fffffu
#define FLOAT64_MANTISSA_MASK  0xfffffffffffffu
#define FLOAT80_MANTISSA_MASK  0xffffffffffffffffu

#define FLOAT16_MANTISSA_QUIET_NAN_MASK  0x200u
#define FLOAT32_MANTISSA_QUIET_NAN_MASK  0x400000u
#define FLOAT64_MANTISSA_QUIET_NAN_MASK  0x8000000000000u
#define FLOAT80_MANTISSA_QUIET_NAN_MASK  0x8000000000000000u

#define FP16_DECIMAL_DIG        5
#define FP16_DENORM_MIN         5.96046447753906250000000000000000000e-8
#define FP16_DIG                3
#define FP16_EPSILON            9.76562500000000000000000000000000000e-4
#define FP16_HAS_DENORM         1
#define FP16_HAS_INFINITY       1
#define FP16_HAS_QUIET_NAN      1
#define FP16_MANT_DIG           11
#define FP16_MAX_10_EXP         4
#define FP16_MAX                6.55040000000000000000000000000000000e+4
#define FP16_MAX_EXP            16
#define FP16_MIN_10_EXP         (-4)
#define FP16_MIN                6.10351562500000000000000000000000000e-5
#define FP16_MIN_EXP            (-13)
#define FP16_NORM_MAX           6.55040000000000000000000000000000000e+4

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
extern "C" {
#endif

struct Float16
{
    union {
#if defined(SANDSTONE_HAS_FLOAT16_TYPE) || \
    defined(SANDSTONE_HAS__FP16_TYPE)

        fp16_t as_float;

#endif

        union {
            uint16_t as_hex;
            uint16_t payload;
        };

        struct __attribute__((packed)) {
            uint16_t mantissa : 10;
            uint16_t exponent : 5;
            uint16_t sign : 1;
        };
    };

#ifdef __cplusplus
    Float16() = default;
    inline Float16(float f);

    static constexpr int digits = FP16_MANT_DIG;
    static constexpr int digits10 = FP16_DIG;
    static constexpr int max_digits10 = 6;  // log2(digits)
    static constexpr int min_exponent = FP16_MIN_EXP;
    static constexpr int min_exponent10 = FP16_MIN_10_EXP;
    static constexpr int max_exponent = FP16_MAX_EXP;
    static constexpr int max_exponent10 = FP16_MAX_10_EXP;

    static constexpr bool radix = 2;
    static constexpr bool is_signed = true;
    static constexpr bool is_integer = false;
    static constexpr bool is_exact = false;
    static constexpr bool has_infinity = FP16_HAS_INFINITY;
    static constexpr bool has_quiet_NaN = FP16_HAS_QUIET_NAN;
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
    explicit constexpr Float16(Holder h) : as_hex(h.payload) {}
#endif
};
static_assert(sizeof(struct Float16) == 2, "Float16 structure is not of the correct size");

struct BFloat16
{
    union {

        union {
            uint16_t as_hex;
            uint16_t payload;
        };

        struct __attribute__((packed)) {
            uint16_t mantissa : 10;
            uint16_t exponent : 5;
            uint16_t sign : 1;
        };
    };

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
    explicit constexpr BFloat16(Holder h) : as_hex(h.payload) {}
#endif
};
static_assert(sizeof(struct BFloat16) == 2, "BFloat16 structure is not of the correct size");

typedef struct Float16 Float16;
typedef struct BFloat16 BFloat16;

typedef union {
    float as_float;
    uint32_t as_hex;
    struct {
        unsigned mantissa : 23;
        unsigned exponent : 8;
        unsigned sign : 1;
    };
} Float32;
static_assert(sizeof(Float32) == sizeof(float), "Float32 structure is not of the correct size");

typedef union {
    double as_float;
    uint64_t as_hex;
    struct {
        unsigned long long mantissa : 52;
        unsigned long long exponent : 11;
        unsigned long long sign : 1;
    };
} Float64;
static_assert(sizeof(Float64) == sizeof(double), "Float64 structure is not of the correct size");

typedef union {
    struct {
        long double as_float;
    };
    struct {
        unsigned long long mantissa : 63;
        unsigned long jbit : 1;
        unsigned exponent : 15;
        unsigned sign : 1;
    };
    struct {
        uint64_t low64;
        uint16_t high16;
    } as_hex;
} Float80;
static_assert(sizeof(double) < sizeof(long double), "Compiler does not support long double");
static_assert(sizeof(Float80) == sizeof(long double), "Float80 structure is not of the correct size");

Float16 new_float16(unsigned sign, unsigned exponent, unsigned mantissa);
Float32 new_float32(uint32_t sign, uint32_t exponent, uint32_t mantissa);
Float64 new_float64(uint32_t sign, uint32_t exponent, uint64_t mantissa);
Float80 new_float80(uint32_t sign, uint32_t exponent, uint32_t jbit, uint64_t mantissa);

Float16 new_random_float16();
Float32 new_random_float32();
Float64 new_random_float64();
Float80 new_random_float80();

#ifdef __cplusplus
} // extern "C"
#endif

#endif //PROJECT_FP_VECTORS_H
