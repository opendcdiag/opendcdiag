/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gtest/gtest.h"
#include "sandstone_data.h"

#include <string.h>
#include <iomanip>

static constexpr bool UseF16C = false
#ifdef __F16C__
        || true
#endif
        ;

#if __GNUC__ > 9 || __clang_major__ >= 9
__attribute__((target("avx512vl,avx512bf16")))
static inline BFloat16 tobf16_avx512(float f)
{
    BFloat16 r;
    __m128bh m = _mm_cvtneps_pbh(_mm_set_ss(f));
    r.payload = std::bit_cast<uint16_t>(m[0]);
    return r;
}

static bool useAvx512Bf16()
{
#ifdef __AVX512BF16__
    return true;
#endif
    return __builtin_cpu_supports("avx512bf16");
}
#else
static inline BFloat16 tobf16_avx512(float f)
{
    __builtin_unreachable();
}
static bool useAvx512Bf16()
{
    return false;
}
#endif

#define DECLARE_CONV_SET(Class, fromfunc, tofunc)       \
    struct Class { \
        using Type = decltype(fromfunc(0.f)); \
        using Traits = SandstoneDataDetails::TypeToDataType<Type>; \
        static constexpr auto tofloat = tofunc; \
        static constexpr auto fromfloat = fromfunc; \
        static const char *tofloat_name() { return #tofunc; } \
        static const char *fromfloat_name() { return #fromfunc; } \
    }

DECLARE_CONV_SET(FP16Emulated, tofp16_emulated, fromfp16_emulated);
DECLARE_CONV_SET(FP16_F16C, tofp16, fromfp16);
DECLARE_CONV_SET(BF16Emulated, tobf16_emulated, frombf16_emulated);
DECLARE_CONV_SET(BF16_AVX512, tobf16_avx512, frombf16_emulated);

struct FloatWrapper { float f; };
static bool operator==(FloatWrapper w1, FloatWrapper w2)
{
    return memcmp(&w1.f, &w2.f, sizeof(w1.f)) == 0;
}

static std::ostream &operator<<(std::ostream &s, FloatWrapper w)
{
    uint32_t n, u;
    memcpy(&u, &w.f, sizeof(u));
    auto f = s.flags();
    s << std::hex << std::setfill('0') << std::setw(8) << u;
    s.flags(f);

    if (isnanf(w.f)) {
        // for NaN, we need to get the detail bits
        float qnan = std::numeric_limits<float>::infinity();
        memcpy(&n, &qnan, sizeof(n));
        u &= ~n;

        s << " nan(0x" << std::hex << u << std::dec << ')';
    } else {
        s << ' ' << std::hexfloat << w.f << std::defaultfloat
          << " (" << w.f << ')';
    }

    s.flags(f);     // restore flags
    return s;
}

template <typename ConversionSet> static
testing::AssertionResult conversions(const char *exp1, const char *exp2, const char *exp3,
                                     float orig, uint16_t f16, float back)
{
    std::stringstream ss;
    auto converted = ConversionSet::fromfloat(orig);
    if (converted.payload == f16) {
        // convert back
        float unconverted = ConversionSet::tofloat(converted);
        if (memcmp(&unconverted, &back, sizeof(float)) == 0)
            return testing::AssertionSuccess();

        ss << "Conversion from " << ConversionSet::Traits::name()
           << " to float using " << ConversionSet::tofloat_name() << "() failed\n";
        ss << "  Source (\"" << exp2 << "\"): 0x" << std::hex << f16 << "\n";
        ss << "  Actual: " << FloatWrapper{unconverted} << '\n';
        ss << "  Expected (\"" << exp3 <<  "\"): " << FloatWrapper{back} << '\n';
    } else {
        ss << "Conversion from float to " << ConversionSet::Traits::name()
           << " using " << ConversionSet::fromfloat_name() << "() failed\n";
        ss << "  Source (\"" << exp1 << "\"): " << FloatWrapper{orig} << '\n';
        ss << "  Actual: 0x" << std::hex << converted.payload << "\n";
        ss << "  Expected (\"" << exp2 <<  "\"): 0x" << f16 << "\n";
    }

    return testing::AssertionFailure() << ss.str();
}

#define fp16_check_full(Float, FP16, Float2)                                    \
    __extension__({                                                             \
        EXPECT_PRED_FORMAT3(conversions<FP16Emulated>, Float, FP16, Float2);    \
        if (UseF16C) { EXPECT_PRED_FORMAT3(conversions<FP16_F16C>, Float, FP16, Float2); } \
    })
#define fp16_check(Float, FP16)  fp16_check_full(Float, FP16, Float)

TEST(Float16, FiniteConversions)
{
    // normals
    fp16_check(0, 0x0000);
    fp16_check(1, 0x3c00);
    fp16_check(-1, 0xbc00);
    fp16_check(2, 0x4000);
    fp16_check_full(1.2, 0x3ccc, 0x9.98p-3);
    fp16_check_full(M_PI, 0x4248, 0xc.90p-2);

    // to denormal
    fp16_check(0x1p-15, 0x0200);

    // underflow and overflow
    fp16_check_full(0x1p16, Float16::max().payload, FLOAT16_MAX);
    fp16_check_full(0x1p-25, 0x0000, 0);

    // check constants
    fp16_check(FLOAT16_MAX, Float16::max().payload);
    fp16_check(FLOAT16_MIN, Float16::min().payload);
    fp16_check(-FLOAT16_MAX, Float16::lowest().payload);
    fp16_check(FLOAT16_DENORM_MIN, Float16::denorm_min().payload);
    fp16_check(FLOAT16_EPSILON, Float16::epsilon().payload);
    fp16_check(std::numeric_limits<float>::round_error(), Float16::round_error().payload);
}

TEST(Float16, InfiniteCoversions)
{
    fp16_check(std::numeric_limits<float>::infinity(), Float16::infinity().payload);
    fp16_check(-std::numeric_limits<float>::infinity(), Float16::neg_infinity().payload);
}

TEST(Float16, NaNConversions)
{
    // QNaN should remain as-is
    fp16_check(std::numeric_limits<float>::quiet_NaN(), Float16::quiet_NaN().payload);

    // x86 converts SNaN to QNaN
    FloatWrapper quieted_snan = { __builtin_nanf("0x200000") };
    fp16_check_full(std::numeric_limits<float>::signaling_NaN(),
                    Float16::quiet_NaN().payload | Float16::signaling_NaN().payload,
                    quieted_snan.f);

    EXPECT_EQ(FloatWrapper{fromfp16_emulated(Float16::signaling_NaN())}, quieted_snan);
    if (UseF16C) {
        EXPECT_EQ(FloatWrapper{fromfp16(Float16::signaling_NaN())}, quieted_snan);
    }
}

#define bf16_check_full(Float, FP16, Float2)                                    \
    __extension__({                                                             \
        EXPECT_PRED_FORMAT3(conversions<BF16Emulated>, Float, FP16, Float2);    \
        if (useAvx512Bf16()) { EXPECT_PRED_FORMAT3(conversions<BF16_AVX512>, Float, FP16, Float2); } \
    })
#define bf16_check(Float, FP16)  bf16_check_full(Float, FP16, Float)

TEST(BFloat16, FiniteConversions)
{
    // normals
    bf16_check(0, 0x0000);
    bf16_check(1, 0x3f80);
    bf16_check(-1, 0xbf80);
    bf16_check(2, 0x4000);

    // inexact
    bf16_check_full(1.2, 0x3f9a, 0x1.34p0);
    bf16_check_full(M_PI, 0x4049, 0xc.90p-2);

    // to denormal
    // ### FIXME
    //bf16_check(BFLT16_DENORM_MIN, 0x0001);

    // overflow
    bf16_check_full(FLT_MAX, BFloat16::infinity().payload, std::numeric_limits<float>::infinity());

    // check constants
    bf16_check(BFLOAT16_MAX, BFloat16::max().payload);
    bf16_check(BFLOAT16_MIN, BFloat16::min().payload);
    bf16_check(-BFLOAT16_MAX, BFloat16::lowest().payload);
    //bf16_check(BFLT16_DENORM_MIN, BFloat16::denorm_min().payload);
    bf16_check(BFLOAT16_EPSILON, BFloat16::epsilon().payload);
    bf16_check(std::numeric_limits<float>::round_error(), BFloat16::round_error().payload);
}

TEST(BFloat16, InfiniteCoversions)
{
    bf16_check(std::numeric_limits<float>::infinity(), BFloat16::infinity().payload);
    bf16_check(-std::numeric_limits<float>::infinity(), BFloat16::neg_infinity().payload);
}

TEST(BFloat16, NaNConversions)
{
    // QNaN should remain as-is
    bf16_check(std::numeric_limits<float>::quiet_NaN(), BFloat16::quiet_NaN().payload);

    // x86 converts SNaN to QNaN
    FloatWrapper quieted_snan = { __builtin_nanf("0x200000") };
    bf16_check_full(std::numeric_limits<float>::signaling_NaN(),
                    BFloat16::quiet_NaN().payload | BFloat16::signaling_NaN().payload,
                    quieted_snan.f);

    EXPECT_EQ(FloatWrapper{frombf16_emulated(BFloat16::signaling_NaN())}, quieted_snan);
}
