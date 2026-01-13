/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <vector>
#include "gtest/gtest.h"
#include "sandstone_chrono.h"
#include "sandstone_data.h"
#include "sandstone_utils.h"

#include <limits.h>
#include <locale.h>
#include <inttypes.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#include <immintrin.h>
#pragma GCC diagnostic pop

#ifndef __F16C__
#  error "Please compile with F16C support"
#endif

using namespace std;

TEST(SimpleStringUtils, GivenEmptyString_WhenConvertedToMilisecs_ThenReturnZero) {
    vector<pair<string, int>> test_vectors = {
            {"",    0},
            {"1",   1},
            {"1s",  1000},
            {"1m",  60 * 1000},
            {"1h",  60 * 60 * 1000},
            {"2h",  2 * 60 * 60 * 1000},
            {"2ms", 2},
    };

    for (auto &p : test_vectors) {
        ASSERT_EQ(string_to_millisecs(p.first).count(), p.second);
    }

}

TEST(PrintfToStdString, Integers)
{
    ASSERT_EQ(stdprintf("%d", 1), "1");
    ASSERT_EQ(stdprintf("%d", -1), "-1");
    ASSERT_EQ(stdprintf("%d", INT_MAX), "2147483647");
    ASSERT_EQ(stdprintf("%d", INT_MIN), "-2147483648");
    ASSERT_EQ(stdprintf("%u", 1), "1");
    ASSERT_EQ(stdprintf("%u", UINT_MAX), "4294967295");
    ASSERT_EQ(stdprintf("%lu", (unsigned long)UINT_MAX), "4294967295");
    ASSERT_EQ(stdprintf("%" PRId64, INT64_MAX), "9223372036854775807");
    ASSERT_EQ(stdprintf("%" PRIu64, (uint64_t)INT64_MAX), "9223372036854775807");
    ASSERT_EQ(stdprintf("%" PRIu64, UINT64_MAX), "18446744073709551615");
    ASSERT_EQ(stdprintf("%#" PRIx64, UINT64_MAX), "0xffffffffffffffff");
}

TEST(PrintfToStdString, FloatingPoint)
{
    setlocale(LC_ALL, "C");     // ensure C locale, so we get periods as decimal separators
    ASSERT_EQ(stdprintf("%a", 0.), "0x0p+0");
    ASSERT_EQ(stdprintf("%e", 0.), "0.000000e+00");
    ASSERT_EQ(stdprintf("%f", 0.), "0.000000");
    ASSERT_EQ(stdprintf("%g", 0.), "0");
}

TEST(PrintfToStdString, String)
{
    for (const char *str : {"", "Hello", "Hello World, this is is a message bigger than 8 chars"}) {
        ASSERT_EQ(stdprintf("%s", str), std::string(str));
    }
}

namespace {
template <typename T> struct my_numeric_limits : std::numeric_limits<T> {};
template <> struct my_numeric_limits<Float16> : Float16 {};
template <> struct my_numeric_limits<BFloat16> : BFloat16 {};
}

template <typename T> static std::string format_type_helper(T v)
{
    using namespace SandstoneDataDetails;
    DataType type = TypeToDataType<T>::Type;
    return format_single_type(type, type_real_size(type),
                              reinterpret_cast<const uint8_t *>(&v), true);
}

TEST(DataCompare, UInt8)
{
    using namespace SandstoneDataDetails;
    EXPECT_STREQ(type_name(UInt8Data), "uint8_t");
    EXPECT_EQ(format_type_helper(uint8_t(0)), "00 (0)");
    EXPECT_EQ(format_type_helper(uint8_t(0x80)), "80 (128)");
    EXPECT_EQ(format_type_helper(uint8_t(0xFF)), "ff (255)");
}

TEST(DataCompare, Int8)
{
    using namespace SandstoneDataDetails;
    EXPECT_STREQ(type_name(Int8Data), "int8_t");
    EXPECT_EQ(format_type_helper(int8_t(0)), "00 (0)");
    EXPECT_EQ(format_type_helper(int8_t(0x80)), "80 (-128)");
    EXPECT_EQ(format_type_helper(int8_t(0xFF)), "ff (-1)");
}

TEST(DataCompare, UInt16)
{
    using namespace SandstoneDataDetails;
    EXPECT_STREQ(type_name(UInt16Data), "uint16_t");
    EXPECT_EQ(format_type_helper(uint16_t(0)), "0000 (0)");
    EXPECT_EQ(format_type_helper(uint16_t(0x1234)), "1234");
    EXPECT_EQ(format_type_helper(uint16_t(0xFFFF)), "ffff");
}

TEST(DataCompare, Int16)
{
    using namespace SandstoneDataDetails;
    EXPECT_STREQ(type_name(Int16Data), "int16_t");
    EXPECT_EQ(format_type_helper(int16_t(0)), "0000 (0)");
    EXPECT_EQ(format_type_helper(int16_t(0x1234)), "1234");
    EXPECT_EQ(format_type_helper(int16_t(0xFFFF)), "ffff (-1)");
}

TEST(DataCompare, UInt32)
{
    using namespace SandstoneDataDetails;
    EXPECT_STREQ(type_name(UInt32Data), "uint32_t");
    EXPECT_EQ(format_type_helper(uint32_t(0)), "00000000 (0)");
    EXPECT_EQ(format_type_helper(uint32_t(0x12345678)), "12345678");
    EXPECT_EQ(format_type_helper(uint32_t(0xFFFFFFFF)), "ffffffff");
}

TEST(DataCompare, Int32)
{
    using namespace SandstoneDataDetails;
    EXPECT_STREQ(type_name(Int32Data), "int32_t");
    EXPECT_EQ(format_type_helper(int32_t(0)), "00000000 (0)");
    EXPECT_EQ(format_type_helper(int32_t(0x12345678)), "12345678");
    EXPECT_EQ(format_type_helper(int32_t(0xFFFFFFFF)), "ffffffff (-1)");
}

TEST(DataCompare, UInt64)
{
    using namespace SandstoneDataDetails;
    EXPECT_STREQ(type_name(UInt64Data), "uint64_t");
    EXPECT_EQ(format_type_helper(uint64_t(0)), "0000000000000000 (0)");
    EXPECT_EQ(format_type_helper(UINT64_C(0x123456789abcdef0)), "123456789abcdef0");
    EXPECT_EQ(format_type_helper(UINT64_C(0xFFFFFFFFFFFFFFFF)), "ffffffffffffffff");
}

TEST(DataCompare, Int64)
{
    using namespace SandstoneDataDetails;
    EXPECT_STREQ(type_name(Int64Data), "int64_t");
    EXPECT_EQ(format_type_helper(int64_t(0)), "0000000000000000 (0)");
    EXPECT_EQ(format_type_helper(INT64_C(0x123456789abcdef0)), "123456789abcdef0");
    EXPECT_EQ(format_type_helper(INT64_C(-1)), "ffffffffffffffff (-1)");
}

TEST(DataCompare, UInt128)
{
    using namespace SandstoneDataDetails;
    EXPECT_STREQ(type_name(UInt128Data), "uint128_t");
    EXPECT_EQ(format_type_helper(__uint128_t(0)), "00000000000000000000000000000000 (0)");
    __uint128_t x = UINT64_C(0x123456789abcdef0);
    x <<= 64;
    x |= ~uint64_t(0);
    EXPECT_EQ(format_type_helper(x), "123456789abcdef0ffffffffffffffff");
    EXPECT_EQ(format_type_helper(~__uint128_t(0)), "ffffffffffffffffffffffffffffffff");
}

TEST(DataCompare, Int128)
{
    using namespace SandstoneDataDetails;
    EXPECT_STREQ(type_name(Int128Data), "int128_t");
    EXPECT_EQ(format_type_helper(__int128_t(0)), "00000000000000000000000000000000 (0)");
    __int128_t x = UINT64_C(0x123456789abcdef0);
    x <<= 64;
    x |= ~uint64_t(0);
    EXPECT_EQ(format_type_helper(x), "123456789abcdef0ffffffffffffffff");
    EXPECT_EQ(format_type_helper(__int128_t(-1)), "ffffffffffffffffffffffffffffffff (-1)");
}

TEST(DataCompare, Float128)
{
    using namespace SandstoneDataDetails;
    setlocale(LC_ALL, "C");     // ensure C locale, so we get periods as decimal separators
    EXPECT_STREQ(type_name(Float128Data), "_Float128");
    EXPECT_EQ(format_type_helper(__float128(0.)), "00000000000000000000000000000000");
    EXPECT_EQ(format_type_helper(__float128(-1.)), "bfff0000000000000000000000000000");
    EXPECT_EQ(format_type_helper(Float128::max()), "7ffeffffffffffffffffffffffffffff");
    EXPECT_EQ(format_type_helper(Float128::min()), "00010000000000000000000000000000");
    EXPECT_EQ(format_type_helper(Float128::denorm_min()), "00000000000000000000000000000001");
    EXPECT_EQ(format_type_helper(Float128::epsilon()), "3f8f0000000000000000000000000000");
    EXPECT_EQ(format_type_helper(1 + Float128::epsilon()), "3fff0000000000000000000000000001");
    EXPECT_EQ(format_type_helper(Float128::infinity()), "7fff0000000000000000000000000000");
    EXPECT_EQ(format_type_helper(-Float128::infinity()), "ffff0000000000000000000000000000");
    EXPECT_EQ(format_type_helper(Float128::quiet_NaN()), "7fff8000000000000000000000000000");
    EXPECT_EQ(format_type_helper(Float128::signaling_NaN()), "7fff4000000000000000000000000000");
}

TEST(DataCompare, Float80)
{
    using namespace SandstoneDataDetails;
    setlocale(LC_ALL, "C");     // ensure C locale, so we get periods as decimal separators
    EXPECT_STREQ(type_name(Float80Data), "_Float64x");
    EXPECT_EQ(format_type_helper(0.L), "00000000000000000000 (0x0p+0)");
    EXPECT_EQ(format_type_helper(-1.L), "bfff8000000000000000 (-0x8p-3)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<long double>::max()), "7ffeffffffffffffffff (0xf.fffffffffffffffp+16380)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<long double>::min()), "00018000000000000000 (0x8p-16385)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<long double>::denorm_min()), "00000000000000000001 (0x0.000000000000001p-16385)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<long double>::epsilon()), "3fc08000000000000000 (0x8p-66)");
    EXPECT_EQ(format_type_helper(1 + std::numeric_limits<long double>::epsilon()), "3fff8000000000000001 (0x8.000000000000001p-3)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<long double>::infinity()), "7fff8000000000000000 (inf)");
    EXPECT_EQ(format_type_helper(-std::numeric_limits<long double>::infinity()), "ffff8000000000000000 (-inf)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<long double>::quiet_NaN()), "7fffc000000000000000 (nan)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<long double>::signaling_NaN()), "7fffa000000000000000 (nan)");
}

TEST(DataCompare, Float64)
{
    using namespace SandstoneDataDetails;
    setlocale(LC_ALL, "C");     // ensure C locale, so we get periods as decimal separators
    EXPECT_STREQ(type_name(Float64Data), "double");
    EXPECT_EQ(format_type_helper(0.0), "0000000000000000 (0x0p+0)");
    EXPECT_EQ(format_type_helper(-1.0), "bff0000000000000 (-0x1p+0)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<double>::max()), "7fefffffffffffff (0x1.fffffffffffffp+1023)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<double>::min()), "0010000000000000 (0x1p-1022)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<double>::denorm_min()), "0000000000000001 (0x0.0000000000001p-1022)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<double>::epsilon()), "3cb0000000000000 (0x1p-52)");
    EXPECT_EQ(format_type_helper(1 + std::numeric_limits<double>::epsilon()), "3ff0000000000001 (0x1.0000000000001p+0)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<double>::infinity()), "7ff0000000000000 (inf)");
    EXPECT_EQ(format_type_helper(-std::numeric_limits<double>::infinity()), "fff0000000000000 (-inf)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<double>::quiet_NaN()), "7ff8000000000000 (nan)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<double>::signaling_NaN()), "7ff4000000000000 (nan)");
}

TEST(DataCompare, Float32)
{
    using namespace SandstoneDataDetails;
    setlocale(LC_ALL, "C");     // ensure C locale, so we get periods as decimal separators
    EXPECT_STREQ(type_name(Float32Data), "float");
    EXPECT_EQ(format_type_helper(0.f), "00000000 (0x0p+0)");
    EXPECT_EQ(format_type_helper(-1.f), "bf800000 (-0x1p+0)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<float>::max()), "7f7fffff (0x1.fffffep+127)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<float>::min()), "00800000 (0x1p-126)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<float>::denorm_min()), "00000001 (0x1p-149)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<float>::epsilon()), "34000000 (0x1p-23)");
    EXPECT_EQ(format_type_helper(1 + std::numeric_limits<float>::epsilon()), "3f800001 (0x1.000002p+0)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<float>::infinity()), "7f800000 (inf)");
    EXPECT_EQ(format_type_helper(-std::numeric_limits<float>::infinity()), "ff800000 (-inf)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<float>::quiet_NaN()), "7fc00000 (nan)");
    EXPECT_EQ(format_type_helper(std::numeric_limits<float>::signaling_NaN()), "7fa00000 (nan)");
}

TEST(DataCompare, BFloat16)
{
    using namespace SandstoneDataDetails;
    setlocale(LC_ALL, "C");     // ensure C locale, so we get periods as decimal separators
    EXPECT_STREQ(type_name(BFloat16Data), "_BFloat16");
    EXPECT_EQ(format_type_helper(BFloat16(0)), "0000 (0x0p+0)");
    EXPECT_EQ(format_type_helper(BFloat16(-1)), "bf80 (-0x1p+0)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<BFloat16>::max()), "7f7f (0x1.fep+127)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<BFloat16>::min()), "0080 (0x1p-126)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<BFloat16>::denorm_min()), "0001 (0x1p-133)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<BFloat16>::epsilon()), "3c00 (0x1p-7)");
    EXPECT_EQ(format_type_helper(BFloat16(1 + BFLOAT16_EPSILON)), "3f81 (0x1.02p+0)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<BFloat16>::infinity()), "7f80 (inf)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<BFloat16>::neg_infinity()), "ff80 (-inf)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<BFloat16>::quiet_NaN()), "7fc0 (nan)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<BFloat16>::signaling_NaN()), "7fa0 (nan)");
}

TEST(DataCompare, Float16)
{
    using namespace SandstoneDataDetails;
    setlocale(LC_ALL, "C");     // ensure C locale, so we get periods as decimal separators
    EXPECT_STREQ(type_name(Float16Data), "_Float16");
    EXPECT_EQ(format_type_helper(Float16(0)), "0000 (0x0p+0)");
    EXPECT_EQ(format_type_helper(Float16(-1)), "bc00 (-0x1p+0)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<Float16>::max()), "7bff (0x1.ffcp+15)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<Float16>::min()), "0400 (0x1p-14)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<Float16>::denorm_min()), "0001 (0x1p-24)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<Float16>::epsilon()), "1400 (0x1p-10)");
    EXPECT_EQ(format_type_helper(Float16(1 + FLOAT16_EPSILON)), "3c01 (0x1.004p+0)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<Float16>::infinity()), "7c00 (inf)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<Float16>::neg_infinity()), "fc00 (-inf)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<Float16>::quiet_NaN()), "7e00 (nan)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<Float16>::signaling_NaN()), "7d00 (nan)");
}

namespace {
template <> struct my_numeric_limits<BFloat8> : public BFloat8 {
    static constexpr BFloat8 neg_infinity()  { return -infinity(); }
    static constexpr BFloat8 denorm_min()    { return BFloat8(0, BFLOAT8_DENORM_EXPONENT, 1); }
    static constexpr BFloat8 overflow()      { return BFloat8(0, BFLOAT8_INFINITY_EXPONENT, BFLOAT8_OVERFLOW_MANTISSA); }
    static constexpr BFloat8 quiet_NaN()     { return BFloat8(0, BFLOAT8_NAN_EXPONENT, BFLOAT8_QNAN_AT_INPUT_MANTISSA); }
    static constexpr BFloat8 signaling_NaN() { return BFloat8(0, BFLOAT8_NAN_EXPONENT, BFLOAT8_SNAN_AT_INPUT_MANTISSA); }
};
}

TEST(DataCompare, BFloat8)
{
    using namespace SandstoneDataDetails;
    setlocale(LC_ALL, "C");     // ensure C locale, so we get periods as decimal separators
    EXPECT_STREQ(type_name(BFloat8Data), "BFloat8");
    EXPECT_EQ(type_real_size(BFloat8Data), 1);
    EXPECT_EQ(type_size(BFloat8Data), 1);

    EXPECT_EQ(format_type_helper(BFloat8(0)), "00 (0)");
    EXPECT_EQ(format_type_helper(BFloat8(-1)), "bc (-1)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<BFloat8>::max()), "7b (57344)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<BFloat8>::min()), "04 (6.10352e-05)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<BFloat8>::denorm_min()), "01 (1.52588e-05)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<BFloat8>::infinity()), "7c (inf)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<BFloat8>::neg_infinity()), "fc (-inf)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<BFloat8>::overflow()), "7d (inf)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<BFloat8>::signaling_NaN()), "7e (nan)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<BFloat8>::quiet_NaN()), "7f (nan)");
}

namespace {
template <> struct my_numeric_limits<HFloat8> : HFloat8 {
    static constexpr HFloat8 infinity()      { return inf_nan(); }
    static constexpr HFloat8 neg_infinity()  { return -inf_nan(); }
    static constexpr HFloat8 denorm_min()    { return HFloat8(0, HFLOAT8_DENORM_EXPONENT, 1); }
    static constexpr HFloat8 overflow()      { return HFloat8(0, HFLOAT8_SATURATED_OVERFLOW_VALUE); }
};
}

TEST(DataCompare, HFloat8)
{
    using namespace SandstoneDataDetails;
    setlocale(LC_ALL, "C");     // ensure C locale, so we get periods as decimal separators
    EXPECT_STREQ(type_name(HFloat8Data), "HFloat8");
    EXPECT_EQ(type_real_size(HFloat8Data), 1);
    EXPECT_EQ(type_size(HFloat8Data), 1);

    EXPECT_EQ(format_type_helper(HFloat8(0)), "00 (0)");
    EXPECT_EQ(format_type_helper(HFloat8(-1)), "b8 (-1)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<HFloat8>::max()), "7d (416)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<HFloat8>::min()), "08 (0.015625)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<HFloat8>::denorm_min()), "01 (0.00195312)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<HFloat8>::overflow()), "7e (inf)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<HFloat8>::infinity()), "7f (inf)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<HFloat8>::neg_infinity()), "ff (-inf)");
    // no NaN values, these are treated as infinity
}

// dummy mocks to allow new_random_xxx() compilation
__attribute__((weak)) uint32_t random32() {
    return random();
}

// test conversion f32 -> bf8 (s.eeeee.mm)
TEST(FloatConversions, BF8fromFloat)
{
    // small float value
    static constexpr float DELTA = 1.0e-6f;
    /// smallest "normal" value
    static constexpr float MIN = 1.0f / ((float) (1 << (BFLOAT8_EXPONENT_BIAS - 1)));
    // lets prevent rounding with MIN/32 by subtracting small value
    static constexpr float FTZ = MIN / 32.0f - DELTA;

    static constexpr uint8_t NEGATIVE = 0x80;
    static constexpr uint8_t ZERO = 0x00;

    EXPECT_EQ(ZERO,            to_bfloat8(0.0f).as_hex);
    EXPECT_EQ(NEGATIVE | ZERO, to_bfloat8(-0.0f).as_hex);
    EXPECT_EQ(NEGATIVE | ZERO, (-to_bfloat8(0.0f)).as_hex);
    EXPECT_EQ(ZERO,            to_bfloat8(FTZ).as_hex);


    // infinite/nan
    EXPECT_EQ(BFLOAT8_OVERFLOW_MANTISSA,      to_bfloat8((float) (1LL << (BFLOAT8_INFINITY_EXPONENT + 1))).mantissa);
    EXPECT_EQ(BFLOAT8_INF_AT_INPUT_MANTISSA,  to_bfloat8(Float32{0, FLOAT32_INFINITY_EXPONENT, 0}.as_float).mantissa);
    EXPECT_EQ(BFLOAT8_SNAN_AT_INPUT_MANTISSA, to_bfloat8(Float32{0, FLOAT32_NAN_EXPONENT, 1}.as_float).mantissa);
    EXPECT_EQ(BFLOAT8_QNAN_AT_INPUT_MANTISSA, to_bfloat8(Float32{0, FLOAT32_NAN_EXPONENT, 1 | FLOAT32_MANTISSA_QUIET_NAN_MASK}.as_float).mantissa);

    static constexpr uint8_t ONE = 0b0'01111'00;
    static constexpr uint8_t TWO = 0b0'10000'00;

    EXPECT_EQ(ONE,            to_bfloat8(1.0f).as_hex);
    EXPECT_EQ(NEGATIVE | ONE, to_bfloat8(-1.0f).as_hex);
    EXPECT_EQ(ONE,            (-to_bfloat8(-1.0f)).as_hex);
    EXPECT_EQ(TWO,            to_bfloat8(2.0f).as_hex);

    EXPECT_EQ(TWO, to_bfloat8(2.0 - DELTA).as_hex);
    EXPECT_EQ(TWO, to_bfloat8(2.0 + DELTA).as_hex);

    EXPECT_EQ(0b0'01111'10, to_bfloat8(1.0f + 1.0f / 2.0f).as_hex);
    EXPECT_EQ(0b0'01111'11, to_bfloat8(1.0f + 1.0f / 2.0f + 1.0f / 4.0f).as_hex);
    EXPECT_EQ(0b0'01111'11, to_bfloat8(1.0f + 1.0f / 2.0f + 1.0f / 4.0f).as_hex);
    EXPECT_EQ(0b0'01111'11, to_bfloat8(1.0f + 1.0f / 2.0f + 1.0f / 8.0f).as_hex); // rounded up
    EXPECT_EQ(0b0'01111'11, to_bfloat8(1.0f + 1.0f / 2.0f + 1.0f / 4.0f + 1.0f / 16.0f).as_hex); // rounded down
    EXPECT_EQ(TWO,          to_bfloat8(1.0f + 1.0f / 2.0f + 1.0f / 4.0f + 1.0f / 8.0f).as_hex); // rounded up

    // denormals
    EXPECT_EQ(0b0'00001'00, to_bfloat8(MIN).as_hex);
    EXPECT_EQ(0b0'00000'10, to_bfloat8(MIN / 2.0f).as_hex);
    EXPECT_EQ(0b0'00000'01, to_bfloat8(MIN / 4.0f).as_hex);
    EXPECT_EQ(0b0'00000'01, to_bfloat8(MIN / 8.0f).as_hex); // rounded up
    EXPECT_EQ(0b0'00000'00, to_bfloat8(MIN / 16.0f).as_hex); // ftz

    // rounding with denormals
    EXPECT_EQ(0b0'00000'11, to_bfloat8(MIN / 2.0f + MIN / 4.0f).as_hex);
    EXPECT_EQ(0b0'00000'10, to_bfloat8(MIN / 4.0f + MIN / 8.0f).as_hex); // round up, MIN/2
    EXPECT_EQ(0b0'00000'11, to_bfloat8(MIN / 2.0f + MIN / 8.0f).as_hex); // round up, MIN/2+MIN/4

    EXPECT_EQ(0b0'00000'11, to_bfloat8(MIN - MIN / 8.0f - MIN / 16.0f).as_hex); // round down, denormal
    EXPECT_EQ(0b0'00001'00, to_bfloat8(MIN - MIN / 8.0f + MIN / 16.0f).as_hex); // round up, MIN

    EXPECT_EQ(0b0'00000'01, to_bfloat8(MIN / 4.0f + MIN / 16.0f).as_hex); // no round up
    EXPECT_EQ(0b0'00000'10, to_bfloat8(MIN / 2.0f + MIN / 16.0f).as_hex); // no round up

    static constexpr uint32_t F8_INF_BIAS = FLOAT32_EXPONENT_BIAS + BFLOAT8_INFINITY_EXPONENT - BFLOAT8_EXPONENT_BIAS;
    EXPECT_EQ(BFLOAT8_OVERFLOW_MANTISSA, to_bfloat8(Float32{0, F8_INF_BIAS, 0x000000}.as_float).mantissa);
}

TEST(FloatConversions, BF8FtoFloat) {
    /// smallest "normal" value
    static constexpr float MIN = 1.0f / ((float) (1 << (BFLOAT8_EXPONENT_BIAS - 1)));
    // do not round up the value
    static constexpr float FTZ = MIN / 8.0f - MIN / 128.0f;

    static constexpr Float32 F32INF{ 0, FLOAT32_INFINITY_EXPONENT, 0 };

    EXPECT_EQ(0.0f, from_bfloat8(to_bfloat8(0.0f)));
    EXPECT_EQ(1.0f, from_bfloat8(to_bfloat8(1.0f)));
    EXPECT_EQ(MIN,  from_bfloat8(BFloat8::min()));
    EXPECT_EQ(0.0f, from_bfloat8(to_bfloat8(FTZ)));

    // denormals
    EXPECT_EQ(MIN / 2.0f,              from_bfloat8(BFloat8{ 0, BFLOAT8_DENORM_EXPONENT, 0b10 }));
    EXPECT_EQ(MIN / 4.0f,              from_bfloat8(BFloat8{ 0, BFLOAT8_DENORM_EXPONENT, 0b01 }));
    EXPECT_EQ(MIN / 2.0f + MIN / 4.0f, from_bfloat8(BFloat8{ 0, BFLOAT8_DENORM_EXPONENT, 0b11 }));

    EXPECT_EQ(MIN / 2.0f,              from_bfloat8(to_bfloat8(MIN / 2.0f)));
    EXPECT_EQ(MIN / 4.0f,              from_bfloat8(to_bfloat8(MIN / 4.0f)));
    EXPECT_EQ(MIN / 4.0f,              from_bfloat8(to_bfloat8(MIN / 8.0f))); // rounded

    EXPECT_EQ(MIN / 2.0f + MIN / 4.0f, from_bfloat8(to_bfloat8(MIN / 2.0f + MIN / 4.0f)));
    EXPECT_EQ(MIN / 2.0f + MIN / 4.0f, from_bfloat8(to_bfloat8(MIN / 2.0f              + MIN / 8.0f))); // round up
    EXPECT_EQ(MIN / 2.0f + MIN / 4.0f, from_bfloat8(to_bfloat8(MIN / 2.0f + MIN / 4.0f - MIN / 8.0f))); // round up
    EXPECT_EQ(MIN,                     from_bfloat8(to_bfloat8(MIN / 2.0f + MIN / 4.0f + MIN / 8.0f))); // round up to normal value
    EXPECT_EQ(MIN / 2.0f + MIN / 4.0f, from_bfloat8(to_bfloat8(MIN / 2.0f + MIN / 4.0f + MIN / 16.0f))); // round down

    static float MAX = from_bfloat8(BFloat8::max());
    EXPECT_EQ(57344.0f, MAX);
    static float MAXBIT = from_bfloat8(BFloat8::max()) / 7.0f;
    EXPECT_EQ(8192.0f, MAXBIT);
    EXPECT_EQ(MAXBIT,          from_bfloat8(to_bfloat8(MAXBIT)));
    EXPECT_EQ(2.0f * MAXBIT,   from_bfloat8(to_bfloat8(2.0f * MAXBIT)));
    EXPECT_EQ(7.0f * MAXBIT,   from_bfloat8(to_bfloat8(7.0f * MAXBIT)));
    EXPECT_EQ(7.0f * MAXBIT,   from_bfloat8(to_bfloat8(7.0f * MAXBIT + 4095.0f))); // still rounded down
    EXPECT_EQ(F32INF.as_float, from_bfloat8(to_bfloat8(7.0f * MAXBIT + 4096.0f))); // round up
    EXPECT_EQ(F32INF.as_float, from_bfloat8(to_bfloat8(8.0f * MAXBIT)));
    EXPECT_EQ(F32INF.as_float, from_bfloat8(to_bfloat8(8.0f * MAXBIT - 4096.0f))); // round up
}

// test conversion f32 -> hf8 (s.eeee.mmm)
TEST(FloatConversions, HF8fromFloat) {
    // small float value
    static constexpr float DELTA = 1.0e-6f;
    /// smallest "normal" value
    static constexpr float MIN = 1.0f / ((float) (1 << (HFLOAT8_EXPONENT_BIAS - 1)));
    // lets prevent rounding with MIN/16 by subtracting small value
    static constexpr float FTZ = MIN / 16.0f - DELTA;

    static constexpr uint8_t NEGATIVE = 0x80;
    static constexpr uint8_t ZERO = 0x00;

    EXPECT_EQ(ZERO,            to_hfloat8(0.0f).as_hex);
    EXPECT_EQ(NEGATIVE | ZERO, to_hfloat8(-0.0f).as_hex);
    EXPECT_EQ(NEGATIVE | ZERO, (-to_hfloat8(0.0f)).as_hex);
    EXPECT_EQ(ZERO,            to_hfloat8(FTZ).as_hex);


    // infinite/nan, saturated/overflow
    EXPECT_EQ(HFLOAT8_SATURATED_OVERFLOW_VALUE, to_hfloat8((float) (1 << (HFLOAT8_INF_NAN_EXPONENT + 1))).value);
    EXPECT_EQ(HFLOAT8_INF_NAN_VALUE,            to_hfloat8(Float32{0, FLOAT32_INFINITY_EXPONENT, 0}.as_float).value);
    EXPECT_EQ(HFLOAT8_INF_NAN_VALUE,            to_hfloat8(Float32{0, FLOAT32_NAN_EXPONENT, 1}.as_float).value);

    EXPECT_EQ(HFLOAT8_SATURATED_OVERFLOW_VALUE, (-to_hfloat8((float) (1 << (HFLOAT8_INF_NAN_EXPONENT + 1)))).value);
    EXPECT_EQ(HFLOAT8_INF_NAN_VALUE,            (-to_hfloat8(Float32{0, FLOAT32_INFINITY_EXPONENT, 0}.as_float)).value);
    EXPECT_EQ(HFLOAT8_INF_NAN_VALUE,            (-to_hfloat8(Float32{0, FLOAT32_NAN_EXPONENT, 1}.as_float)).value);

    static constexpr uint8_t ONE = 0b0'0111'000;
    static constexpr uint8_t TWO = 0b0'1000'000;

    EXPECT_EQ(ONE,            to_hfloat8(1.0f).as_hex);
    EXPECT_EQ(NEGATIVE | ONE, to_hfloat8(-1.0f).as_hex);
    EXPECT_EQ(ONE,            (-to_hfloat8(-1.0f)).as_hex);
    EXPECT_EQ(TWO,            to_hfloat8(2.0f).as_hex);

    EXPECT_EQ(TWO, to_hfloat8(2.0 - DELTA).as_hex);
    EXPECT_EQ(TWO, to_hfloat8(2.0 + DELTA).as_hex);

    EXPECT_EQ(0b0'0111'100, to_hfloat8(1.0f + 1.0f / 2.0f).as_hex);
    EXPECT_EQ(0b0'0111'110, to_hfloat8(1.0f + 1.0f / 2.0f + 1.0f / 4.0f).as_hex);
    EXPECT_EQ(0b0'0111'101, to_hfloat8(1.0f + 1.0f / 2.0f + 1.0f / 8.0f).as_hex);
    EXPECT_EQ(0b0'0111'111, to_hfloat8(1.0f + 1.0f / 2.0f + 1.0f / 4.0f + 1.0f / 8.0f).as_hex);
    EXPECT_EQ(0b0'0111'111, to_hfloat8(1.0f + 1.0f / 2.0f + 1.0f / 4.0f + 1.0f / 8.0f + 1.0f / 32.0f).as_hex); // rounded down
    EXPECT_EQ(TWO,          to_hfloat8(1.0f + 1.0f / 2.0f + 1.0f / 4.0f + 1.0f / 8.0f + 1.0f / 16.0f).as_hex); // rounded up

    // denormals
    EXPECT_EQ(0b0'0001'000, to_hfloat8(MIN).as_hex);
    EXPECT_EQ(0b0'0000'100, to_hfloat8(MIN / 2.0f).as_hex);
    EXPECT_EQ(0b0'0000'010, to_hfloat8(MIN / 4.0f).as_hex);
    EXPECT_EQ(0b0'0000'001, to_hfloat8(MIN / 8.0f).as_hex);
    EXPECT_EQ(0b0'0000'001, to_hfloat8(MIN / 16.0f).as_hex);

    EXPECT_EQ(0b0'0000'101, to_hfloat8(MIN / 2.0f + MIN / 8.0f).as_hex);
    EXPECT_EQ(0b0'0000'010, to_hfloat8(MIN / 8.0f + MIN / 16.0f).as_hex); // round up, MIN/4
    EXPECT_EQ(0b0'0000'011, to_hfloat8(MIN / 4.0f + MIN / 16.0f).as_hex); // round up, MIN/4+MIN/8
    EXPECT_EQ(0b0'0000'101, to_hfloat8(MIN / 2.0f + MIN / 16.0f).as_hex); // round up, MIN/2+MIN/8


    // rounding with denormals
    EXPECT_EQ(0b0'0000'111, to_hfloat8(MIN - MIN / 16.0f - MIN / 32.0f).as_hex); // round down, denormal
    EXPECT_EQ(0b0'0001'000, to_hfloat8(MIN - MIN / 16.0f + MIN / 32.0f).as_hex); // round up, MIN

    EXPECT_EQ(0b0'0000'001, to_hfloat8(MIN / 8.0f + MIN / 32.0f).as_hex); // no round up
    EXPECT_EQ(0b0'0000'010, to_hfloat8(MIN / 4.0f + MIN / 32.0f).as_hex); // no round up
    EXPECT_EQ(0b0'0000'100, to_hfloat8(MIN / 2.0f + MIN / 32.0f).as_hex); // no round up

    static constexpr uint32_t F8_INF_BIAS = FLOAT32_EXPONENT_BIAS + HFLOAT8_INF_NAN_EXPONENT - HFLOAT8_EXPONENT_BIAS;
    EXPECT_EQ(0b0'1111'000, to_hfloat8(Float32{0, F8_INF_BIAS, 0x000000}.as_float).as_hex);
    EXPECT_EQ(0b0'1111'001, to_hfloat8(Float32{0, F8_INF_BIAS, 0x100000}.as_float).as_hex);
    EXPECT_EQ(0b0'1111'010, to_hfloat8(Float32{0, F8_INF_BIAS, 0x200000}.as_float).as_hex);
    EXPECT_EQ(0b0'1111'011, to_hfloat8(Float32{0, F8_INF_BIAS, 0x300000}.as_float).as_hex);
    EXPECT_EQ(0b0'1111'100, to_hfloat8(Float32{0, F8_INF_BIAS, 0x400000}.as_float).as_hex);
    EXPECT_EQ(0b0'1111'101, to_hfloat8(Float32{0, F8_INF_BIAS, 0x500000}.as_float).as_hex);
    EXPECT_EQ(HFLOAT8_SATURATED_OVERFLOW_VALUE, to_hfloat8(Float32{0, F8_INF_BIAS, 0x600000}.as_float).value);
    EXPECT_EQ(HFLOAT8_SATURATED_OVERFLOW_VALUE, to_hfloat8(Float32{0, F8_INF_BIAS, 0x700000}.as_float).value);
    EXPECT_EQ(HFLOAT8_SATURATED_OVERFLOW_VALUE, to_hfloat8(Float32{0, F8_INF_BIAS + 1, 0}.as_float).value);
}

TEST(FloatConversions, HF8toFloat) {
    // small float value
    static constexpr float DELTA = 1.0e-6f;
    /// smallest "normal" value
    static constexpr float MIN = 1.0f / ((float) (1 << (HFLOAT8_EXPONENT_BIAS - 1)));
    // lets prevent rounding with MIN/16 by subtracting small value
    static constexpr float FTZ = MIN / 16.0f - DELTA;

    static constexpr Float32 F32INF{ 0, FLOAT32_INFINITY_EXPONENT, 0 };

    EXPECT_EQ(0.0f, from_hfloat8(to_hfloat8(0.0f)));
    EXPECT_EQ(1.0f, from_hfloat8(to_hfloat8(1.0f)));
    EXPECT_EQ(MIN, from_hfloat8(HFloat8::min()));

    EXPECT_EQ(0.0f, from_hfloat8(to_hfloat8(FTZ)));

    // denormals
    EXPECT_EQ(MIN / 2.0f, from_hfloat8(HFloat8{ 0, HFLOAT8_DENORM_EXPONENT, 0b100 }));
    EXPECT_EQ(MIN / 4.0f, from_hfloat8(HFloat8{ 0, HFLOAT8_DENORM_EXPONENT, 0b010 }));
    EXPECT_EQ(MIN / 8.0f, from_hfloat8(HFloat8{ 0, HFLOAT8_DENORM_EXPONENT, 0b001 }));
    EXPECT_EQ(MIN / 2.0f + MIN / 4.0f, from_hfloat8(HFloat8{ 0, HFLOAT8_DENORM_EXPONENT, 0b110 }));
    EXPECT_EQ(MIN / 2.0f + MIN / 8.0f, from_hfloat8(HFloat8{ 0, HFLOAT8_DENORM_EXPONENT, 0b101 }));
    EXPECT_EQ(MIN / 4.0f + MIN / 8.0f, from_hfloat8(HFloat8{ 0, HFLOAT8_DENORM_EXPONENT, 0b011 }));
    EXPECT_EQ(MIN / 2.0f + MIN / 4.0f + MIN / 8.0f, from_hfloat8(HFloat8{ 0, HFLOAT8_DENORM_EXPONENT, 0b111 }));

    EXPECT_EQ(MIN / 2.0f, from_hfloat8(to_hfloat8(MIN / 2.0f)));
    EXPECT_EQ(MIN / 4.0f, from_hfloat8(to_hfloat8(MIN / 4.0f)));
    EXPECT_EQ(MIN / 8.0f, from_hfloat8(to_hfloat8(MIN / 8.0f)));
    EXPECT_EQ(MIN / 8.0f, from_hfloat8(to_hfloat8(MIN / 16.0f))); // rounded!
    EXPECT_EQ(MIN / 2.0f + MIN / 4.0f, from_hfloat8(to_hfloat8(MIN / 2.0f + MIN / 4.0f)));
    EXPECT_EQ(MIN / 2.0f + MIN / 8.0f, from_hfloat8(to_hfloat8(MIN / 2.0f + MIN / 8.0f)));
    EXPECT_EQ(MIN / 2.0f + MIN / 4.0f + MIN / 8.0f, from_hfloat8(to_hfloat8(MIN / 2.0f + MIN / 4.0f + MIN / 8.0f)));
    EXPECT_EQ(MIN, from_hfloat8(to_hfloat8(MIN / 2.0f + MIN / 4.0f + MIN / 8.0f + MIN / 16.0f))); // rounded!

    // almost NaNs with rounding
    static float MAX1 = from_hfloat8(HFloat8::max1());
    EXPECT_EQ(256.0f, MAX1);
    EXPECT_EQ(MAX1, from_hfloat8(to_hfloat8(MAX1)));
    EXPECT_EQ(MAX1, from_hfloat8(to_hfloat8(MAX1 + 1.0f)));
    EXPECT_EQ(MAX1, from_hfloat8(to_hfloat8(MAX1 + 2.0f)));
    EXPECT_EQ(MAX1, from_hfloat8(to_hfloat8(MAX1 + 4.0f)));
    EXPECT_EQ(MAX1, from_hfloat8(to_hfloat8(MAX1 + 8.0f)));
    EXPECT_EQ(MAX1, from_hfloat8(to_hfloat8(MAX1 + 15.0f)));
    EXPECT_EQ(MAX1 + 32.0f,    from_hfloat8(to_hfloat8(MAX1 + 16.0f))); // round up

    EXPECT_EQ(MAX1 + 32.0f,    from_hfloat8(to_hfloat8(MAX1 + 1.0f * 32.0f)));
    EXPECT_EQ(MAX1 + 64.0f,    from_hfloat8(to_hfloat8(MAX1 + 1.0f * 32.0f + 16.0f))); // round up
    EXPECT_EQ(MAX1 + 64.0f,    from_hfloat8(to_hfloat8(MAX1 + 2.0f * 32.0f)));
    EXPECT_EQ(MAX1 + 96.0f,    from_hfloat8(to_hfloat8(MAX1 + 3.0f * 32.0f)));
    EXPECT_EQ(MAX1 + 128.0f,   from_hfloat8(to_hfloat8(MAX1 + 4.0f * 32.0f)));
    EXPECT_EQ(MAX1 + 160.0f,   from_hfloat8(to_hfloat8(MAX1 + 5.0f * 32.0f)));
    EXPECT_EQ(F32INF.as_float, from_hfloat8(to_hfloat8(MAX1 + 6.0f * 32.0f)));
    EXPECT_EQ(F32INF.as_float, from_hfloat8(to_hfloat8(MAX1 + 7.0f * 32.0f)));
    EXPECT_EQ(F32INF.as_float, from_hfloat8(to_hfloat8(2.0f * MAX1)));

}

extern "C" int test_floats_prototypes_c(void);

int test_floats_prototypes_cpp(void)
{
    HFloat8 hfloat8 = new_hfloat8(0, 0, 0);
    BFloat8 bfloat8 = new_bfloat8(0, 0, 0);
    Float16 float16 = new_float16(0, 0, 0);
    BFloat16 bfloat16 = new_bfloat16(0, 0, 0);
    Float32 float32 = new_float32(0, 0, 0);
    float f = 0.0f;
    Float64 float64 = new_float64(0, 0, 0);
    double d = 0.0;
    Float80 float80 = new_float80(0, 0, 0, 0);

    if (IS_NEGATIVE(hfloat8)) return __LINE__;
    if (IS_NEGATIVE(bfloat8)) return __LINE__;
    if (IS_NEGATIVE(float16)) return __LINE__;
    if (IS_NEGATIVE(bfloat16)) return __LINE__;
    if (IS_NEGATIVE(float32)) return __LINE__;
    if (IS_NEGATIVE(f)) return __LINE__;
    if (IS_NEGATIVE(float64)) return __LINE__;
    if (IS_NEGATIVE(d)) return __LINE__;
    if (IS_NEGATIVE(float80)) return __LINE__;

    if (!IS_ZERO(hfloat8)) return __LINE__;
    if (!IS_ZERO(bfloat8)) return __LINE__;
    if (!IS_ZERO(float16)) return __LINE__;
    if (!IS_ZERO(bfloat16)) return __LINE__;
    if (!IS_ZERO(float32)) return __LINE__;
    if (!IS_ZERO(f)) return __LINE__;
    if (!IS_ZERO(float64)) return __LINE__;
    if (!IS_ZERO(d)) return __LINE__;
    if (!IS_ZERO(float80)) return __LINE__;

    if (IS_DENORMAL(hfloat8)) return __LINE__;
    if (IS_DENORMAL(bfloat8)) return __LINE__;
    if (IS_DENORMAL(float16)) return __LINE__;
    if (IS_DENORMAL(bfloat16)) return __LINE__;
    if (IS_DENORMAL(float32)) return __LINE__;
    if (IS_DENORMAL(f)) return __LINE__;
    if (IS_DENORMAL(float64)) return __LINE__;
    if (IS_DENORMAL(d)) return __LINE__;
    if (IS_DENORMAL(float80)) return __LINE__;

    if (!IS_FINITE(hfloat8)) return __LINE__;
    if (!IS_FINITE(bfloat8)) return __LINE__;
    if (!IS_FINITE(float16)) return __LINE__;
    if (!IS_FINITE(bfloat16)) return __LINE__;
    if (!IS_FINITE(float32)) return __LINE__;
    if (!IS_FINITE(f)) return __LINE__;
    if (!IS_FINITE(float64)) return __LINE__;
    if (!IS_FINITE(d)) return __LINE__;
    if (!IS_FINITE(float80)) return __LINE__;

    if (IS_INF_NAN(hfloat8)) return __LINE__;
    if (IS_OVERFLOW(hfloat8)) return __LINE__;
    if (IS_OVERFLOW(bfloat8)) return __LINE__;

    if (IS_INF(bfloat8)) return __LINE__;
    if (IS_INF(float16)) return __LINE__;
    if (IS_INF(bfloat16)) return __LINE__;
    if (IS_INF(float32)) return __LINE__;
    if (IS_INF(f)) return __LINE__;
    if (IS_INF(float64)) return __LINE__;
    if (IS_INF(d)) return __LINE__;
    if (IS_INF(float80)) return __LINE__;

    if (IS_NAN(bfloat8)) return __LINE__;
    if (IS_NAN(float16)) return __LINE__;
    if (IS_NAN(bfloat16)) return __LINE__;
    if (IS_NAN(float32)) return __LINE__;
    if (IS_NAN(f)) return __LINE__;
    if (IS_NAN(float64)) return __LINE__;
    if (IS_NAN(d)) return __LINE__;
    if (IS_NAN(float80)) return __LINE__;

    if (IS_SNAN(bfloat8)) return __LINE__;
    if (IS_SNAN(float16)) return __LINE__;
    if (IS_SNAN(bfloat16)) return __LINE__;
    if (IS_SNAN(float32)) return __LINE__;
    if (IS_SNAN(f)) return __LINE__;
    if (IS_SNAN(float64)) return __LINE__;
    if (IS_SNAN(d)) return __LINE__;
    if (IS_SNAN(float80)) return __LINE__;

    if (IS_QNAN(bfloat8)) return __LINE__;
    if (IS_QNAN(float16)) return __LINE__;
    if (IS_QNAN(bfloat16)) return __LINE__;
    if (IS_QNAN(float32)) return __LINE__;
    if (IS_QNAN(f)) return __LINE__;
    if (IS_QNAN(float64)) return __LINE__;
    if (IS_QNAN(d)) return __LINE__;
    if (IS_QNAN(float80)) return __LINE__;

    if (GET_NAN_PAYLOAD(float16) != 0) return __LINE__;
    if (GET_NAN_PAYLOAD(bfloat16) != 0) return __LINE__;
    if (GET_NAN_PAYLOAD(float32) != 0) return __LINE__;
    if (GET_NAN_PAYLOAD(f) != 0) return __LINE__;
    if (GET_NAN_PAYLOAD(float64) != 0) return __LINE__;
    if (GET_NAN_PAYLOAD(d) != 0) return __LINE__;
    if (GET_NAN_PAYLOAD(float80) != 0) return __LINE__;

    if (AS_FP(hfloat8) != 0.0) return __LINE__;
    if (AS_FP(bfloat8) != 0.0) return __LINE__;
    if (AS_FP(float16) != 0.0) return __LINE__;
    if (AS_FP(bfloat16) != 0.0) return __LINE__;
    if (AS_FP(float32) != 0.0) return __LINE__;
    if (AS_FP(f) != 0.0) return __LINE__;
    if (AS_FP(float64) != 0.0) return __LINE__;
    if (AS_FP(d) != 0.0) return __LINE__;
    if (AS_FP(float80) != 0.0) return __LINE__;

    hfloat8 = new_random_hfloat8();
    bfloat8 = new_random_bfloat8();
    float16 = new_random_float16();
    bfloat16 = new_random_bfloat16();
    float32 = new_random_float32();
    f = new_random_float();
    float64 = new_random_float64();
    d = new_random_double();
    float80 = new_random_float80();

    SET_RANDOM(hfloat8);
    SET_RANDOM(bfloat8);
    SET_RANDOM(float16);
    SET_RANDOM(bfloat16);
    SET_RANDOM(float32);
    SET_RANDOM(f);
    SET_RANDOM(float64);
    SET_RANDOM(d);
    SET_RANDOM(float80);

    bfloat8 = new_random(BFloat8);
    hfloat8 = new_random(HFloat8);
    float16 = new_random(Float16);
    bfloat16 = new_random(BFloat16);
    float32 = new_random(Float32);
    f = new_random(float);
    float64 = new_random(Float64);
    d = new_random(double);
    float80 = new_random(Float80);
    return 0;
}

TEST(FloatGeneration, new_random_float_prototypes) {
    // briefly verify C interface
    ASSERT_EQ(0, test_floats_prototypes_c());
    ASSERT_EQ(0, test_floats_prototypes_cpp());
}
