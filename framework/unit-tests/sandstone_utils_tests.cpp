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
__attribute__((weak)) void* memset_random(void* buf, size_t n) {
    uint8_t* b = (uint8_t*) buf;
    do {
        uint32_t r = random();
        size_t s = (n > sizeof(r)) ? sizeof(r) : n;
        memcpy(b, &r, s);
        b += s;
        n -= s;
    } while (n > 0);
    return buf;
}
__attribute__((weak)) __uint128_t random128() {
    __uint128_t f;
    memset_random(&f, sizeof(f));
    return f;
}
__attribute__((weak)) uint64_t random64() {
    uint64_t f;
    memset_random(&f, sizeof(f));
    return f;
}
__attribute__((weak)) uint32_t random32() {
    uint32_t f;
    memset_random(&f, sizeof(f));
    return f;
}
uint64_t set_random_bits(unsigned num_bits_to_set, uint32_t bitwidth) {
    if (bitwidth > 64) {
        assert(!"bitwidth > 64");
    }
    uint64_t r = random32();
    if (bitwidth >= 32) {
        r <<= 32;
        r |= random32();
    }
    return r & MASK(bitwidth);
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

#define EXPECT_IN_RANGE(MIN, MAX, VAL) \
    ({\
        float val = AS_FP(VAL);\
        EXPECT_GE(val, (MIN));\
        EXPECT_LT(val, (MAX));\
    })
#define EXPECT_IN_RANGE_INCL(MIN, MAX, VAL) \
    ({\
        float val = AS_FP(VAL);\
        EXPECT_GE(val, (MIN));\
        EXPECT_LE(val, (MAX));\
    })

extern "C" {
int num_float16_vectors() {
    return 1;
}
#define VECTOR_FLOAT16 Float16{ 0, 2, 34 }
Float16 get_float16_vector(int idx) {
    return VECTOR_FLOAT16;
}
int num_float32_vectors() {
    return 1;
}
#define VECTOR_FLOAT32 Float32{ 0, 3, 456 }
Float32 get_float32_vector(int idx) {
    return VECTOR_FLOAT32;
}
int num_float64_vectors() {
    return 1;
}
#define VECTOR_FLOAT64 Float64{ 0, 12, 3456 }
Float64 get_float64_vector(int idx) {
    return VECTOR_FLOAT64;
}
int num_float80_vectors() {
    return 1;
}
#define VECTOR_FLOAT80 Float80{ 0, 34, 5678 }
Float80 get_float80_vector(int idx) {
    return VECTOR_FLOAT80;
}
}

extern "C" int test_new_random_float_prototypes_c(void);
extern "C" int test_floats_prototypes_c(void);

// reuse "C" code to check the prototypes, etc, but in the context of C++
#define test_floats_prototypes_c test_floats_prototypes_cpp
#define test_new_random_float_prototypes_c test_new_random_float_prototypes_cpp
#include "sandstone_utils_tests.c"
#undef test_floats_prototypes_c
#undef test_new_random_float_prototypes_c

TEST(FloatGeneration, new_random_float_prototypes) {
    // briefly verify C interface
    ASSERT_EQ(0, test_floats_prototypes_c());
    ASSERT_EQ(0, test_floats_prototypes_cpp());
    ASSERT_EQ(0, test_new_random_float_prototypes_c());
    ASSERT_EQ(0, test_new_random_float_prototypes_cpp());

    // unhandled fast path generators with additional flags
    EXPECT_DEATH(new_random_hfloat8(FP_GEN_FAST_ZERO | FP_GEN_POSITIVE), "");
    EXPECT_DEATH(new_random_hfloat8(FP_GEN_FAST_MEMSET_ZERO | FP_GEN_POSITIVE), "");
    EXPECT_DEATH(new_random_hfloat8(FP_GEN_FAST_MEMSET_RANDOM | FP_GEN_POSITIVE), "");
    EXPECT_DEATH(new_random_hfloat8(FP_GEN_COMPATIBILITY_GENERATOR | FP_GEN_POSITIVE), "");

    new_random_bfloat8(FP_GEN_FAST_MEMSET_RANDOM);
    ASSERT_TRUE(IS_ZERO(new_random_float16(FP_GEN_FAST_ZERO)));
    ASSERT_TRUE(IS_ZERO(new_random_float16(FP_GEN_FAST_MEMSET_ZERO)));

    // unhandled cmath category classes, these should all trigger assertion failure
    #if FP_SUBNORMAL != 0
    EXPECT_DEATH(new_random_float(FP_SUBNORMAL), "");
    #endif
    #if FP_NORMAL != 0
    EXPECT_DEATH(new_random_float(FP_NORMAL), "");
    #endif
    #if FP_ZERO != 0
    EXPECT_DEATH(new_random_float(FP_ZERO), "");
    #endif
    #if FP_INFINITE != 0
    EXPECT_DEATH(new_random_float(FP_INFINITE), "");
    #endif
    #if FP_NAN != 0
    EXPECT_DEATH(new_random_float(FP_NAN), "");
    #endif

    // unhandled selector bits, normalization is checked before!
    EXPECT_DEATH(new_random_bfloat8(-1 & (~FP_GEN_NORMALIZE)), "");

    // unhandled mantissa selectors
    EXPECT_DEATH(new_random_hfloat8(FP_GEN_RANDOM_FLAGS_MANTISSA_UNHANDLED1), "");
    EXPECT_DEATH(new_random_hfloat8(FP_GEN_RANDOM_FLAGS_MANTISSA_UNHANDLED2), "");
    EXPECT_DEATH(new_random_hfloat8(FP_GEN_RANDOM_FLAGS_MANTISSA_UNHANDLED3), "");

    EXPECT_EQ(1.0f, AS_FP(new_random_hfloat8(FP_GEN_RANDOM_FLAGS_SIGN_POSITIVE | FP_GEN_RANDOM_FLAGS_EXPONENT_BIAS | FP_GEN_RANDOM_FLAGS_MANTISSA_ZERO)));
    EXPECT_EQ(1.0f, AS_FP(new_random_bfloat8(FP_GEN_RANDOM_FLAGS_SIGN_POSITIVE | FP_GEN_RANDOM_FLAGS_EXPONENT_BIAS | FP_GEN_RANDOM_FLAGS_MANTISSA_ZERO)));
    EXPECT_EQ(1.0f, AS_FP(new_random_float16(FP_GEN_RANDOM_FLAGS_SIGN_POSITIVE | FP_GEN_RANDOM_FLAGS_EXPONENT_BIAS | FP_GEN_RANDOM_FLAGS_MANTISSA_ZERO)));
    EXPECT_EQ(1.0f, AS_FP(new_random_bfloat16(FP_GEN_RANDOM_FLAGS_SIGN_POSITIVE | FP_GEN_RANDOM_FLAGS_EXPONENT_BIAS | FP_GEN_RANDOM_FLAGS_MANTISSA_ZERO)));
    EXPECT_EQ(1.0f, AS_FP(new_random_float32(FP_GEN_RANDOM_FLAGS_SIGN_POSITIVE | FP_GEN_RANDOM_FLAGS_EXPONENT_BIAS | FP_GEN_RANDOM_FLAGS_MANTISSA_ZERO)));
    EXPECT_EQ(1.0f, AS_FP(new_random_float64(FP_GEN_RANDOM_FLAGS_SIGN_POSITIVE | FP_GEN_RANDOM_FLAGS_EXPONENT_BIAS | FP_GEN_RANDOM_FLAGS_MANTISSA_ZERO)));
    EXPECT_EQ(1.0f, AS_FP(new_random_float80(FP_GEN_RANDOM_FLAGS_SIGN_POSITIVE | FP_GEN_RANDOM_FLAGS_EXPONENT_BIAS | FP_GEN_RANDOM_FLAGS_MANTISSA_ZERO)));

    EXPECT_DEATH(new_random_hfloat8(FP_GEN_STATIC_VECTOR), "");
    EXPECT_DEATH(new_random_bfloat8(FP_GEN_STATIC_VECTOR), "");
    EXPECT_DEATH(new_random_bfloat16(FP_GEN_STATIC_VECTOR), "");
    EXPECT_EQ(AS_FP(VECTOR_FLOAT16), new_random_float16(FP_GEN_STATIC_VECTOR).as_fp());
    EXPECT_EQ(AS_FP(VECTOR_FLOAT32), new_random_float32(FP_GEN_STATIC_VECTOR).as_fp());
    EXPECT_EQ(AS_FP(VECTOR_FLOAT32), new_random_float(FP_GEN_STATIC_VECTOR));
    // .as_fp() gives more precise result, AS_FP always reports float!
    EXPECT_EQ(AS_FP(VECTOR_FLOAT64), (float) new_random_float64(FP_GEN_STATIC_VECTOR).as_fp());
    EXPECT_EQ(AS_FP(VECTOR_FLOAT64), (float) new_random_double(FP_GEN_STATIC_VECTOR));
    EXPECT_EQ(AS_FP(VECTOR_FLOAT80), (float) new_random_float80(FP_GEN_STATIC_VECTOR).as_fp());

    EXPECT_EQ(AS_FP(VECTOR_FLOAT16), new_random_float16(FP_GEN_PCT_VEC(100)).as_fp());
    EXPECT_DEATH(new_random_float16(FP_GEN_PCT_VEC(101)), "");
    ASSERT_TRUE(IS_ZERO(new_random_float16(FP_GEN_PCT_VEC(0) | FP_GEN_ZERO)));
    // just waste of RNG calls, always static vector value is returned
    EXPECT_EQ(AS_FP(VECTOR_FLOAT16), new_random_float16(FP_GEN_PCT_VEC(100)).as_fp());
    // just waste of RNG calls, in "both" 50/50 cases we get static vector value is returned
    EXPECT_EQ(AS_FP(VECTOR_FLOAT16), new_random_float16(FP_GEN_STATIC_VECTOR | FP_GEN_PCT_VEC(50)).as_fp());

    // either static_vector or zero, 50/50 chance
    Float16 v_val = new_random_float16(FP_GEN_PCT_VEC(50) | FP_GEN_ZERO);
    ASSERT_TRUE(IS_ZERO(v_val) || AS_FP(v_val) == AS_FP(VECTOR_FLOAT16));


    ASSERT_EQ(0, new_random_float16(FP_GEN_SNAN).as_nan.quiet);
    ASSERT_EQ(1, new_random_float16(FP_GEN_QNAN).as_nan.quiet);

    ASSERT_TRUE(IS_ZERO(new_random_hfloat8(FP_GEN_ZERO)));
    ASSERT_TRUE(IS_DENORMAL(new_random_hfloat8(FP_GEN_DENORMAL)));
    // HFloat8 does not support infinities and NaNs as a separate values
    // INF generates INF_NAN, NaN is not allowed
    ASSERT_TRUE(IS_INF_NAN(new_random_hfloat8(FP_GEN_INF)));
    EXPECT_DEATH(IS_INF_NAN(new_random_hfloat8(FP_GEN_NAN)), "");
    ASSERT_TRUE(IS_FINITE(new_random_hfloat8(FP_GEN_ZERO)));
    ASSERT_TRUE(IS_FINITE(new_random_hfloat8(FP_GEN_DENORMAL)));
    ASSERT_TRUE(IS_FINITE(new_random_hfloat8(FP_GEN_RANGE12)));
    ASSERT_FALSE(IS_FINITE(new_random_hfloat8(FP_GEN_INF)));

    // NaNs are not supported for HFloat8
    EXPECT_DEATH(new_random_hfloat8(FP_GEN_NAN), "");
    EXPECT_DEATH(new_random_hfloat8(FP_GEN_SNAN), "");
    EXPECT_DEATH(new_random_hfloat8(FP_GEN_QNAN), "");

    ASSERT_TRUE(IS_ZERO(new_random_bfloat8(FP_GEN_ZERO)));
    ASSERT_TRUE(IS_DENORMAL(new_random_bfloat8(FP_GEN_DENORMAL)));
    ASSERT_TRUE(IS_INF(new_random_bfloat8(FP_GEN_INF)));
    ASSERT_TRUE(IS_NAN(new_random_bfloat8(FP_GEN_NAN)));
    ASSERT_TRUE(IS_SNAN(new_random_bfloat8(FP_GEN_SNAN)));
    ASSERT_TRUE(IS_QNAN(new_random_bfloat8(FP_GEN_QNAN)));
    ASSERT_TRUE(IS_FINITE(new_random_bfloat8(FP_GEN_ZERO)));
    ASSERT_TRUE(IS_FINITE(new_random_bfloat8(FP_GEN_DENORMAL)));
    ASSERT_TRUE(IS_FINITE(new_random_bfloat8(FP_GEN_RANGE12)));
    ASSERT_FALSE(IS_FINITE(new_random_bfloat8(FP_GEN_INF)));
    ASSERT_FALSE(IS_FINITE(new_random_bfloat8(FP_GEN_NAN)));
    ASSERT_FALSE(IS_FINITE(new_random_bfloat8(FP_GEN_SNAN)));
    ASSERT_FALSE(IS_FINITE(new_random_bfloat8(FP_GEN_QNAN)));

    ASSERT_TRUE(IS_ZERO(new_random_float16(FP_GEN_ZERO)));
    ASSERT_TRUE(IS_DENORMAL(new_random_float16(FP_GEN_DENORMAL)));
    ASSERT_TRUE(IS_INF(new_random_float16(FP_GEN_INF)));
    ASSERT_TRUE(IS_NAN(new_random_float16(FP_GEN_NAN)));
    ASSERT_TRUE(IS_SNAN(new_random_float16(FP_GEN_SNAN)));
    ASSERT_TRUE(IS_QNAN(new_random_float16(FP_GEN_QNAN)));
    ASSERT_TRUE(IS_FINITE(new_random_float16(FP_GEN_ZERO)));
    ASSERT_TRUE(IS_FINITE(new_random_float16(FP_GEN_DENORMAL)));
    ASSERT_TRUE(IS_FINITE(new_random_float16(FP_GEN_RANGE12)));
    ASSERT_FALSE(IS_FINITE(new_random_float16(FP_GEN_INF)));
    ASSERT_FALSE(IS_FINITE(new_random_float16(FP_GEN_NAN)));
    ASSERT_FALSE(IS_FINITE(new_random_float16(FP_GEN_SNAN)));
    ASSERT_FALSE(IS_FINITE(new_random_float16(FP_GEN_QNAN)));

    ASSERT_TRUE(IS_ZERO(new_random_bfloat16(FP_GEN_ZERO)));
    ASSERT_TRUE(IS_DENORMAL(new_random_bfloat16(FP_GEN_DENORMAL)));
    ASSERT_TRUE(IS_INF(new_random_bfloat16(FP_GEN_INF)));
    ASSERT_TRUE(IS_NAN(new_random_bfloat16(FP_GEN_NAN)));
    ASSERT_TRUE(IS_SNAN(new_random_bfloat16(FP_GEN_SNAN)));
    ASSERT_TRUE(IS_QNAN(new_random_bfloat16(FP_GEN_QNAN)));
    ASSERT_TRUE(IS_FINITE(new_random_bfloat16(FP_GEN_ZERO)));
    ASSERT_TRUE(IS_FINITE(new_random_bfloat16(FP_GEN_DENORMAL)));
    ASSERT_TRUE(IS_FINITE(new_random_bfloat16(FP_GEN_RANGE12)));
    ASSERT_FALSE(IS_FINITE(new_random_bfloat16(FP_GEN_INF)));
    ASSERT_FALSE(IS_FINITE(new_random_bfloat16(FP_GEN_NAN)));
    ASSERT_FALSE(IS_FINITE(new_random_bfloat16(FP_GEN_SNAN)));
    ASSERT_FALSE(IS_FINITE(new_random_bfloat16(FP_GEN_QNAN)));

    ASSERT_TRUE(IS_ZERO(new_random_float32(FP_GEN_ZERO)));
    ASSERT_TRUE(IS_DENORMAL(new_random_float32(FP_GEN_DENORMAL)));
    ASSERT_TRUE(IS_INF(new_random_float32(FP_GEN_INF)));
    ASSERT_TRUE(IS_NAN(new_random_float32(FP_GEN_NAN)));
    ASSERT_TRUE(IS_SNAN(new_random_float32(FP_GEN_SNAN)));
    ASSERT_TRUE(IS_QNAN(new_random_float32(FP_GEN_QNAN)));
    ASSERT_TRUE(IS_FINITE(new_random_float32(FP_GEN_ZERO)));
    ASSERT_TRUE(IS_FINITE(new_random_float32(FP_GEN_DENORMAL)));
    ASSERT_TRUE(IS_FINITE(new_random_float32(FP_GEN_RANGE12)));
    ASSERT_FALSE(IS_FINITE(new_random_float32(FP_GEN_INF)));
    ASSERT_FALSE(IS_FINITE(new_random_float32(FP_GEN_NAN)));
    ASSERT_FALSE(IS_FINITE(new_random_float32(FP_GEN_SNAN)));
    ASSERT_FALSE(IS_FINITE(new_random_float32(FP_GEN_QNAN)));

    ASSERT_TRUE(IS_ZERO(new_random_float64(FP_GEN_ZERO)));
    ASSERT_TRUE(IS_DENORMAL(new_random_float64(FP_GEN_DENORMAL)));
    ASSERT_TRUE(IS_INF(new_random_float64(FP_GEN_INF)));
    ASSERT_TRUE(IS_NAN(new_random_float64(FP_GEN_NAN)));
    ASSERT_TRUE(IS_SNAN(new_random_float64(FP_GEN_SNAN)));
    ASSERT_TRUE(IS_QNAN(new_random_float64(FP_GEN_QNAN)));
    ASSERT_TRUE(IS_FINITE(new_random_float64(FP_GEN_ZERO)));
    ASSERT_TRUE(IS_FINITE(new_random_float64(FP_GEN_DENORMAL)));
    ASSERT_TRUE(IS_FINITE(new_random_float64(FP_GEN_RANGE12)));
    ASSERT_FALSE(IS_FINITE(new_random_float64(FP_GEN_INF)));
    ASSERT_FALSE(IS_FINITE(new_random_float64(FP_GEN_NAN)));
    ASSERT_FALSE(IS_FINITE(new_random_float64(FP_GEN_SNAN)));
    ASSERT_FALSE(IS_FINITE(new_random_float64(FP_GEN_QNAN)));

    EXPECT_IN_RANGE(1.0, 2.0, new_random_hfloat8(FP_GEN_RANGE12).as_fp());
    EXPECT_IN_RANGE(1.0, 2.0, new_random_bfloat8(FP_GEN_RANGE12).as_fp());
    EXPECT_IN_RANGE(1.0, 2.0, new_random_float16(FP_GEN_RANGE12).as_fp());
    EXPECT_IN_RANGE(1.0, 2.0, new_random_bfloat16(FP_GEN_RANGE12).as_fp());
    EXPECT_IN_RANGE(1.0, 2.0, new_random_float32(FP_GEN_RANGE12).as_fp());
    EXPECT_IN_RANGE(1.0, 2.0, new_random_float64(FP_GEN_RANGE12).as_fp());
    EXPECT_IN_RANGE(1.0, 2.0, new_random_float80(FP_GEN_RANGE12).as_fp());

    // some types are rounded up, make sure the range doesn't force up-rounding!
    // (e.g. "almost" 12 will allways be 12 for hfloat8). Keeping mantissa tidy
    // (t.i force power-of-2 ranges) might be profitable.
    // default flags here are POSITITE/RANGE12, Inf values are excluded by definition
    EXPECT_IN_RANGE(8.0f, 16.0f, new_random_hfloat8(8.0, 16.0));
    EXPECT_IN_RANGE(8.0f, 16.0f, new_random_bfloat8(8.0, 16.0));
    EXPECT_IN_RANGE(8.0f, 16.0f, new_random_float16(8.0, 16.0));
    EXPECT_IN_RANGE(8.0f, 16.0f, new_random_bfloat16(8.0, 16.0));
    EXPECT_IN_RANGE(8.0f, 16.0f, new_random_float32(8.0, 16.0));
    EXPECT_IN_RANGE(8.0f, 16.0f, new_random_float(8.0, 16.0));
    EXPECT_IN_RANGE(8.0f, 16.0f, new_random_float64(8.0, 16.0));
    EXPECT_IN_RANGE(8.0f, 16.0f, new_random_double(8.0, 16.0));
    EXPECT_IN_RANGE(8.0f, 16.0f, new_random_float80(8.0, 16.0));

    // only finite values are normalized
    EXPECT_IN_RANGE(2, 32, new_random_hfloat8(FP_GEN_FINITE, 2, 32));
    EXPECT_IN_RANGE(2, 32, new_random_bfloat8(FP_GEN_FINITE, 2, 32));
    EXPECT_IN_RANGE(2, 32, new_random_float16(FP_GEN_FINITE, 2, 32));
    EXPECT_IN_RANGE(2, 32, new_random_bfloat16(FP_GEN_FINITE, 2, 32));
    EXPECT_IN_RANGE(2, 32, new_random_float32(FP_GEN_FINITE, 2, 32));
    EXPECT_IN_RANGE(2, 32, new_random_float(FP_GEN_FINITE, 2, 32));
    EXPECT_IN_RANGE(2, 32, new_random_float64(FP_GEN_FINITE, 2, 32));
    EXPECT_IN_RANGE(2, 32, new_random_double(FP_GEN_FINITE, 2, 32));
    EXPECT_IN_RANGE(2, 32, new_random_float80(FP_GEN_FINITE, 2, 32));

    // Inf/NaN/overflow values are never normalized, so the range is irrelevant here
    EXPECT_TRUE(IS_INF_NAN(new_random_hfloat8(FP_GEN_INF, 2, 32)));

    EXPECT_TRUE(IS_INF(new_random_bfloat8(FP_GEN_INF, 2, 32)));
    EXPECT_TRUE(IS_INF(new_random_float16(FP_GEN_INF, 2, 32)));
    EXPECT_TRUE(IS_INF(new_random_bfloat16(FP_GEN_INF, 2, 32)));
    EXPECT_TRUE(IS_INF(new_random_float32(FP_GEN_INF, 2, 32)));
    EXPECT_TRUE(IS_INF(new_random_float(FP_GEN_INF, 2, 32)));
    EXPECT_TRUE(IS_INF(new_random_float64(FP_GEN_INF, 2, 32)));
    EXPECT_TRUE(IS_INF(new_random_double(FP_GEN_INF, 2, 32)));
    EXPECT_TRUE(IS_INF(new_random_float80(FP_GEN_INF, 2, 32)));

    EXPECT_TRUE(IS_NAN(new_random_bfloat8(FP_GEN_NAN, 2, 32)));
    EXPECT_TRUE(IS_NAN(new_random_float16(FP_GEN_NAN, 2, 32)));
    EXPECT_TRUE(IS_NAN(new_random_bfloat16(FP_GEN_NAN, 2, 32)));
    EXPECT_TRUE(IS_NAN(new_random_float32(FP_GEN_NAN, 2, 32)));
    EXPECT_TRUE(IS_NAN(new_random_float(FP_GEN_NAN, 2, 32)));
    EXPECT_TRUE(IS_NAN(new_random_float64(FP_GEN_NAN, 2, 32)));
    EXPECT_TRUE(IS_NAN(new_random_double(FP_GEN_NAN, 2, 32)));
    EXPECT_TRUE(IS_NAN(new_random_float80(FP_GEN_NAN, 2, 32)));

    EXPECT_TRUE(IS_OVERFLOW(new_random_hfloat8(FP_GEN_OVERFLOW, 2, 32)));
    EXPECT_TRUE(IS_OVERFLOW(new_random_bfloat8(FP_GEN_OVERFLOW, 2, 32)));

    // verify sanity checks
    ASSERT_TRUE(IS_ZERO(new_random_bfloat8(0, 0)));
    EXPECT_EQ(1.0, AS_FP(new_random_bfloat8(FP_GEN_ZERO, 1, 2)));
    ASSERT_DEATH(new_random_bfloat8(FP_GEN_INF, 0, 0), "");
    ASSERT_DEATH(new_random_bfloat8(FP_GEN_POSITIVE, -2, -1), "");
    ASSERT_DEATH(new_random_bfloat8(FP_GEN_POSITIVE, -1, 0), "");
    ASSERT_DEATH(new_random_bfloat8(FP_GEN_NEGATIVE, 1, 2), "");
    ASSERT_DEATH(new_random_bfloat8(FP_GEN_NEGATIVE, 0, 1), "");
    EXPECT_DEATH(new_random_bfloat8(FP_GEN_NORMALIZE), "");

    // half-axes ranges. The distribution is not uniform here!
    ASSERT_FALSE(IS_NEGATIVE(new_random_bfloat8(0, std::numeric_limits<float>::max())));
    ASSERT_TRUE(IS_FINITE(new_random_bfloat8(0, std::numeric_limits<float>::max())));

    ASSERT_TRUE(IS_NEGATIVE(new_random_bfloat8(-std::numeric_limits<float>::max(), 0)));
    ASSERT_TRUE(IS_FINITE(new_random_bfloat8(-std::numeric_limits<float>::max(), 0)));

    // no normalization forced.. Just to get any valid value
    ASSERT_TRUE(IS_FINITE(new_random_bfloat8(-std::numeric_limits<float>::max(), std::numeric_limits<float>::max())));

    // symetrical ranges
    ASSERT_FALSE(IS_NEGATIVE(new_random_bfloat8(std::numeric_limits<float>::max(), 0)));
    ASSERT_TRUE(IS_NEGATIVE(new_random_bfloat8(0, -std::numeric_limits<float>::max())));
    ASSERT_TRUE(IS_FINITE(new_random_bfloat8(std::numeric_limits<float>::max(), 0)));
    ASSERT_TRUE(IS_FINITE(new_random_bfloat8(0, -std::numeric_limits<float>::max())));
    ASSERT_TRUE(IS_FINITE(new_random_bfloat8(std::numeric_limits<float>::max(), -std::numeric_limits<float>::max())));

    // contradicting flags
    ASSERT_DEATH(new_random_bfloat8(FP_GEN_INF | FP_GEN_RANDOM_FLAGS_FORCE_FINITE), "");
    ASSERT_DEATH(new_random_bfloat8(FP_GEN_NAN | FP_GEN_RANDOM_FLAGS_FORCE_FINITE), "");
    ASSERT_DEATH(new_random_bfloat8(FP_GEN_SNAN | FP_GEN_RANDOM_FLAGS_FORCE_FINITE), "");
    ASSERT_DEATH(new_random_bfloat8(FP_GEN_QNAN | FP_GEN_RANDOM_FLAGS_FORCE_FINITE), "");
    ASSERT_DEATH(new_random_bfloat8(FP_GEN_OVERFLOW | FP_GEN_RANDOM_FLAGS_FORCE_FINITE), "");

    // check floats
    ASSERT_FALSE(IS_NEGATIVE(new_random_float(0, std::numeric_limits<float>::max())));
    ASSERT_TRUE(IS_FINITE(new_random_float(0, std::numeric_limits<float>::max())));

    ASSERT_TRUE(IS_NEGATIVE(new_random_float(-std::numeric_limits<float>::max(), 0)));
    ASSERT_TRUE(IS_FINITE(new_random_float(-std::numeric_limits<float>::max(), 0)));

    // 8 bit types use rounding-up when converting from higher types (and both minimal and maximal value are possible)
    EXPECT_IN_RANGE_INCL(2, 32, BFloat8{ new_random_float(2, 32) });
    EXPECT_IN_RANGE_INCL(2, 32, HFloat8{ new_random_float(2, 32) });
    EXPECT_IN_RANGE(2, 32, BFloat16{ new_random_float(2, 32) });
    EXPECT_IN_RANGE(2, 32, Float16{ new_random_float(2, 32) });

    EXPECT_IN_RANGE_INCL(2, 32, BFloat8(new_random_float(2, 32)));
    EXPECT_IN_RANGE_INCL(2, 32, HFloat8(new_random_float(2, 32)));
    EXPECT_IN_RANGE(2, 32, BFloat16(new_random_float(2, 32)));
    EXPECT_IN_RANGE(2, 32, Float16(new_random_float(2, 32)));

    static constexpr size_t ARR_SIZE = 1000;
    HFloat8 hf8_arr[ARR_SIZE]; // uninitialized!!!!

    // force 1.0 in all emements
    SET_RANDOM_ARR(hf8_arr, FP_GEN_POSITIVE | FP_GEN_RANDOM_FLAGS_EXPONENT_BIAS | FP_GEN_RANDOM_FLAGS_MANTISSA_ZERO);
    for (int i = 0; i < ARR_SIZE; i++) {
        EXPECT_EQ(1.0f, AS_FP(hf8_arr[i]));
    }
    SET_RANDOM_ARR(hf8_arr, FP_GEN_FAST_ZERO);
    for (int i = 0; i < ARR_SIZE; i++) {
        EXPECT_EQ(0.0f, AS_FP(hf8_arr[i]));
    }

    float f = new_random_float(FP_GEN_CMATH_CLASS(FP_NORMAL));
    EXPECT_TRUE((IS_FINITE(f)) && (!IS_DENORMAL(f)));
    EXPECT_TRUE(IS_DENORMAL(new_random_float(FP_GEN_CMATH_CLASS(FP_SUBNORMAL))));
    EXPECT_TRUE(IS_ZERO(new_random_float(FP_GEN_CMATH_CLASS(FP_ZERO))));
    EXPECT_TRUE(IS_INF(new_random_float(FP_GEN_CMATH_CLASS(FP_INFINITE))));
    EXPECT_TRUE(IS_NAN(new_random_float(FP_GEN_CMATH_CLASS(FP_NAN))));

    static constexpr size_t HFLOAT8_ARR_SIZE = 543;
    HFloat8 hfloat8_arr[HFLOAT8_ARR_SIZE];
    SET_RANDOM_ARR(hfloat8_arr, FP_GEN_FAST_MEMSET_ZERO);
    for (size_t i = 0; i < HFLOAT8_ARR_SIZE; i++) {
        ASSERT_TRUE(IS_ZERO(hfloat8_arr[i]));
    }
    // all values but last should be random, nothing is guaranteed about the values
    // last value must remain unmodified!
    SET_RANDOM_PTR(hfloat8_arr, HFLOAT8_ARR_SIZE - 1, FP_GEN_FAST_MEMSET_RANDOM);
    ASSERT_TRUE(IS_ZERO(hfloat8_arr[HFLOAT8_ARR_SIZE - 1]));

    // "slower" fast path generator
    SET_RANDOM_ARR(hfloat8_arr, FP_GEN_FAST_ZERO);
    for (size_t i = 0; i < HFLOAT8_ARR_SIZE; i++) {
        ASSERT_TRUE(IS_ZERO(hfloat8_arr[i]));
    }

    set_random(hfloat8_arr, HFLOAT8_ARR_SIZE - 1, FP_GEN_RANDOM_FLAGS_MANTISSA_ZERO | FP_GEN_RANDOM_FLAGS_EXPONENT_BIAS | FP_GEN_POSITIVE);
    for (size_t i = 0; i < HFLOAT8_ARR_SIZE - 1; i++) {
        //EXPECT_EQ(1.0f, AS_FP(hfloat8_arr[i]));
    }
    ASSERT_TRUE(IS_ZERO(hfloat8_arr[HFLOAT8_ARR_SIZE - 1]));
}
