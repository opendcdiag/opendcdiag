/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <vector>
#include "gtest/gtest.h"
#include "sandstone_utils.h"

#include <limits.h>
#include <locale.h>
#include <inttypes.h>
#include <immintrin.h>

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
    EXPECT_EQ(format_type_helper(BFloat16(1 + BFLT16_EPSILON)), "3f81 (0x1.02p+0)");
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
    EXPECT_EQ(format_type_helper(Float16(1 + __FLT16_EPSILON__)), "3c01 (0x1.004p+0)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<Float16>::infinity()), "7c00 (inf)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<Float16>::neg_infinity()), "fc00 (-inf)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<Float16>::quiet_NaN()), "7e00 (nan)");
    EXPECT_EQ(format_type_helper(my_numeric_limits<Float16>::signaling_NaN()), "7d00 (nan)");
}
