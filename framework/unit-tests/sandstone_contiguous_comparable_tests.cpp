/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

// SandstoneCrossCheck::ContiguousComparable and the container memcmp_or_fail
// overload. Failure-path coverage lives in the selftest_container_comparefail_*
// selftests in framework/selftest.cpp. The success-path runtime checks use the
// stubs in sandstone_report_stubs.cpp.

#include "sandstone.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <list>
#include <memory>
#include <span>
#include <string>
#include <vector>

#ifdef __linux__
#  include <sys/mman.h>
#  include <unistd.h>
#endif

#include "gtest/gtest.h"

// ---------------------------------------------------------------------------
// ContiguousComparable concept checks
// ---------------------------------------------------------------------------

// Primary targets: contiguous, sized, trivially-copyable element.
static_assert(SandstoneCrossCheck::ContiguousComparable<std::vector<uint32_t>>);
static_assert(SandstoneCrossCheck::ContiguousComparable<std::array<float, 4>>);
static_assert(SandstoneCrossCheck::ContiguousComparable<std::string>);
static_assert(SandstoneCrossCheck::ContiguousComparable<std::basic_string<char>>);
static_assert(SandstoneCrossCheck::ContiguousComparable<std::span<int>>);

// Exclusions.
static_assert(!SandstoneCrossCheck::ContiguousComparable<std::vector<bool>>);      // proxy-reference, not contiguous
static_assert(!SandstoneCrossCheck::ContiguousComparable<std::vector<std::vector<int>>>); // element not a ValidDataType
static_assert(!SandstoneCrossCheck::ContiguousComparable<std::list<int>>);         // not contiguous
static_assert(!SandstoneCrossCheck::ContiguousComparable<int>);                    // not a range
struct NotARange {};
static_assert(!SandstoneCrossCheck::ContiguousComparable<NotARange>);              // not a range

// Opaque struct element: even though it is trivially copyable, it has no
// TypeToDataType specialization and so is not a ValidDataType. A container of
// such a struct must be rejected, because comparing it via raw memcmp would
// be unsound (padding bytes, pointer members, etc. are not addressed by a
// byte comparison semantics).
struct OpaqueTrivial {
    uint32_t a;
    uint16_t b;
    uint8_t  c;
    uint8_t  pad;
};
static_assert(std::is_trivially_copyable_v<OpaqueTrivial>);
static_assert(!SandstoneCrossCheck::ContiguousComparable<std::vector<OpaqueTrivial>>);

// ---------------------------------------------------------------------------
// Container memcmp_or_fail overload: success-path runtime tests
// ---------------------------------------------------------------------------

// The container overload is [[noreturn]] on mismatch; on a match it returns
// normally. These tests exercise the match path. Mismatch coverage lives in
// the selftest_container_comparefail_* selftests in framework/selftest.cpp.

TEST(ContiguousComparableMemcmpOrFail, MatchingVectorUint32)
{
    std::vector<uint32_t> actual   = {1, 2, 3, 4, 5};
    std::vector<uint32_t> expected = {1, 2, 3, 4, 5};
    memcmp_or_fail(actual, expected);   // must not fail
    SUCCEED();
}

TEST(ContiguousComparableMemcmpOrFail, MatchingArrayFloat)
{
    std::array<float, 4> actual   = {1.0f, 2.0f, 3.0f, 4.0f};
    std::array<float, 4> expected = {1.0f, 2.0f, 3.0f, 4.0f};
    memcmp_or_fail(actual, expected);
    SUCCEED();
}

TEST(ContiguousComparableMemcmpOrFail, MatchingString)
{
    std::string actual   = "hello, world";
    std::string expected = "hello, world";
    memcmp_or_fail(actual, expected);
    SUCCEED();
}

TEST(ContiguousComparableMemcmpOrFail, EmptyContainersMatch)
{
    std::vector<uint32_t> actual;
    std::vector<uint32_t> expected;
    memcmp_or_fail(actual, expected);   // zero-size byte comparison, no mismatch
    SUCCEED();
}

// ---------------------------------------------------------------------------
// Container memcmp_or_fail overload with a formatter: success-path runtime
// tests. Mismatch coverage (which would reach the [[noreturn]] report()) lives
// in the selftest_container_comparefail_* selftests in framework/selftest.cpp.
// ---------------------------------------------------------------------------

TEST(ContiguousComparableMemcmpOrFail, MatchingVectorUint32WithFormatter)
{
    std::vector<uint32_t> actual   = {1, 2, 3, 4, 5};
    std::vector<uint32_t> expected = {1, 2, 3, 4, 5};
    // On a match, the formatter is only exercised via test_formatter()'s
    // self-check (under assert()), not actually used to build a report.
    memcmp_or_fail(actual, expected, [](ptrdiff_t) -> std::string { return {}; });
    SUCCEED();
}

// ---------------------------------------------------------------------------
// Overload resolution: pointer and container shapes coexist without ambiguity
// in the same translation unit.
// ---------------------------------------------------------------------------

TEST(ContiguousComparableMemcmpOrFail, OverloadResolutionNoAmbiguity)
{
    // Pointer shape.
    uint32_t pa[4] = {10, 20, 30, 40};
    uint32_t pe[4] = {10, 20, 30, 40};
    memcmp_or_fail(pa, pe, 4);

    // Container shape.
    std::vector<uint32_t> ca = {10, 20, 30, 40};
    std::vector<uint32_t> ce = {10, 20, 30, 40};
    memcmp_or_fail(ca, ce);

    SUCCEED();
}

extern "C" void test_memcmp_long_double_c(const long double *, const long double *, size_t, int);
extern "C" int test_memcmp_equal_long_double_c(const void *, const void *, size_t);

namespace {
class LongDoubleCompare : public testing::Test
{
protected:
    static constexpr DataType TYPE = SandstoneDataDetails::TypeToDataType<long double>::Type;
    static constexpr size_t COUNT = 3;
    static constexpr size_t STRIDE = SandstoneDataDetails::type_size(TYPE);
    static constexpr size_t MEANINGFUL = SandstoneDataDetails::type_real_size(TYPE);
    std::array<long double, COUNT> actual;
    std::array<long double, COUNT> expected;
    long double pattern = 1.L;

    void fill(const long double &value)
    {
        // Only byte copies/writes follow initialization, so padding stays controlled.
        memcpy(&pattern, &value, STRIDE);
        memset(reinterpret_cast<uint8_t *>(&pattern) + MEANINGFUL, 0, STRIDE - MEANINGFUL);
        for (size_t i = 0; i < COUNT; ++i) {
            memcpy(&actual[i], &value, STRIDE);
            memcpy(&expected[i], &value, STRIDE);
            memset(reinterpret_cast<uint8_t *>(&actual[i]) + MEANINGFUL, int(i + 1), STRIDE - MEANINGFUL);
            memset(reinterpret_cast<uint8_t *>(&expected[i]) + MEANINGFUL, int(i + 4), STRIDE - MEANINGFUL);
        }
    }

    LongDoubleCompare() { fill(1.L); }
};
}

TEST_F(LongDoubleCompare, PaddingOnly)
{
    using namespace SandstoneDataDetails;
    EXPECT_LT(memcmp_offset(actual.data(), expected.data(), sizeof(actual), TYPE), 0);
    if constexpr (MEANINGFUL < STRIDE) {
        EXPECT_NE(memcmp(actual.data(), expected.data(), sizeof(actual)), 0);
        EXPECT_FALSE(memcmp_equal<UInt8Data>(actual.data(), expected.data(), sizeof(actual)));
        EXPECT_DEATH_IF_SUPPORTED(memcmp_or_fail(static_cast<const void *>(actual.data()),
                                                static_cast<const void *>(expected.data()), sizeof(actual)), "");
    }
    for (size_t count : {size_t(0), size_t(1), COUNT}) {
        memcmp_or_fail(actual.data(), expected.data(), count);
        memcmp_or_fail(actual.data(), expected.data(), count, [](ptrdiff_t) { return std::string(); });
        memcmp_or_fail(actual.data(), expected.data(), count, "typed printf comparison");
        test_memcmp_long_double_c(actual.data(), expected.data(), count, 0);
        test_memcmp_long_double_c(actual.data(), expected.data(), count, 1);
        memcmp_pattern_or_fail(actual.data(), pattern, count);
    }
    memcmp_or_fail(actual, expected);
    memcmp_or_fail(actual, expected, [](ptrdiff_t) { return std::string(); });
}

TEST_F(LongDoubleCompare, MeaningfulDifferenceAfterPadding)
{
    using namespace SandstoneDataDetails;
    reinterpret_cast<uint8_t *>(&actual[2])[1] ^= 1;
    EXPECT_EQ(memcmp_offset(actual.data(), expected.data(), sizeof(actual), TYPE), 2 * STRIDE + 1);
    EXPECT_FALSE(memcmp_equal<TYPE>(actual.data(), expected.data(), sizeof(actual)));
    memcmp_or_fail(actual.data(), expected.data(), 2);
    memcmp_pattern_or_fail(actual.data(), pattern, 2);
    EXPECT_DEATH_IF_SUPPORTED(memcmp_or_fail(actual.data(), expected.data(), COUNT), "");
    EXPECT_DEATH_IF_SUPPORTED(memcmp_or_fail(actual.data(), expected.data(), COUNT,
                                            [](ptrdiff_t) { return std::string(); }), "");
    EXPECT_DEATH_IF_SUPPORTED(memcmp_or_fail(actual.data(), expected.data(), COUNT, "printf mismatch"), "");
    EXPECT_DEATH_IF_SUPPORTED(memcmp_or_fail(actual, expected), "");
    EXPECT_DEATH_IF_SUPPORTED(memcmp_or_fail(actual, expected,
                                            [](ptrdiff_t) { return std::string(); }), "");
    EXPECT_DEATH_IF_SUPPORTED(test_memcmp_long_double_c(actual.data(), expected.data(), COUNT, 0), "");
    EXPECT_DEATH_IF_SUPPORTED(test_memcmp_long_double_c(actual.data(), expected.data(), COUNT, 1), "");
    EXPECT_DEATH_IF_SUPPORTED(memcmp_pattern_or_fail(actual.data(), pattern, COUNT), "");
}

#ifdef __linux__
TEST_F(LongDoubleCompare, InaccessiblePadding)
{
    using namespace SandstoneDataDetails;
    if constexpr (TYPE != Float80Data || MEANINGFUL == STRIDE)
        GTEST_SKIP() << "Requires padded Float80Data";

    const auto page_size = sysconf(_SC_PAGESIZE);
    ASSERT_GT(page_size, 0);
    const size_t mapping_size = size_t(page_size) * 2;
    void *mapping = mmap(nullptr, mapping_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(mapping, MAP_FAILED);
    auto unmap = [mapping_size](void *p) { munmap(p, mapping_size); };
    std::unique_ptr<void, decltype(unmap)> cleanup(mapping, unmap);
    auto *end = static_cast<uint8_t *>(mapping) + page_size;
    ASSERT_EQ(mprotect(end, size_t(page_size), PROT_NONE), 0);

    // The payload is readable, but any access to trailing padding faults.
    auto *payload = end - MEANINGFUL;
    std::array<uint8_t, MEANINGFUL> reference = {};
    memset(payload, 0, MEANINGFUL);
    EXPECT_TRUE(memcmp_equal<TYPE>(payload, reference.data(), STRIDE));
    EXPECT_TRUE(memcmp_equal<TYPE>(reference.data(), payload, STRIDE));
    EXPECT_TRUE(test_memcmp_equal_long_double_c(payload, reference.data(), STRIDE));
    EXPECT_TRUE(test_memcmp_equal_long_double_c(reference.data(), payload, STRIDE));
    EXPECT_EQ(memcmp_offset(payload, reference.data(), STRIDE, TYPE), -1);
    EXPECT_EQ(memcmp_offset(reference.data(), payload, STRIDE, TYPE), -1);

    reference.back() = 1;
    EXPECT_FALSE(memcmp_equal<TYPE>(payload, reference.data(), STRIDE));
    EXPECT_FALSE(memcmp_equal<TYPE>(reference.data(), payload, STRIDE));
    EXPECT_FALSE(test_memcmp_equal_long_double_c(payload, reference.data(), STRIDE));
    EXPECT_FALSE(test_memcmp_equal_long_double_c(reference.data(), payload, STRIDE));
    EXPECT_EQ(memcmp_offset(payload, reference.data(), STRIDE, TYPE), ptrdiff_t(MEANINGFUL - 1));
    EXPECT_EQ(memcmp_offset(reference.data(), payload, STRIDE, TYPE), ptrdiff_t(MEANINGFUL - 1));
}
#endif

TEST_F(LongDoubleCompare, PatternNaNPayload)
{
    const long double nan = std::numeric_limits<long double>::quiet_NaN();
    fill(nan);
    memcmp_pattern_or_fail(actual.data(), pattern, 1);
    memcmp_pattern_or_fail(actual.data(), pattern, COUNT);
    reinterpret_cast<uint8_t *>(&actual[0])[0] ^= 1;
    EXPECT_EQ(SandstoneDataDetails::memcmp_offset(actual.data(), expected.data(), sizeof(actual), TYPE), 0);
    EXPECT_DEATH_IF_SUPPORTED(memcmp_pattern_or_fail(actual.data(), pattern, 1), "");
    EXPECT_DEATH_IF_SUPPORTED(memcmp_pattern_or_fail(actual.data(), pattern, COUNT), "");
}

TEST_F(LongDoubleCompare, PatternSignedZero)
{
    fill(0.L);
    const long double negative_zero = -0.L;
    memcpy(&actual[0], &negative_zero, STRIDE);
    EXPECT_FALSE(SandstoneDataDetails::memcmp_equal<TYPE>(actual.data(), &pattern, STRIDE));
    EXPECT_DEATH_IF_SUPPORTED(memcmp_pattern_or_fail(actual.data(), pattern, 1), "");
    EXPECT_DEATH_IF_SUPPORTED(memcmp_pattern_or_fail(actual.data(), pattern, COUNT), "");
}
