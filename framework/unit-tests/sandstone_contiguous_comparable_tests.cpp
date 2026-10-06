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
#include <list>
#include <span>
#include <string>
#include <vector>

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
