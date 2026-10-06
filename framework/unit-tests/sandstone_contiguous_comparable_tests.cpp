/*
 * Copyright 2024 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

// SandstoneCrossCheck::ContiguousComparable concept and the container
// memcmp_or_fail overload. Failure-path coverage (size and content mismatch)
// lives in the selftest_container_comparefail_* selftests in
// framework/selftest.cpp, because _report_fail_msg is [[noreturn]] and depends
// on sApp->shmem and so cannot be exercised from a plain gtest. This TU covers
// the compile-time concept checks and the success-path runtime behavior.

#include "sandstone.h"

#include <array>
#include <cstdlib>
#include <list>
#include <span>
#include <string>
#include <vector>

#include "gtest/gtest.h"

// The unittest binary does not link sandstone_run.cpp, which defines
// _report_fail_msg and SandstoneMemcmpOrFail::report. The success-path tests
// below never reach those symbols at runtime, but instantiating the container
// memcmp_or_fail overload references them. Provide noreturn stubs so the TU
// links; they abort() if ever reached, which would be a test failure.
// Failure-path coverage lives in the selftest_container_comparefail_*
// selftests in framework/selftest.cpp, which run against the full binary.
extern "C" void _report_fail_msg(const char *, int, const char *, ...)
{
    std::abort();
}
namespace SandstoneMemcmpOrFail {
[[noreturn, gnu::cold]] void
report(const void *, const void *, size_t, DataType, FormatterCallback,
       const void *, void *)
{
    std::abort();
}
// test_formatter() is only called on the match path (assert()-gated
// self-check of the formatter callback), which these success-path tests do
// reach; it's not [[noreturn]] upstream, so just run the callback for real.
bool test_formatter(std::function<std::string ()> cb, size_t)
{
    cb();
    return true;
}
bool test_formatter(std::function<std::string (ptrdiff_t)> cb, size_t)
{
    cb(0);
    return true;
}
} // namespace SandstoneMemcmpOrFail

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
static_assert(!SandstoneCrossCheck::ContiguousComparable<std::vector<std::vector<int>>>); // element not trivially copyable
static_assert(!SandstoneCrossCheck::ContiguousComparable<std::list<int>>);         // not contiguous
static_assert(!SandstoneCrossCheck::ContiguousComparable<int>);                    // not a range
struct NotARange {};
static_assert(!SandstoneCrossCheck::ContiguousComparable<NotARange>);              // not a range

// Trivially-copyable struct element: satisfies the concept, has no
// TypeToDataType specialization, so the byte-reinterpret comparison path is
// the only available one. Used by the runtime tests below.
struct OpaqueTrivial {
    uint32_t a;
    uint16_t b;
    uint8_t  c;
    uint8_t  pad;
};
static_assert(std::is_trivially_copyable_v<OpaqueTrivial>);
static_assert(SandstoneCrossCheck::ContiguousComparable<std::vector<OpaqueTrivial>>);

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

TEST(ContiguousComparableMemcmpOrFail, MatchingOpaqueTrivialStructContainer)
{
    std::vector<OpaqueTrivial> actual   = {{1, 2, 3, 0}, {4, 5, 6, 0}};
    std::vector<OpaqueTrivial> expected = {{1, 2, 3, 0}, {4, 5, 6, 0}};
    memcmp_or_fail(actual, expected);   // byte-reinterpret path, no DataType
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
