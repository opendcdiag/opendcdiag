/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck.h"

#include <algorithm>
#include <array>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <list>
#include <iterator>
#include <memory>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

#ifdef __linux__
#  include <sys/mman.h>
#  include <unistd.h>
#endif

#include "gtest/gtest.h"

namespace {
using namespace SandstoneCrossCheck;
using namespace SandstoneDataDetails;

struct OpaqueInput { uint32_t value; };

template <typename T>
concept CanDeclareInput = requires { typename InputKey<T>; };

template <typename T, typename R>
concept CanSetInputRange = CanDeclareInput<T> && requires(InputKey<T> tag, const R &range) {
    set_input(tag, range);
    set_input(tag, range, "description");
};

template <typename T, typename P>
concept CanSetInputPointer = CanDeclareInput<T> && requires(InputKey<T> tag, P pointer) {
    set_input(tag, pointer, size_t(1));
    set_input(tag, pointer, size_t(1), "description");
};

static_assert(CanDeclareInput<uint32_t>);
static_assert(CanDeclareInput<bool>);
static_assert(!CanDeclareInput<void>);
static_assert(!CanDeclareInput<const uint32_t>);
static_assert(!CanDeclareInput<volatile uint32_t>);
static_assert(!CanDeclareInput<OpaqueInput>);
static_assert(CanSetInputRange<uint32_t, std::vector<uint32_t>>);
static_assert(CanSetInputRange<uint32_t, std::array<uint32_t, 3>>);
static_assert(CanSetInputRange<uint32_t, uint32_t[3]>);
static_assert(CanSetInputRange<uint32_t, const uint32_t[3]>);
static_assert(CanSetInputRange<uint32_t, std::span<const uint32_t>>);
static_assert(CanSetInputRange<char, std::string>);
static_assert(CanSetInputRange<bool, bool[3]>);
static_assert(!CanSetInputRange<uint32_t, std::vector<uint16_t>>);
static_assert(!CanSetInputRange<uint32_t, std::list<uint32_t>>);
static_assert(!CanSetInputRange<bool, std::vector<bool>>);
static_assert(!CanSetInputRange<uint8_t, std::array<bool, 3>>);
static_assert(!CanSetInputRange<bool, std::array<uint8_t, 3>>);
static_assert(!CanSetInputRange<uint32_t, std::vector<OpaqueInput>>);
static_assert(!CanSetInputRange<uint32_t, std::span<volatile uint32_t>>);
static_assert(!CanSetInputRange<uint32_t, volatile uint32_t[3]>);
static_assert(CanSetInputPointer<uint32_t, uint32_t *>);
static_assert(CanSetInputPointer<uint32_t, const uint32_t *>);
static_assert(!CanSetInputPointer<uint32_t, uint16_t *>);
static_assert(!CanSetInputPointer<uint8_t, bool *>);
static_assert(!CanSetInputPointer<bool, uint8_t *>);
static_assert(!CanSetInputPointer<uint32_t, void *>);
static_assert(!CanSetInputPointer<uint32_t, OpaqueInput *>);
static_assert(!CanSetInputPointer<uint32_t, volatile uint32_t *>);

CROSSCHECK_INPUT(crosscheck_words, uint32_t);
CROSSCHECK_INPUT(crosscheck_flags, bool);
static_assert(std::same_as<decltype(crosscheck_words), const InputKey<uint32_t>>);
static_assert(std::same_as<decltype(get_input(crosscheck_words)), std::span<const uint32_t>>);
static_assert(std::same_as<decltype(get_input(crosscheck_flags)), std::span<const bool>>);
static_assert(TypeToDataType<bool>::Type == TypeToDataType<uint8_t>::Type);

template <typename T>
std::span<const T> typed_view(const CapturedSlot &slot)
{
    // This is the same typed storage view returned by get_input, without the
    // framework lifecycle lookup (which is covered by cross-check selftests).
    return {static_cast<const T *>(slot.storage.get()), slot.count};
}

TEST(CrossCheckInput, OwnsCopyAfterSourceMutation)
{
    std::array<uint32_t, 3> source = {11, 22, 33};
    auto slot = make_captured_slot(source.data(), source.size());
    auto values = typed_view<uint32_t>(slot);
    EXPECT_NE(values.data(), source.data());
    source.fill(99);
    ASSERT_EQ(values.size(), 3);
    EXPECT_EQ(values[0], 11);
    EXPECT_EQ(values[1], 22);
    EXPECT_EQ(values[2], 33);
}

TEST(CrossCheckInput, OwnsCopyAfterSourceDestruction)
{
    auto slot = [] {
        std::vector<int32_t> source = {-7, 42, 100};
        return make_captured_slot(source.data(), source.size());
    }();
    auto values = typed_view<int32_t>(slot);
    ASSERT_EQ(values.size(), 3);
    EXPECT_EQ(values[0], -7);
    EXPECT_EQ(values[1], 42);
    EXPECT_EQ(values[2], 100);
}

TEST(CrossCheckInput, MetadataAndDescriptionAreOwned)
{
    const uint64_t source[] = {1, 2};
    auto slot = [&] {
        std::string description = "original input";
        auto result = make_captured_slot(source, 2, description.c_str());
        description.assign("changed");
        return result;
    }();
    EXPECT_EQ(slot.count, 2);
    EXPECT_EQ(slot.type, UInt64Data);
    EXPECT_EQ(slot.type_token, &CAPTURE_TYPE_TOKEN<uint64_t>);
    EXPECT_EQ(slot.description, "original input");
    EXPECT_EQ(make_captured_slot(source, 2).description, "");
    EXPECT_EQ(make_captured_slot(source, 2, "").description, "");
    EXPECT_STREQ(crosscheck_words.name, "crosscheck_words");
}

TEST(CrossCheckInput, EmptyNullInput)
{
    auto slot = make_captured_slot<uint32_t>(nullptr, 0, "empty");
    EXPECT_EQ(slot.storage.get(), nullptr);
    EXPECT_EQ(slot.count, 0);
    EXPECT_EQ(slot.type, UInt32Data);
    EXPECT_EQ(slot.type_token, &CAPTURE_TYPE_TOKEN<uint32_t>);
    EXPECT_EQ(slot.description, "empty");
    EXPECT_TRUE(typed_view<uint32_t>(slot).empty());
    EXPECT_EQ(slot.bytes().data(), nullptr);
    EXPECT_TRUE(slot.bytes().empty());
}

TEST(CrossCheckInput, BoolArrayUsesRealTypedStorage)
{
    bool source[] = {true, false, true, false};
    auto slot = make_captured_slot(source, std::size(source));
    source[0] = false;
    auto values = typed_view<bool>(slot);
    ASSERT_EQ(values.size(), 4);
    EXPECT_TRUE(values[0]);
    EXPECT_FALSE(values[1]);
    EXPECT_TRUE(values[2]);
    EXPECT_FALSE(values[3]);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(values.data()) % alignof(bool), 0);
}

TEST(CrossCheckInput, AlignmentFor128BitElements)
{
    const __uint128_t source[] = {(__uint128_t(1) << 100) | 7, ~__uint128_t(0)};
    auto slot = make_captured_slot(source, std::size(source));
    auto values = typed_view<__uint128_t>(slot);
    ASSERT_EQ(values.size(), 2);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(values.data()) % alignof(__uint128_t), 0);
    EXPECT_TRUE(values[0] == source[0]);
    EXPECT_TRUE(values[1] == source[1]);
    EXPECT_EQ(slot.type, UInt128Data);
    EXPECT_EQ(slot.type_token, &CAPTURE_TYPE_TOKEN<__uint128_t>);
}

TEST(CrossCheckInput, ByteViewUsesElementCountAndOwnedPointer)
{
    const uint32_t source[] = {0x12345678, 0xabcdef01, 0};
    auto slot = make_captured_slot(source, std::size(source));
    auto bytes = slot.bytes();
    EXPECT_EQ(bytes.data(), slot.storage.get());
    ASSERT_EQ(bytes.size(), sizeof(source));
    EXPECT_EQ(std::memcmp(bytes.data(), source, bytes.size()), 0);
}

constexpr DataType LongDoubleType = TypeToDataType<long double>::Type;
constexpr size_t LongDoublePayload = type_real_size(LongDoubleType);

TEST(CrossCheckInput, LongDoublePaddingIsNormalizedDeterministically)
{
    if constexpr (LongDoublePayload == sizeof(long double))
        GTEST_SKIP() << "Requires trailing long double padding";

    std::array<long double, 3> first = {1.L, -2.L, 3.L};
    std::array<long double, 3> second;
    for (size_t i = 0; i < first.size(); ++i) {
        std::memcpy(&second[i], &first[i], sizeof(long double));
        std::memset(reinterpret_cast<unsigned char *>(&first[i]) + LongDoublePayload,
                    0xa5, sizeof(long double) - LongDoublePayload);
        std::memset(reinterpret_cast<unsigned char *>(&second[i]) + LongDoublePayload,
                    0x5a, sizeof(long double) - LongDoublePayload);
    }
    ASSERT_NE(std::memcmp(first.data(), second.data(), sizeof(first)), 0);
    auto a = make_captured_slot(first.data(), first.size());
    auto b = make_captured_slot(second.data(), second.size());
    ASSERT_EQ(a.bytes().size(), sizeof(first));
    EXPECT_EQ(std::memcmp(a.bytes().data(), b.bytes().data(), a.bytes().size()), 0);
    auto values = typed_view<long double>(a);
    for (size_t i = 0; i < first.size(); ++i) {
        EXPECT_EQ(values[i], first[i]);
        const auto element = a.bytes().subspan(i * sizeof(long double), sizeof(long double));
        EXPECT_TRUE(std::all_of(element.begin() + LongDoublePayload, element.end(),
                                [](std::byte b) { return b == std::byte{0}; }));
        EXPECT_EQ(std::memcmp(&values[i], &first[i], LongDoublePayload), 0);
    }
}

TEST(CrossCheckInput, LongDoubleMeaningfulSignedZeroAndNaNBitsArePreserved)
{
    const long double source[] = {0.L, -0.L, std::numeric_limits<long double>::quiet_NaN(),
                                 std::numeric_limits<long double>::signaling_NaN()};
    auto slot = make_captured_slot(source, std::size(source));
    auto again = make_captured_slot(typed_view<long double>(slot).data(), slot.count);
    auto values = typed_view<long double>(slot);
    for (size_t i = 0; i < std::size(source); ++i)
        EXPECT_EQ(std::memcmp(&values[i], &source[i], LongDoublePayload), 0);
    EXPECT_NE(std::memcmp(&values[0], &values[1], LongDoublePayload), 0);
    EXPECT_EQ(std::memcmp(slot.bytes().data(), again.bytes().data(), slot.bytes().size()), 0);
}

TEST(CrossCheckInput, FloatNaNPayloadsAndSignedZeroArePreserved)
{
    static_assert(sizeof(float) == sizeof(uint32_t));
    const std::array<uint32_t, 5> bits = {0, 0x80000000, 0x7fc12345, 0x7fc54321, 0x7f812345};
    const auto source = std::bit_cast<std::array<float, 5>>(bits);
    auto slot = make_captured_slot(source.data(), source.size());
    ASSERT_EQ(slot.bytes().size(), sizeof(bits));
    EXPECT_EQ(std::memcmp(slot.bytes().data(), bits.data(), sizeof(bits)), 0);
    auto again = make_captured_slot(typed_view<float>(slot).data(), slot.count);
    EXPECT_EQ(std::memcmp(slot.bytes().data(), again.bytes().data(), sizeof(bits)), 0);
}

TEST(CrossCheckInput, DoesNotReadInaccessibleLongDoublePadding)
{
#ifdef __linux__
    if constexpr (LongDoublePayload == sizeof(long double))
        GTEST_SKIP() << "Requires trailing long double padding";
    const auto page_size = sysconf(_SC_PAGESIZE);
    ASSERT_GT(page_size, 0);
    // Do not manufacture a misaligned long double pointer merely to test a
    // byte-copy implementation: make_captured_slot's storage contract is typed.
    if (size_t(page_size) % alignof(long double) != LongDoublePayload % alignof(long double))
        GTEST_SKIP() << "A page-boundary payload would require a misaligned long double";
    const size_t mapping_size = size_t(page_size) * 2;
    void *mapping = mmap(nullptr, mapping_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(mapping, MAP_FAILED);
    auto unmap = [mapping_size](void *p) { munmap(p, mapping_size); };
    std::unique_ptr<void, decltype(unmap)> cleanup(mapping, unmap);
    auto *boundary = static_cast<unsigned char *>(mapping) + page_size;
    ASSERT_EQ(mprotect(boundary, size_t(page_size), PROT_NONE), 0);
    auto *payload = boundary - LongDoublePayload;
    const long double reference = 1.L;
    std::memcpy(payload, &reference, LongDoublePayload);
    auto slot = make_captured_slot(reinterpret_cast<const long double *>(payload), 1);
    EXPECT_EQ(typed_view<long double>(slot)[0], reference);
    EXPECT_EQ(std::memcmp(slot.bytes().data(), &reference, LongDoublePayload), 0);
#else
    GTEST_SKIP() << "Requires Linux guard pages";
#endif
}

} // namespace
