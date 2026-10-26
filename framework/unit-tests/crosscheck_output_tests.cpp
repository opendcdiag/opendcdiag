/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck_state.hpp"
#include "crosscheck_output_peer.hpp"
#include "fp_vectors/Floats.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include "gtest/gtest.h"

namespace {
using namespace SandstoneCrossCheck;
using namespace SandstoneDataDetails;

TEST(CrossCheckOutput, InitOwnsDataNameAndDescription)
{
    CrossCheckState state;
    state.reset(2);
    state.phase = CrossCheckState::Phase::Initializing;
    {
        std::vector<uint32_t> source = {11, 22, 33};
        std::string name = "words";
        std::string description = "golden words";
        state.submit_init(name.c_str(), source.data(), source.size(), description.c_str());
        source.assign(3, 99);
        name.assign("changed");
        description.assign("changed");
    }
    const auto &slot = state.init_outputs.at("words");
    const uint32_t expected[] = {11, 22, 33};
    EXPECT_EQ(compare_output(slot, expected, 3), OutputMatch::Equal);
    EXPECT_EQ(slot.description, "golden words");
    EXPECT_EQ(slot.type, UInt32Data);
    EXPECT_EQ(slot.type_token, &CAPTURE_TYPE_TOKEN<uint32_t>);
    EXPECT_FALSE(state.worker_outputs[0]);
    EXPECT_FALSE(state.worker_outputs[1]);
}

TEST(CrossCheckOutput, WorkersOwnIndependentImmutableFirstReferences)
{
    CrossCheckState state;
    state.reset(2);
    state.phase = CrossCheckState::Phase::Initializing;
    const uint32_t golden[] = {1, 2};
    state.submit_init("words", golden, 2, "init description");
    state.phase = CrossCheckState::Phase::Running;
    {
        std::vector<uint32_t> source = {3, 4};
        // A wrong first submission is saved, not compared with the golden output yet.
        EXPECT_EQ(state.submit_output(0, "words", source.data(), 2, "ignored"), OutputMatch::First);
        source.assign(2, 99);
    }
    ASSERT_TRUE(state.worker_outputs[0]);
    EXPECT_FALSE(state.worker_outputs[1]);
    const auto &first = state.worker_outputs[0]->at("words");
    auto *saved = first.storage.get();
    const uint32_t repeated[] = {3, 4};
    for (int i = 0; i < 3; ++i)
        EXPECT_EQ(state.submit_output(0, "words", repeated, 2, nullptr), OutputMatch::Equal);
    EXPECT_EQ(state.submit_output(0, "words", golden, 2, "override"), OutputMatch::DataMismatch);
    EXPECT_EQ(state.submit_output(0, "words", golden, 1, nullptr), OutputMatch::CountMismatch);
    EXPECT_EQ(first.storage.get(), saved);
    EXPECT_EQ(first.storage.use_count(), 1);
    EXPECT_EQ(first.count, 2);
    EXPECT_EQ(compare_output(first, repeated, 2), OutputMatch::Equal);
    EXPECT_EQ(first.description, "ignored");
    EXPECT_EQ(state.init_outputs.at("words").description, "init description");
    EXPECT_EQ(state.submit_output(1, "words", golden, 2, nullptr), OutputMatch::First);
    EXPECT_NE(state.worker_outputs[1]->at("words").storage.get(), saved);
    EXPECT_EQ(compare_output(state.init_outputs.at("words"), first.storage.get(), first.count),
              OutputMatch::DataMismatch);
}

TEST(CrossCheckOutput, FirstWorkerTypeIsIndependentOfInit)
{
    CrossCheckState state;
    state.reset(1);
    state.phase = CrossCheckState::Phase::Initializing;
    const uint32_t value = 42;
    state.submit_init("words", &value, 1, nullptr);
    state.phase = CrossCheckState::Phase::Running;

    auto unknown = state.output_submission(0, "unknown");
    EXPECT_FALSE(state.worker_outputs[0]);
    EXPECT_FALSE(unknown.existing);

    auto submission = state.output_submission(0, "words");
    EXPECT_FALSE(state.worker_outputs[0]);
    EXPECT_FALSE(submission.existing);
    const uint8_t wrong_type = 42;
    EXPECT_EQ(submission.submit(&wrong_type, 1, nullptr), OutputMatch::First);
    ASSERT_TRUE(state.worker_outputs[0]);
    EXPECT_EQ(state.worker_outputs[0]->size(), 1);
    EXPECT_EQ(state.submit_output(0, "words", &value, 1, nullptr), OutputMatch::TypeMismatch);
}

TEST(CrossCheckOutput, ExactIdentitySurvivesTranslationUnits)
{
    auto flag = crosscheck_output_peer_bool();
    auto byte = crosscheck_output_peer_byte();
    auto native = crosscheck_output_peer_float();
    auto wrapper = crosscheck_output_peer_wrapper();
    EXPECT_EQ(flag.type_token, &CAPTURE_TYPE_TOKEN<bool>);
    EXPECT_EQ(byte.type_token, &CAPTURE_TYPE_TOKEN<uint8_t>);
    EXPECT_EQ(native.type_token, &CAPTURE_TYPE_TOKEN<float>);
    EXPECT_EQ(wrapper.type_token, &CAPTURE_TYPE_TOKEN<Float32>);
    EXPECT_EQ(flag.type, byte.type);
    EXPECT_NE(flag.type_token, byte.type_token);
    EXPECT_EQ(native.type, wrapper.type);
    EXPECT_NE(native.type_token, wrapper.type_token);
}

TEST(CrossCheckOutput, InitHasOneImmutableVoteAndKeepsItsOwnMetadata)
{
    CrossCheckState state;
    state.reset(2);
    state.phase = CrossCheckState::Phase::Initializing;
    uint32_t value = 17;
    EXPECT_EQ(state.submit_init("words", &value, 1, "init"), OutputMatch::First);
    EXPECT_EQ(state.submit_init("words", &value, 1, "replacement"), OutputMatch::Equal);
    ++value;
    EXPECT_EQ(state.submit_init("words", &value, 1, nullptr), OutputMatch::DataMismatch);
    EXPECT_EQ(state.init_outputs.size(), 1);
    EXPECT_EQ(state.init_outputs.at("words").description, "init");
}

TEST(CrossCheckOutput, StrictMajorityIsNotArrivalOrderOrPlurality)
{
    uint32_t a = 1, b = 2, c = 3;
    auto A = make_captured_slot(&a, 1);
    auto B = make_captured_slot(&b, 1);
    auto C = make_captured_slot(&c, 1);
    for (auto slots : {std::vector<const CapturedSlot *>{&B, &A, &A},
                       std::vector<const CapturedSlot *>{&A, &B, &A},
                       std::vector<const CapturedSlot *>{&A, &A, &B}}) {
        ASSERT_NE(find_majority(slots), nullptr);
        EXPECT_EQ(compare_output(A, find_majority(slots)), OutputMatch::Equal);
    }
    for (auto slots : {std::vector<const CapturedSlot *>{},
                       std::vector<const CapturedSlot *>{&A, &B},
                       std::vector<const CapturedSlot *>{&A, &A, &B, &B},
                       std::vector<const CapturedSlot *>{&A, &A, &B, &B, &C},
                       std::vector<const CapturedSlot *>{&A, &B, &C}})
        EXPECT_EQ(find_majority(slots), nullptr);
}

TEST(CrossCheckOutput, FirstSnapshotsAndNamesAreIndependentOfArrivalOrder)
{
    CrossCheckState state;
    state.reset(4);
    state.phase = CrossCheckState::Phase::Running;
    for (size_t worker : {3, 2, 1, 0}) {
        uint32_t value = worker == 0 ? 1 : 2;
        EXPECT_EQ(state.submit_output(worker, "z", &value, 1, "first description"), OutputMatch::First);
        EXPECT_EQ(state.submit_output(worker, "a", &value, 1, nullptr), OutputMatch::First);
        value = 99;
    }
    const auto &names = *state.worker_outputs[0];
    ASSERT_EQ(names.size(), 2);
    EXPECT_EQ(names.begin()->first, "a");
    EXPECT_EQ(names.rbegin()->first, "z");
    for (const auto &[name, reference] : names) {
        EXPECT_EQ(compare_output(reference, &reference), OutputMatch::Equal);
        for (size_t worker = 1; worker < 4; ++worker)
            EXPECT_EQ(compare_output(reference, &state.worker_outputs[worker]->at(name)),
                      OutputMatch::DataMismatch);
    }
    EXPECT_EQ(names.at("z").description, "first description");
    uint32_t value = 1;
    EXPECT_EQ(state.submit_output(0, "z", &value, 1, "replacement"), OutputMatch::Equal);
    EXPECT_EQ(names.at("z").description, "first description");
    state.reset(2);
    EXPECT_FALSE(state.worker_outputs[0]);
    EXPECT_FALSE(state.worker_outputs[1]);
}

TEST(CrossCheckOutput, ConsensusMissingCountAndExactTypeAreSafe)
{
    CrossCheckState state;
    state.reset(2);
    state.phase = CrossCheckState::Phase::Running;
    const uint32_t value[] = {1, 2};
    state.submit_output(1, "only_other", value, 2, nullptr);
    EXPECT_FALSE(state.worker_outputs[0]);
    EXPECT_TRUE(state.worker_outputs[1]->contains("only_other"));
    state.submit_output(0, "words", value, 2, nullptr);
    auto *reference = &state.worker_outputs[0]->at("words");
    EXPECT_EQ(compare_output(*reference, nullptr), OutputMatch::Missing);
    auto short_slot = make_captured_slot(value, 1);
    EXPECT_EQ(compare_output(*reference, &short_slot), OutputMatch::CountMismatch);
    const uint8_t bytes[] = {1, 2};
    auto wrong_type = make_captured_slot(bytes, 2);
    EXPECT_EQ(compare_output(*reference, &wrong_type), OutputMatch::TypeMismatch);
    EXPECT_EQ(state.submit_output(0, "words", bytes, 2, nullptr), OutputMatch::TypeMismatch);
    const bool flag = true;
    state.submit_output(0, "flag", &flag, 1, nullptr);
    EXPECT_EQ(state.submit_output(0, "flag", bytes, 1, nullptr), OutputMatch::TypeMismatch);
}

TEST(CrossCheckOutput, MultipleNamesKeepFirstCountsAndSubmissionOrderIndependent)
{
    CrossCheckState state;
    state.reset(2);
    state.phase = CrossCheckState::Phase::Initializing;
    const uint32_t words[] = {1, 2};
    const uint32_t other[] = {3};
    state.submit_init("words", words, 2, nullptr);
    state.submit_init("other", other, 1, "other output");
    state.phase = CrossCheckState::Phase::Running;
    EXPECT_EQ(state.submit_output(0, "other", other, 1, nullptr), OutputMatch::First);
    EXPECT_EQ(state.submit_output(0, "words", words, 1, nullptr), OutputMatch::First);
    EXPECT_EQ(state.submit_output(1, "words", words, 2, nullptr), OutputMatch::First);
    EXPECT_EQ(state.submit_output(1, "other", other, 1, nullptr), OutputMatch::First);
    const auto &first = state.worker_outputs[0]->at("words");
    EXPECT_EQ(compare_output(state.init_outputs.at("words"), first.storage.get(), first.count),
              OutputMatch::CountMismatch);
    EXPECT_EQ(state.submit_output(0, "words", words, 2, nullptr), OutputMatch::CountMismatch);
    EXPECT_EQ(first.count, 1);
    EXPECT_EQ(state.submit_output(0, "other", other, 1, "ignored"), OutputMatch::Equal);
    EXPECT_EQ(state.submit_output(1, "words", words, 2, nullptr), OutputMatch::Equal);
    EXPECT_EQ(state.submit_output(1, "other", other, 1, nullptr), OutputMatch::Equal);
}

TEST(CrossCheckOutput, CountPrecedesAnyDataAccessAndEmptyIsSafe)
{
    const uint32_t source[] = {1, 2};
    auto slot = make_captured_slot(source, 2, nullptr);
    EXPECT_EQ(compare_output(slot, nullptr, 0), OutputMatch::CountMismatch);
    EXPECT_EQ(compare_output(slot, nullptr, 3), OutputMatch::CountMismatch);
    auto empty = make_captured_slot<uint32_t>(nullptr, 0, nullptr);
    EXPECT_FALSE(empty.storage);
    EXPECT_TRUE(empty.bytes().empty());
    EXPECT_EQ(compare_output(empty, nullptr, 0), OutputMatch::Equal);

    CrossCheckState state;
    state.reset(1);
    state.phase = CrossCheckState::Phase::Initializing;
    state.submit_init<uint32_t>("empty", nullptr, 0, nullptr);
    state.phase = CrossCheckState::Phase::Running;
    EXPECT_EQ(state.submit_output<uint32_t>(0, "empty", nullptr, 0, nullptr), OutputMatch::First);
    EXPECT_EQ(state.submit_output<uint32_t>(0, "empty", nullptr, 0, nullptr), OutputMatch::Equal);
}

#ifndef NDEBUG
TEST(CrossCheckOutput, RejectsCountJustBeyondPtrdiffByteLimit)
{
    const uint32_t source = 1;
    const size_t count = size_t(std::numeric_limits<ptrdiff_t>::max() - 1) / sizeof(source) + 1;
    EXPECT_DEATH_IF_SUPPORTED(make_captured_slot(&source, count), "count <=");

    CrossCheckState state;
    state.reset(1);
    state.phase = CrossCheckState::Phase::Running;
    state.submit_output(0, "words", &source, 1, nullptr);
    EXPECT_DEATH_IF_SUPPORTED(state.submit_output(0, "words", &source, count, nullptr), "count <=");

    auto slot = make_captured_slot(&source, 1);
    slot.count = count;
    EXPECT_DEATH_IF_SUPPORTED(slot.bytes(), "count <=");
    EXPECT_DEATH_IF_SUPPORTED(compare_output(slot, &source, count), "count <=");
}

TEST(CrossCheckOutput, RejectsPtrdiffMaxEvenForSingleByteElements)
{
    const uint8_t source = 1;
    const size_t count = size_t(std::numeric_limits<ptrdiff_t>::max());
    EXPECT_DEATH_IF_SUPPORTED(make_captured_slot(&source, count), "count <=");
}
#endif

TEST(CrossCheckOutput, FloatComparisonPreservesNaNBitsAndSignedZero)
{
    const std::array<uint32_t, 5> bits = {0, 0x80000000, 0x7fc12345, 0x7fc54321, 0x7f812345};
    auto source = std::bit_cast<std::array<float, 5>>(bits);
    auto slot = make_captured_slot(source.data(), source.size(), nullptr);
    EXPECT_EQ(std::memcmp(slot.storage.get(), bits.data(), sizeof(bits)), 0);
    EXPECT_EQ(compare_output(slot, source.data(), source.size()), OutputMatch::Equal);
    auto peer = make_captured_slot(source.data(), source.size());
    EXPECT_EQ(compare_output(slot, &peer), OutputMatch::Equal);
    auto changed = bits;
    changed[0] = bits[1];
    auto actual = std::bit_cast<std::array<float, 5>>(changed);
    EXPECT_EQ(compare_output(slot, actual.data(), actual.size()), OutputMatch::DataMismatch);
    peer = make_captured_slot(actual.data(), actual.size());
    EXPECT_EQ(compare_output(slot, &peer), OutputMatch::DataMismatch);
    changed = bits;
    changed[2] = bits[3];
    actual = std::bit_cast<std::array<float, 5>>(changed);
    EXPECT_EQ(compare_output(slot, actual.data(), actual.size()), OutputMatch::DataMismatch);
}

TEST(CrossCheckOutput, MultiElementLongDoublePaddingIsNormalizedAndIgnored)
{
    constexpr size_t meaningful = type_real_size(TypeToDataType<long double>::Type);
    if constexpr (meaningful == sizeof(long double))
        GTEST_SKIP() << "Requires trailing long double padding";

    std::array<long double, 4> source = {0.L, -0.L,
            std::numeric_limits<long double>::quiet_NaN(),
            std::numeric_limits<long double>::signaling_NaN()};
    for (auto &value : source)
        std::memset(reinterpret_cast<unsigned char *>(&value) + meaningful,
                    0xa5, sizeof(long double) - meaningful);
    auto golden = make_captured_slot(source.data(), source.size(), nullptr);
    auto first = make_captured_slot(source.data(), source.size(), nullptr);
    auto bytes = golden.bytes();
    for (size_t i = 0; i < source.size(); ++i) {
        EXPECT_EQ(std::memcmp(bytes.data() + i * sizeof(long double), &source[i], meaningful), 0);
        auto padding = bytes.subspan(i * sizeof(long double) + meaningful,
                                     sizeof(long double) - meaningful);
        EXPECT_TRUE(std::all_of(padding.begin(), padding.end(),
                                [](std::byte b) { return b == std::byte{0}; }));
    }
    EXPECT_EQ(std::memcmp(golden.storage.get(), first.storage.get(), bytes.size()), 0);
    EXPECT_EQ(compare_output(first, source.data(), source.size()), OutputMatch::Equal);
    EXPECT_EQ(compare_output(golden, &first), OutputMatch::Equal);
    // Mutate a meaningful byte in a later element without floating load/store.
    auto *changed = reinterpret_cast<unsigned char *>(&source[2]);
    changed[0] ^= 1;
    EXPECT_EQ(compare_output(first, source.data(), source.size()), OutputMatch::DataMismatch);
    auto changed_slot = make_captured_slot(source.data(), source.size());
    EXPECT_EQ(compare_output(first, &changed_slot), OutputMatch::DataMismatch);
    EXPECT_EQ(memcmp_offset(source.data(), first.storage.get(), sizeof(source), first.type),
              ptrdiff_t(2 * sizeof(long double)));
}

TEST(CrossCheckOutput, ResetReleasesCapturedStorageAndClearsPhase)
{
    CrossCheckState state;
    EXPECT_EQ(state.phase, CrossCheckState::Phase::Inactive);
    const uint32_t source[] = {1, 2};
    for (auto phase : {CrossCheckState::Phase::Inactive, CrossCheckState::Phase::Initializing,
                       CrossCheckState::Phase::Running}) {
        state.reset(2);
        state.inputs.emplace("input", make_captured_slot(source, 2));
        state.phase = CrossCheckState::Phase::Initializing;
        state.submit_init("words", source, 2, "reset me");
        state.phase = CrossCheckState::Phase::Running;
        state.submit_output(0, "words", source, 2, nullptr);
        state.submit_output(1, "words", source, 2, nullptr);
        std::weak_ptr<const void> input = state.inputs.at("input").storage;
        std::weak_ptr<const void> golden = state.init_outputs.at("words").storage;
        std::weak_ptr<const void> worker0 = state.worker_outputs[0]->at("words").storage;
        std::weak_ptr<const void> worker1 = state.worker_outputs[1]->at("words").storage;
        state.phase = phase;
        state.reset(1);
        EXPECT_TRUE(input.expired());
        EXPECT_TRUE(golden.expired());
        EXPECT_TRUE(worker0.expired());
        EXPECT_TRUE(worker1.expired());
        EXPECT_TRUE(state.inputs.empty());
        EXPECT_TRUE(state.init_outputs.empty());
        ASSERT_EQ(state.worker_outputs.size(), 1);
        EXPECT_FALSE(state.worker_outputs[0]);
        EXPECT_EQ(state.phase, CrossCheckState::Phase::Inactive);
    }
    for (int i = 0; i < 2; ++i) {
        state.reset();
        EXPECT_TRUE(state.inputs.empty());
        EXPECT_TRUE(state.init_outputs.empty());
        EXPECT_TRUE(state.worker_outputs.empty());
        EXPECT_EQ(state.phase, CrossCheckState::Phase::Inactive);
    }
}

} // namespace
