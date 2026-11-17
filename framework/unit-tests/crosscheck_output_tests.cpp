/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck_state.hpp"
#include "crosscheck_output_peer.hpp"
#include "fp_vectors/Floats.h"
#include "test_data.h"

#include <array>
#include <atomic>
#include <barrier>
#include <bit>
#include <cstdint>
#include <cstring>
#include <numeric>
#include <set>
#include <thread>

#include "gtest/gtest.h"

namespace {
using namespace SandstoneCrossCheck;
using namespace SandstoneDataDetails;

constexpr LogicalProcessor CpuA{42}, CpuB{99}, CpuC{43}, CpuD{44};

template<typename T>
OutputMatch submit_output(CrossCheckState &state, size_t owner, const char *name, const T *data,
                          size_t count, const char *description, int worker = 0,
                          LogicalProcessor cpu = LogicalProcessor::None)
{
    return state.output_submission(owner, name, worker, cpu).submit(data, count, description);
}

TEST(CrossCheckOutput, InitAndWorkerShareImmutableOwnerSnapshot)
{
    CrossCheckState state;
    state.reset(2);
    {
        std::vector<uint32_t> source = {11, 22, 33};
        std::string name = "words", description = "first description";
        EXPECT_EQ(submit_output(state, 1, name.c_str(), source.data(), source.size(),
                                description.c_str(), -1, CpuA), OutputMatch::First);
        source.assign(3, 99);
        name.assign("changed");
        description.assign("changed");
    }
    const uint32_t equal[] = {11, 22, 33}, different[] = {1, 2, 3};
    const auto &slot = *state.owner_outputs[1].find("words");
    const void *storage = slot.storage.get();
    EXPECT_EQ(submit_output(state, 1, "words", equal, 3, "replacement", 0, CpuA), OutputMatch::Equal);
    EXPECT_EQ(submit_output(state, 1, "words", different, 3, nullptr, 1, CpuA), OutputMatch::DataMismatch);
    EXPECT_EQ(submit_output(state, 1, "words", equal, 2, nullptr), OutputMatch::CountMismatch);
    EXPECT_EQ(slot.storage.get(), storage);
    EXPECT_EQ(slot.description, "first description");
    EXPECT_EQ(slot.first_worker, -1);
    EXPECT_EQ(slot.cpu, CpuA);
    EXPECT_EQ(slot.storage.use_count(), 1);
    EXPECT_EQ(state.owner_outputs[1].head.load()->next, nullptr);
    EXPECT_EQ(state.owner_outputs[0].head.load(), nullptr);
    const auto results = state.classify_outputs();
    ASSERT_EQ(results.size(), 1);
    ASSERT_EQ(results[0].groups.size(), 1);
    EXPECT_EQ(results[0].groups[0].size(), 1); // Init adds no separate vote.
}

TEST(CrossCheckOutput, SerializedOwnerContextsKeepIndependentSnapshots)
{
    CrossCheckState state;
    state.reset(2);
    const uint32_t a[] = {1, 2}, b[] = {3, 4};
    EXPECT_EQ(submit_output(state, 0, "words", a, 2, "A", 7, CpuA), OutputMatch::First);
    EXPECT_EQ(submit_output(state, 1, "words", b, 2, "B", 7, CpuB), OutputMatch::First);
    EXPECT_EQ(submit_output(state, 0, "words", a, 2, "changed", 7, CpuA), OutputMatch::Equal);
    EXPECT_EQ(submit_output(state, 0, "words", b, 2, nullptr, 7, CpuA), OutputMatch::DataMismatch);
    EXPECT_EQ(state.owner_outputs[0].find("words")->description, "A");
    EXPECT_EQ(state.owner_outputs[1].find("words")->description, "B");
    EXPECT_EQ(state.owner_outputs[1].find("words")->cpu, CpuB);
    const auto results = state.classify_outputs();
    ASSERT_EQ(results[0].groups.size(), 2);
    EXPECT_EQ(results[0].majority_group, -1);
}

TEST(CrossCheckOutput, PublishedOwnersVoteWithoutSuccessfulConfirmation)
{
    CrossCheckState state;
    state.reset(3);
    uint32_t value = 17;
    submit_output(state, 0, "confirmed", &value, 1, "skipped first", 0, CpuA);
    submit_output(state, 0, "skipped-only", &value, 1, nullptr, 0, CpuA);
    submit_output(state, 0, "confirmed", &value, 1, "successful confirmation", 1, CpuA);
    submit_output(state, 1, "confirmed", &value, 1, nullptr, 1, CpuC);
    submit_output(state, 2, "init-only", &value, 1, nullptr, -1, CpuD);
    const auto results = state.classify_outputs();
    ASSERT_EQ(results.size(), 3);
    EXPECT_EQ(results[0].name, "confirmed");
    ASSERT_EQ(results[0].groups.size(), 1);
    ASSERT_EQ(results[0].groups[0].size(), 2);
    EXPECT_EQ(results[0].groups[0][0].slot->first_worker, 0);
    EXPECT_EQ(results[0].groups[0][0].slot->description, "skipped first");
    EXPECT_EQ(results[1].name, "init-only");
    EXPECT_EQ(results[2].name, "skipped-only");
    EXPECT_EQ(results[2].groups[0][0].slot->first_worker, 0);
}

TEST(CrossCheckOutput, ReentrantInspectionAndSubmissionBeforeMismatchReporting)
{
    CrossCheckState state;
    state.reset(1);
    uint32_t first = 1, different = 2;
    submit_output(state, 0, "words", &first, 1, nullptr);
    auto submission = state.output_submission(0, "words", 0, CpuA);
    EXPECT_EQ(submission.submit(&different, 1, nullptr), OutputMatch::DataMismatch);
    // Inspection may borrow the snapshot after the completed mismatch submission.
    EXPECT_EQ(submit_output(state, 0, "other", &first, 1, nullptr), OutputMatch::First);
    EXPECT_EQ(compare_output(submission.snapshot(), &first, 1), OutputMatch::Equal);
    EXPECT_EQ(state.classify_outputs().size(), 2);
}

TEST(CrossCheckOutput, DistinctOwnerPublishersAndReadOnlyTraversalKeepImmutableChains)
{
    CrossCheckState state;
    constexpr int Owners = 3, Names = 32;
    state.reset(Owners);
    const uint32_t value = 17;
    std::array<const CapturedSlot *, Owners> snapshots;
    for (int owner = 0; owner < Owners; ++owner) {
        submit_output(state, owner, "repeat", &value, 1, "immutable", -1, CpuA);
        snapshots[owner] = state.owner_outputs[owner].find("repeat");
    }
    std::barrier phase(Owners + 1);
    std::array<std::thread, Owners> threads;
    std::atomic_int errors = 0;
    for (int owner = 0; owner < Owners; ++owner) {
        threads[owner] = std::thread([&, owner] {
            for (int index = 0; index < Names; ++index) {
                std::string name = "name_" + std::to_string(owner) + "_" + std::to_string(index);
                auto submission = state.output_submission(owner, name, owner, CpuB);
                phase.arrive_and_wait();
                errors += submission.submit(&value, 1, nullptr) != OutputMatch::First;
                errors += submit_output(state, owner, "repeat", &value, 1, nullptr, owner, CpuB)
                        != OutputMatch::Equal;
                phase.arrive_and_wait();
            }
        });
    }
    for (int index = 0; index < Names; ++index) {
        phase.arrive_and_wait();
        for (const auto &outputs : state.outputs()) {
            std::set<std::string_view> names;
            for (auto *node = outputs.head.load(std::memory_order_acquire); node; node = node->next) {
                EXPECT_TRUE(names.insert(node->name).second);
                EXPECT_EQ(compare_output(node->slot, &value, 1), OutputMatch::Equal);
            }
        }
        phase.arrive_and_wait();
    }
    for (auto &thread : threads)
        thread.join();
    EXPECT_EQ(errors, 0);
    EXPECT_EQ(state.classify_outputs().size(), Owners * Names + 1);
    for (int owner = 0; owner < Owners; ++owner) {
        EXPECT_EQ(state.owner_outputs[owner].find("repeat"), snapshots[owner]);
        EXPECT_EQ(snapshots[owner]->description, "immutable");
        EXPECT_EQ(snapshots[owner]->first_worker, -1);
        EXPECT_EQ(snapshots[owner]->cpu, CpuA);
        EXPECT_EQ(snapshots[owner]->storage.use_count(), 1);
        for (int index = 0; index < Names; ++index) {
            std::string name = "name_" + std::to_string(owner) + "_" + std::to_string(index);
            const auto *slot = state.owner_outputs[owner].find(name);
            ASSERT_NE(slot, nullptr);
            EXPECT_EQ(slot->first_worker, owner);
            EXPECT_EQ(slot->cpu, CpuB);
            EXPECT_EQ(slot->storage.use_count(), 1);
        }
        size_t count = 0;
        for (auto *node = state.owner_outputs[owner].head.load(); node; node = node->next)
            ++count;
        EXPECT_EQ(count, Names + 1);
    }
}

TEST(CrossCheckOutput, QuiescentDestructionReleasesLongChainIteratively)
{
    constexpr int Names = 4096;
    std::vector<std::weak_ptr<const void>> captures;
    {
        CrossCheckState state;
        state.reset(1);
        const uint32_t value = 17;
        for (int index = 0; index < Names; ++index) {
            std::string name = std::to_string(index);
            auto submission = state.output_submission(0, name, 0, CpuA);
            EXPECT_EQ(submission.submit(&value, 1, nullptr), OutputMatch::First);
            captures.push_back(submission.snapshot().storage);
        }
    }
    for (const auto &capture : captures)
        EXPECT_TRUE(capture.expired());
}

TEST(CrossCheckOutput, WholeArrayGroupsHaveExactImplicatedSetsInRepresentativeArrivalOrders)
{
    for (const auto &values : {std::vector<uint32_t>{1, 1, 1}, {1, 1, 2}, {1, 1, 1, 2, 2},
                              {1, 1, 1, 2, 3}, {1, 1, 2, 2}, {1, 2, 3}, {1, 1, 1, 2, 2, 3, 3}}) {
        std::array<std::vector<size_t>, 3> orders;
        orders[0].resize(values.size());
        std::iota(orders[0].begin(), orders[0].end(), 0);
        orders[1] = orders[0];
        std::reverse(orders[1].begin(), orders[1].end());
        orders[2] = orders[0];
        std::rotate(orders[2].begin(), orders[2].begin() + values.size() / 2, orders[2].end());
        for (const auto &order : orders) {
            CrossCheckState state;
            state.reset(values.size());
            for (size_t owner : order) {
                const uint32_t array[] = {values[owner], 99};
                submit_output(state, owner, "words", array, 2, nullptr);
            }
            const auto results = state.classify_outputs();
            ASSERT_EQ(results.size(), 1);
            const auto &result = results[0];
            EXPECT_FALSE(result.has_type_or_count_mismatch);
            size_t ones = std::count(values.begin(), values.end(), 1);
            bool majority = ones > values.size() / 2;
            EXPECT_EQ(result.majority_group >= 0, majority);
            std::set<size_t> implicated;
            if (result.groups.size() > 1) {
                for (size_t group = 0; group < result.groups.size(); ++group) {
                    if (int(group) != result.majority_group) {
                        for (const auto &vote : result.groups[group])
                            implicated.insert(vote.owner);
                    }
                }
            }
            std::set<size_t> expected;
            if (result.groups.size() > 1) {
                for (size_t i = 0; i < values.size(); ++i) {
                    if (!majority || values[i] != 1)
                        expected.insert(i);
                }
            }
            EXPECT_EQ(implicated, expected);
        }
    }
}

TEST(CrossCheckOutput, DoesNotSynthesizeElementwiseMajority)
{
    CrossCheckState state;
    state.reset(3);
    const uint32_t a[] = {1, 1, 2}, b[] = {1, 2, 1}, c[] = {2, 1, 1};
    submit_output(state, 0, "array", a, 3, nullptr);
    submit_output(state, 1, "array", b, 3, nullptr);
    submit_output(state, 2, "array", c, 3, nullptr);
    const auto results = state.classify_outputs();
    EXPECT_EQ(results[0].majority_group, -1);
    EXPECT_EQ(results[0].groups.size(), 3);
}

TEST(CrossCheckOutput, ShapeErrorsAndIndependentNamesAreFrozenTogether)
{
    CrossCheckState state;
    state.reset(2);
    uint32_t word = 42, other = 43;
    uint8_t byte = 42;
    submit_output(state, 0, "count", &word, 1, nullptr);
    submit_output(state, 1, "count", &word, 0, nullptr);
    submit_output(state, 0, "type", &word, 1, nullptr);
    submit_output(state, 1, "type", &byte, 1, nullptr);
    submit_output(state, 0, "valid", &word, 1, nullptr);
    submit_output(state, 1, "valid", &other, 1, nullptr);
    const auto results = state.classify_outputs();
    ASSERT_EQ(results.size(), 3);
    EXPECT_TRUE(results[0].has_type_or_count_mismatch);
    EXPECT_TRUE(results[1].has_type_or_count_mismatch);
    EXPECT_FALSE(results[2].has_type_or_count_mismatch);
    EXPECT_EQ(results[2].groups.size(), 2);
    EXPECT_EQ(submit_output(state, 0, "valid", &byte, 1, nullptr), OutputMatch::TypeMismatch);
    EXPECT_EQ(submit_output(state, 0, "valid", &word, 0, nullptr), OutputMatch::CountMismatch);
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

TEST(CrossCheckOutput, CountPrecedesAnyDataAccessAndEmptyIsSafe)
{
    const uint32_t source[] = {1, 2};
    auto slot = make_captured_slot(source, 2);
    EXPECT_EQ(compare_output(slot, nullptr, 0), OutputMatch::CountMismatch);
    EXPECT_EQ(compare_output(slot, nullptr, 3), OutputMatch::CountMismatch);
    auto empty = make_captured_slot<uint32_t>(nullptr, 0);
    EXPECT_FALSE(empty.storage);
    EXPECT_TRUE(empty.bytes().empty());
    EXPECT_EQ(compare_output(empty, nullptr, 0), OutputMatch::Equal);
    EXPECT_EQ(compare_output(slot, empty), OutputMatch::CountMismatch);
    EXPECT_EQ(compare_output(empty, empty), OutputMatch::Equal);
}

TEST(CrossCheckOutput, SubmissionDistinguishesEmptyRepeatAndRejectsShapeBeforeDataAccess)
{
    CrossCheckState state;
    state.reset(1);
    const uint32_t *empty = nullptr;
    auto first = state.output_submission(0, "empty", -1, CpuA);
    EXPECT_EQ(first.submit(empty, 0, nullptr), OutputMatch::First);
    EXPECT_FALSE(first.snapshot().storage);
    EXPECT_EQ(first.snapshot().first_worker, -1);
    EXPECT_EQ(state.owner_outputs[0].find("absent"), nullptr);

    auto repeat = state.output_submission(0, "empty", 1, CpuA);
    EXPECT_EQ(repeat.submit(empty, 0, nullptr), OutputMatch::Equal);
    EXPECT_FALSE(repeat.snapshot().storage);
    EXPECT_EQ(&repeat.snapshot(), &first.snapshot());

    const uint32_t word = 42, different = 43;
    submit_output(state, 0, "word", &word, 1, nullptr, -1, CpuA);
    // These nonnull addresses must never be read when the shape is incompatible.
    const auto *unreadable = reinterpret_cast<const uint32_t *>(uintptr_t(1));
    EXPECT_EQ(submit_output(state, 0, "word", unreadable, 2, nullptr, 2, CpuA),
              OutputMatch::CountMismatch);
    EXPECT_EQ(submit_output(state, 0, "word", reinterpret_cast<const uint8_t *>(uintptr_t(1)),
                            1, nullptr, 3, CpuA), OutputMatch::TypeMismatch);
    EXPECT_EQ(submit_output(state, 0, "word", &different, 1, nullptr, 4, CpuA),
              OutputMatch::DataMismatch);
    EXPECT_EQ(submit_output(state, 0, "word", &word, 1, nullptr, 5, CpuA), OutputMatch::Equal);
    EXPECT_EQ(state.owner_outputs[0].find("word")->first_worker, -1);
}

#ifndef NDEBUG
TEST(CrossCheckOutput, RejectsCountJustBeyondPtrdiffByteLimit)
{
    const uint32_t source = 1;
    const size_t count = size_t(std::numeric_limits<ptrdiff_t>::max() - 1) / sizeof(source) + 1;
    EXPECT_DEATH_IF_SUPPORTED(make_captured_slot(&source, count), "count <=");
    CrossCheckState state;
    state.reset(1);
    submit_output(state, 0, "words", &source, 1, nullptr);
    EXPECT_DEATH_IF_SUPPORTED(submit_output(state, 0, "words", &source, count, nullptr), "count <=");
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
    auto slot = make_captured_slot(source.data(), source.size());
    CrossCheckState state;
    state.reset(1);
    EXPECT_EQ(submit_output(state, 0, "float", source.data(), source.size(), nullptr), OutputMatch::First);
    EXPECT_EQ(submit_output(state, 0, "float", source.data(), source.size(), nullptr), OutputMatch::Equal);
    EXPECT_EQ(std::memcmp(slot.storage.get(), bits.data(), sizeof(bits)), 0);
    EXPECT_EQ(compare_output(slot, source.data(), source.size()), OutputMatch::Equal);
    for (size_t index : {0, 2}) {
        auto changed = bits;
        changed[index] = bits[index + 1];
        auto actual = std::bit_cast<std::array<float, 5>>(changed);
        EXPECT_EQ(submit_output(state, 0, "float", actual.data(), actual.size(), nullptr), OutputMatch::DataMismatch);
        EXPECT_EQ(compare_output(slot, actual.data(), actual.size()), OutputMatch::DataMismatch);
        auto peer = make_captured_slot(actual.data(), actual.size());
        EXPECT_EQ(compare_output(slot, peer), OutputMatch::DataMismatch);
    }
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
    auto slot = make_captured_slot(source.data(), source.size());
    CrossCheckState state;
    state.reset(1);
    EXPECT_EQ(submit_output(state, 0, "long double", source.data(), source.size(), nullptr), OutputMatch::First);
    EXPECT_EQ(submit_output(state, 0, "long double", source.data(), source.size(), nullptr), OutputMatch::Equal);
    for (size_t i = 0; i < source.size(); ++i) {
        const auto bytes = slot.bytes().subspan(i * sizeof(long double), sizeof(long double));
        EXPECT_EQ(std::memcmp(bytes.data(), &source[i], meaningful), 0);
        for (auto byte : bytes.subspan(meaningful))
            EXPECT_EQ(byte, std::byte{0});
    }
    EXPECT_EQ(compare_output(slot, source.data(), source.size()), OutputMatch::Equal);
    auto *changed = reinterpret_cast<unsigned char *>(&source[2]);
    changed[0] ^= 1;
    EXPECT_EQ(submit_output(state, 0, "long double", source.data(), source.size(), nullptr), OutputMatch::DataMismatch);
    EXPECT_EQ(compare_output(slot, source.data(), source.size()), OutputMatch::DataMismatch);
    EXPECT_EQ(memcmp_offset(source.data(), slot.storage.get(), sizeof(source), slot.type),
              ptrdiff_t(2 * sizeof(long double)));
}

TEST(CrossCheckOutput, ResetReleasesAllCaptures)
{
    CrossCheckState state;
    const uint32_t source[] = {1, 2};
    for (int i = 0; i < 3; ++i) {
        state.reset(2);
        state.inputs.emplace("input", make_captured_slot(source, 2));
        submit_output(state, 0, "words", source, 2, "reset me", -1);
        submit_output(state, 0, "words", source, 2, nullptr, 7);
        submit_output(state, 1, "words", source, 2, nullptr, 7);
        std::weak_ptr<const void> input = state.inputs.at("input").storage;
        std::weak_ptr<const void> owner0 = state.owner_outputs[0].find("words")->storage;
        std::weak_ptr<const void> owner1 = state.owner_outputs[1].find("words")->storage;
        state.reset(1);
        EXPECT_TRUE(input.expired());
        EXPECT_TRUE(owner0.expired());
        EXPECT_TRUE(owner1.expired());
        EXPECT_TRUE(state.inputs.empty());
        ASSERT_EQ(state.owner_count, 1);
        EXPECT_EQ(state.owner_outputs[0].head.load(), nullptr);
    }
    state.reset();
    EXPECT_FALSE(state.owner_outputs);
}

TEST(CrossCheckOutput, ReportingContextDoesNotImplicateItsInitialHardware)
{
    PerThreadData::TestCommon context;
    context.init();
    context.fail_time = MonotonicTimePoint(MonotonicTimePoint::duration(1));
    context.failing_cpu_plus_1 = 43;
    context.thread_flags = uint32_t(PerThreadData::Common::Flag::CrossCheckFailure);
    EXPECT_TRUE(context.has_failed());
    EXPECT_FALSE(context.has_non_crosscheck_failure());
    context.thread_flags |= uint32_t(PerThreadData::Common::Flag::OrdinaryFailure);
    EXPECT_TRUE(context.has_non_crosscheck_failure());
    context.init();
    EXPECT_FALSE(context.has_non_crosscheck_failure());
}

} // namespace
