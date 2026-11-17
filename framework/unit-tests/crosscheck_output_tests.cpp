/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck_state.hpp"
#include "crosscheck_output_peer.hpp"
#include "fp_vectors/Floats.h"
#include "test_data.h"

#include <array>
#include <bit>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <thread>

#include "gtest/gtest.h"

namespace SandstoneCrossCheck {
[[noreturn]] void invalid_operation(const char *reason)
{
    // Preserve the reason so death tests distinguish API misuse from a bad-data read.
    std::fputs(reason, stderr);
    std::abort();
}
}

namespace {
using namespace SandstoneCrossCheck;
using namespace SandstoneDataDetails;

constexpr LogicalProcessor CpuA{42}, CpuB{99}, CpuC{43}, CpuD{44};

int released_captures;

void count_capture_release(const void *ptr)
{
    ++released_captures;
    delete[] static_cast<const uint32_t *>(ptr);
}

template<typename T>
const CapturedSlot *record_output(CrossCheckState &state, size_t thread, const char *name, const T *data,
                          size_t count, const char *description, int worker = -2,
                          LogicalProcessor cpu = LogicalProcessor::None)
{
    return state.output_submission(thread, name, worker == -2 ? int(thread) : worker, cpu)
            .submit(data, count, description);
}

TEST(CrossCheckOutput, InitAndMigratedThreadZeroShareImmutableSnapshot)
{
    CrossCheckState state;
    state.reset(2);
    {
        std::vector<uint32_t> source = {11, 22, 33};
        std::string name = "words", description = "first description";
        EXPECT_EQ(record_output(state, 0, name.c_str(), source.data(), source.size(),
                                description.c_str(), -1, CpuA), nullptr);
        source.assign(3, 99);
        name.assign("changed");
        description.assign("changed");
    }
    const uint32_t equal[] = {11, 22, 33}, different[] = {1, 2, 3};
    const auto &slot = *state.thread_outputs[0].find("words");
    const void *storage = slot.storage.get();
    EXPECT_EQ(record_output(state, 0, "words", equal, 3, "replacement", 0, CpuB), &slot);
    auto submission = state.output_submission(0, "words", 0, CpuB);
    EXPECT_EQ(submission.submit(different, 3, nullptr), &slot);
    EXPECT_EQ(&submission.snapshot(), &slot);
    EXPECT_EQ(compare_output(submission.snapshot(), different, 3), OutputMatch::DataMismatch);
    EXPECT_EQ(slot.storage.get(), storage);
    EXPECT_EQ(slot.description, "first description");
    EXPECT_EQ(slot.first_worker, -1);
    EXPECT_EQ(slot.cpu, CpuA);
    EXPECT_EQ(state.thread_outputs[0].snapshots.size(), 1);
    EXPECT_TRUE(state.thread_outputs[1].snapshots.empty());
    const auto results = state.classify_outputs();
    ASSERT_EQ(results.size(), 1);
    ASSERT_EQ(results[0].groups.size(), 1);
    EXPECT_EQ(results[0].groups[0].size(), 1); // Init adds no separate vote.
    EXPECT_EQ(record_output(state, 0, "other", equal, 3, nullptr), nullptr);
    EXPECT_EQ(&submission.snapshot(), &slot);
    EXPECT_EQ(compare_output(submission.snapshot(), equal, 3), OutputMatch::Equal);
    EXPECT_EQ(state.classify_outputs().size(), 2);
}

TEST(CrossCheckOutput, InitAndThreadZeroAddOneVoteToThreeThreadMajority)
{
    CrossCheckState state;
    state.reset(3);
    const uint32_t a = 1, b = 2;
    EXPECT_EQ(record_output(state, 0, "words", &a, 1, "init", -1, CpuA), nullptr);
    EXPECT_EQ(record_output(state, 0, "words", &a, 1, "worker zero", 0, CpuB),
              state.thread_outputs[0].find("words"));
    record_output(state, 1, "words", &b, 1, nullptr, 1, CpuC);
    record_output(state, 2, "words", &b, 1, nullptr, 2, CpuD);
    const auto results = state.classify_outputs();
    ASSERT_EQ(results.size(), 1);
    const auto &result = results[0];
    ASSERT_EQ(result.groups.size(), 2);
    ASSERT_GE(result.majority_group, 0);
    const auto &majority = result.groups[result.majority_group];
    ASSERT_EQ(majority.size(), 2);
    EXPECT_EQ(majority[0].thread, 1);
    EXPECT_EQ(majority[1].thread, 2);
    const auto &outliers = result.groups[1 - result.majority_group];
    ASSERT_EQ(outliers.size(), 1);
    EXPECT_EQ(outliers[0].thread, 0);
    EXPECT_EQ(outliers[0].slot->first_worker, -1);
    EXPECT_EQ(outliers[0].slot->cpu, CpuA);
}

TEST(CrossCheckOutput, ConcurrentTestThreadsKeepIndependentMapsAndStableSnapshots)
{
    CrossCheckState state;
    constexpr int Threads = 3, Names = 2;
    state.reset(Threads);
    const uint32_t value = 17;
    std::array<const CapturedSlot *, Threads> snapshots;
    for (int thread = 0; thread < Threads; ++thread) {
        record_output(state, thread, "repeat", &value, 1, "immutable", thread, CpuA);
        snapshots[thread] = state.thread_outputs[thread].find("repeat");
    }
    std::array<std::thread, Threads> threads;
    std::array<int, Threads> errors{};
    for (int thread = 0; thread < Threads; ++thread) {
        threads[thread] = std::thread([&, thread] {
            for (int index = 0; index < Names; ++index) {
                std::string name = "name_" + std::to_string(thread) + "_" + std::to_string(index);
                auto submission = state.output_submission(thread, name, thread, CpuB);
                errors[thread] += submission.submit(&value, 1, nullptr) != nullptr;
                errors[thread] += record_output(state, thread, "repeat", &value, 1, nullptr, thread, CpuB)
                        != snapshots[thread];
            }
        });
    }
    for (auto &thread : threads)
        thread.join();
    EXPECT_EQ(state.classify_outputs().size(), Threads * Names + 1);
    for (int thread = 0; thread < Threads; ++thread) {
        EXPECT_EQ(errors[thread], 0);
        EXPECT_EQ(state.thread_outputs[thread].find("repeat"), snapshots[thread]);
        EXPECT_EQ(snapshots[thread]->description, "immutable");
        EXPECT_EQ(snapshots[thread]->first_worker, thread);
        EXPECT_EQ(snapshots[thread]->cpu, CpuA);
        for (int index = 0; index < Names; ++index) {
            std::string name = "name_" + std::to_string(thread) + "_" + std::to_string(index);
            const auto *slot = state.thread_outputs[thread].find(name);
            ASSERT_NE(slot, nullptr);
            EXPECT_EQ(slot->first_worker, thread);
            EXPECT_EQ(slot->cpu, CpuB);
            EXPECT_EQ(compare_output(*slot, &value, 1), OutputMatch::Equal);
        }
        EXPECT_EQ(state.thread_outputs[thread].snapshots.size(), Names + 1);
    }
}

TEST(CrossCheckOutput, WholeArrayDistributionsHaveExactImplicatedSets)
{
    for (const auto &values : {std::vector<uint32_t>{1, 1, 1}, {1, 1, 2}, {1, 1, 1, 2, 2},
                              {1, 1, 1, 2, 3}, {1, 1, 2, 2}, {1, 2, 3}, {1, 1, 1, 2, 2, 3, 3}}) {
        CrossCheckState state;
        state.reset(values.size());
        for (size_t thread = 0; thread < values.size(); ++thread) {
            const uint32_t array[] = {values[thread], 99};
            record_output(state, thread, "words", array, 2, nullptr);
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
                        implicated.insert(vote.thread);
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

TEST(CrossCheckOutput, DoesNotSynthesizeElementwiseMajority)
{
    CrossCheckState state;
    state.reset(3);
    const uint32_t a[] = {1, 1, 2}, b[] = {1, 2, 1}, c[] = {2, 1, 1};
    record_output(state, 0, "array", a, 3, nullptr);
    record_output(state, 1, "array", b, 3, nullptr);
    record_output(state, 2, "array", c, 3, nullptr);
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
    record_output(state, 0, "count", &word, 1, nullptr);
    record_output(state, 1, "count", &word, 0, nullptr);
    record_output(state, 0, "type", &word, 1, nullptr);
    record_output(state, 1, "type", &byte, 1, nullptr);
    record_output(state, 0, "valid", &word, 1, nullptr);
    record_output(state, 1, "valid", &other, 1, nullptr);
    const auto results = state.classify_outputs();
    ASSERT_EQ(results.size(), 3);
    EXPECT_TRUE(results[0].has_type_or_count_mismatch);
    EXPECT_TRUE(results[1].has_type_or_count_mismatch);
    EXPECT_FALSE(results[2].has_type_or_count_mismatch);
    EXPECT_EQ(results[2].groups.size(), 2);
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

TEST(CrossCheckOutput, SubmissionDistinguishesEmptyRepeatAndBorrowsWithoutDataAccess)
{
    CrossCheckState state;
    state.reset(1);
    const uint32_t *empty = nullptr;
    auto first = state.output_submission(0, "empty", -1, CpuA);
    EXPECT_EQ(first.submit(empty, 0, nullptr), nullptr);
    EXPECT_FALSE(first.snapshot().storage);
    EXPECT_EQ(first.snapshot().first_worker, -1);
    EXPECT_EQ(state.thread_outputs[0].find("absent"), nullptr);

    auto repeat = state.output_submission(0, "empty", 0, CpuB);
    EXPECT_EQ(repeat.submit(empty, 0, nullptr), &first.snapshot());
    EXPECT_FALSE(repeat.snapshot().storage);
    EXPECT_EQ(&repeat.snapshot(), &first.snapshot());

    const uint32_t word = 42, different = 43;
    record_output(state, 0, "word", &word, 1, nullptr, -1, CpuA);
    // Compatible repeats only borrow, leaving actual-data access to the public API.
    const auto *unreadable = reinterpret_cast<const uint32_t *>(uintptr_t(1));
    const auto *slot = state.thread_outputs[0].find("word");
    EXPECT_EQ(record_output(state, 0, "word", unreadable, 1, nullptr, 0, CpuB), slot);
    EXPECT_EQ(record_output(state, 0, "word", &different, 1, nullptr, 0, CpuC),
              slot);
    EXPECT_EQ(record_output(state, 0, "word", &word, 1, nullptr, 0, CpuD), slot);
    EXPECT_EQ(state.thread_outputs[0].find("word")->first_worker, -1);
}

TEST(CrossCheckOutputDeathTest, RejectsExactTypeAndCountBeforeDataAccess)
{
    CrossCheckState state;
    state.reset(1);
    const float value = 42;
    record_output(state, 0, "value", &value, 1, nullptr);
    volatile uintptr_t address = 1;
    const auto *unreadable = reinterpret_cast<const float *>(address);
    EXPECT_DEATH_IF_SUPPORTED(record_output(state, 0, "value", unreadable, 0, nullptr),
                              "later output submission count mismatch");
    EXPECT_DEATH_IF_SUPPORTED(record_output(state, 0, "value", unreadable, 2, nullptr),
                              "later output submission count mismatch");
    EXPECT_DEATH_IF_SUPPORTED(record_output(state, 0, "value", static_cast<const float *>(nullptr),
                                           2, nullptr), "later output submission count mismatch");
    // Float32 maps to the same DataType as float, but has a distinct exact type.
    EXPECT_DEATH_IF_SUPPORTED(record_output(state, 0, "value",
            reinterpret_cast<const Float32 *>(address), 1, nullptr),
            "output element type mismatch");
    const auto count = size_t(std::numeric_limits<ptrdiff_t>::max());
    EXPECT_DEATH_IF_SUPPORTED(record_output(state, 0, "value", unreadable, count, nullptr),
                              "later output submission count mismatch");
}

#ifndef NDEBUG
TEST(CrossCheckOutput, RejectsCountJustBeyondPtrdiffByteLimit)
{
    const uint32_t source = 1;
    const size_t count = size_t(std::numeric_limits<ptrdiff_t>::max() - 1) / sizeof(source) + 1;
    EXPECT_DEATH_IF_SUPPORTED(make_captured_slot(&source, count), "count <=");
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
    EXPECT_EQ(record_output(state, 0, "float", source.data(), source.size(), nullptr), nullptr);
    const auto *snapshot = record_output(state, 0, "float", source.data(), source.size(), nullptr);
    ASSERT_NE(snapshot, nullptr);
    EXPECT_TRUE(memcmp_equal<TypeToDataType<float>::Type>(
            source.data(), snapshot->storage.get(), source.size() * sizeof(float)));
    EXPECT_EQ(std::memcmp(slot.storage.get(), bits.data(), sizeof(bits)), 0);
    EXPECT_EQ(compare_output(slot, source.data(), source.size()), OutputMatch::Equal);
    for (size_t index : {0, 2}) {
        auto changed = bits;
        changed[index] = bits[index + 1];
        auto actual = std::bit_cast<std::array<float, 5>>(changed);
        EXPECT_EQ(record_output(state, 0, "float", actual.data(), actual.size(), nullptr), snapshot);
        EXPECT_FALSE(memcmp_equal<TypeToDataType<float>::Type>(
                actual.data(), snapshot->storage.get(), actual.size() * sizeof(float)));
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
    EXPECT_EQ(record_output(state, 0, "long double", source.data(), source.size(), nullptr), nullptr);
    const auto *snapshot = record_output(state, 0, "long double", source.data(), source.size(), nullptr);
    ASSERT_NE(snapshot, nullptr);
    EXPECT_TRUE(memcmp_equal<TypeToDataType<long double>::Type>(
            source.data(), snapshot->storage.get(), sizeof(source)));
    for (size_t i = 0; i < source.size(); ++i) {
        const auto bytes = slot.bytes().subspan(i * sizeof(long double), sizeof(long double));
        EXPECT_EQ(std::memcmp(bytes.data(), &source[i], meaningful), 0);
        for (auto byte : bytes.subspan(meaningful))
            EXPECT_EQ(byte, std::byte{0});
    }
    EXPECT_EQ(compare_output(slot, source.data(), source.size()), OutputMatch::Equal);
    auto *changed = reinterpret_cast<unsigned char *>(&source[2]);
    changed[0] ^= 1;
    EXPECT_EQ(record_output(state, 0, "long double", source.data(), source.size(), nullptr), snapshot);
    EXPECT_FALSE(memcmp_equal<TypeToDataType<long double>::Type>(
            source.data(), snapshot->storage.get(), sizeof(source)));
    EXPECT_EQ(compare_output(slot, source.data(), source.size()), OutputMatch::DataMismatch);
    EXPECT_EQ(memcmp_offset(source.data(), slot.storage.get(), sizeof(source), slot.type),
              ptrdiff_t(2 * sizeof(long double)));
}

TEST(CrossCheckOutput, ResetReleasesAllCaptures)
{
    const uint32_t source[] = {1, 2};
    released_captures = 0;
    {
        CrossCheckState state;
        state.reset(2);
        for (size_t count : {2, 4, 1, 3, 0, 2}) {
            state.inputs.emplace("input", make_captured_slot(source, 2));
            state.inputs.at("input").storage.get_deleter() = count_capture_release;
            for (size_t thread = 0; thread < state.thread_count; ++thread) {
                record_output(state, thread, "words", source, 2, "reset me", -1);
                record_output(state, thread, "words", source, 2, nullptr, int(thread));
                auto &outputs = state.thread_outputs[thread];
                outputs.completion_cpu = CpuB;
                outputs.completion_device = 3;
                outputs.mismatch_device = 2;
                outputs.snapshots.at("words").storage.get_deleter() = count_capture_release;
            }
            const int expected_releases = int(state.thread_count) + 1;
            released_captures = 0;
            state.reset(count);
            EXPECT_EQ(released_captures, expected_releases);
            EXPECT_TRUE(state.inputs.empty());
            ASSERT_EQ(state.thread_count, count);
            ASSERT_EQ(state.outputs().size(), count);
            EXPECT_TRUE(state.classify_outputs().empty());
            for (const auto &outputs : state.outputs()) {
                EXPECT_TRUE(outputs.snapshots.empty());
                EXPECT_EQ(outputs.completion_cpu, LogicalProcessor(-1));
                EXPECT_EQ(outputs.completion_device, -1);
                EXPECT_EQ(outputs.mismatch_device, -1);
            }
        }
        state.reset();
        EXPECT_TRUE(state.outputs().empty());
        state.reset(1);
        state.inputs.emplace("input", make_captured_slot(source, 2));
        state.inputs.at("input").storage.get_deleter() = count_capture_release;
        record_output(state, 0, "words", source, 2, nullptr);
        state.thread_outputs[0].snapshots.at("words").storage.get_deleter() = count_capture_release;
        released_captures = 0;
    }
    EXPECT_EQ(released_captures, 2);
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
