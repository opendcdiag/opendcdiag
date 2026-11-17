/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_CROSSCHECK_STATE_HPP
#define SANDSTONE_CROSSCHECK_STATE_HPP

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "sandstone_data.h"

enum class LogicalProcessor : int;

namespace SandstoneCrossCheck {

template<typename T> inline constexpr char CAPTURE_TYPE_TOKEN = 0;

struct CapturedSlot {
    std::unique_ptr<const void, void (*)(const void *)> storage{nullptr, nullptr};
    size_t count;
    DataType type;
    const void *type_token;
    std::string description;
    LogicalProcessor cpu = LogicalProcessor(-1); // first-submission host CPU metadata, not attribution
    int first_worker = -1; // -1 denotes init; preserved for the snapshot lifetime.

    std::span<const std::byte> bytes() const;
};

using OutputMap = std::map<std::string, CapturedSlot, std::less<>>;

struct ThreadOutputs {
    OutputMap snapshots;
    // Written by the test thread; read by the main thread only after join.
    LogicalProcessor completion_cpu = LogicalProcessor(-1);
    int completion_device = -1;
    int mismatch_device = -1;

    const CapturedSlot *find(std::string_view name) const;
};

enum class OutputMatch { First, Equal, TypeMismatch, CountMismatch, DataMismatch };
OutputMatch compare_output(const CapturedSlot &expected, const void *actual, size_t count);
OutputMatch compare_output(const CapturedSlot &expected, const CapturedSlot &actual);
[[noreturn]] void invalid_operation(const char *reason);

struct OutputSubmission {
    std::string_view name;
    ThreadOutputs *outputs;
    const CapturedSlot *reference;
    size_t thread_index;
    int worker; // reporting context; init uses -1, not thread_index zero
    LogicalProcessor cpu;

    const CapturedSlot &snapshot() const { return *reference; }

    template<typename T>
    const CapturedSlot *submit(const T *data, size_t count, const char *description);
};

struct OutputVote {
    size_t thread;
    const CapturedSlot *slot;
};

struct OutputConclusion {
    std::string_view name;
    std::vector<std::vector<OutputVote>> groups;
    int majority_group = -1;
    bool has_type_or_count_mismatch = false;
};

struct CrossCheckState {
    OutputMap inputs;
    // Test thread indices, never device indices. Init shares index zero.
    std::unique_ptr<ThreadOutputs[]> thread_outputs;
    size_t thread_count = 0;
    size_t thread_capacity = 0;

    std::span<const ThreadOutputs> outputs() const { return {thread_outputs.get(), thread_count}; }

    // Called before init or after all test threads have joined. Retains backing storage, not captures.
    void reset(size_t thread_count = 0);
    OutputSubmission output_submission(size_t thread_index, std::string_view name,
                                       int worker, LogicalProcessor cpu);
    // Called after join; reporting must not change these frozen conclusions.
    std::vector<OutputConclusion> classify_outputs() const;
};

inline OutputSubmission CrossCheckState::output_submission(size_t thread_index, std::string_view name,
                                                           int worker, LogicalProcessor cpu)
{
    assert(!name.empty());
    assert(thread_index < thread_count);
    auto &outputs = thread_outputs[thread_index];
    return {name, &outputs, outputs.find(name), thread_index, worker, cpu};
}

template<typename T>
CapturedSlot make_captured_slot(const T *data, size_t count, const char *description = nullptr)
{
    using namespace SandstoneDataDetails;
    static_assert(ValidDataType<T> && !std::is_void_v<T>
                  && !std::is_const_v<T> && !std::is_volatile_v<T>);
    static_assert(std::is_trivially_copyable_v<T>);
    constexpr DataType type = TypeToDataType<T>::Type;
    static_assert(type_size(type) == sizeof(T));
    static_assert(type_real_size(type) <= sizeof(T));
    assert(count <= size_t(std::numeric_limits<ptrdiff_t>::max() - 1) / sizeof(T));
    assert(data || count == 0);

    std::unique_ptr<const void, void (*)(const void *)> storage{nullptr, nullptr};
    if (count) {
        std::unique_ptr<T[]> owned(new T[count]);
        if constexpr (type_real_size(type) == sizeof(T)) {
            std::memcpy(static_cast<void *>(owned.get()), data, count * sizeof(T));
        } else {
            // Copy only meaningful bytes and normalize trailing padding.
            std::memset(static_cast<void *>(owned.get()), 0, count * sizeof(T));
            for (size_t i = 0; i < count; ++i)
                std::memcpy(static_cast<void *>(owned.get() + i), data + i, type_real_size(type));
        }
        storage = {owned.release(), [](const void *ptr) { delete[] static_cast<const T *>(ptr); }};
    }

    return { std::move(storage), count, type, &CAPTURE_TYPE_TOKEN<T>,
             description ? description : "", LogicalProcessor(-1), -1 };
}

// First submission returns null; compatible repeats borrow the immutable snapshot.
template<typename T>
inline const CapturedSlot *
OutputSubmission::submit(const T *data, size_t count, const char *description)
{
    static_assert(SandstoneDataDetails::ValidDataType<T> && !std::is_void_v<T>
                  && !std::is_const_v<T> && !std::is_volatile_v<T>
                  && std::is_trivially_copyable_v<T>);
    assert(!name.empty());
    if (!reference) {
        auto slot = make_captured_slot(data, count, description);
        slot.first_worker = worker;
        slot.cpu = cpu;
        auto result = outputs->snapshots.emplace(std::string(name), std::move(slot));
        assert(result.second);
        reference = &result.first->second;
        return nullptr;
    }
    if (reference->type_token != &CAPTURE_TYPE_TOKEN<T>)
        invalid_operation("output element type mismatch");
    if (reference->count != count)
        invalid_operation("later output submission count mismatch");
    return reference;
}

} // namespace SandstoneCrossCheck

#endif // SANDSTONE_CROSSCHECK_STATE_HPP
