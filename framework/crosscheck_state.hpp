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
#include <mutex>
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
    std::shared_ptr<const void> storage;
    size_t count;
    DataType type;
    const void *type_token;
    std::string description;
    LogicalProcessor cpu = LogicalProcessor(-1); // observed host CPU, separate from output ownership
    int first_worker = -1; // -1 denotes init; preserved for the snapshot lifetime.
    std::vector<int> contributors;

    std::span<const std::byte> bytes() const;
};

using OutputMap = std::map<std::string, CapturedSlot, std::less<>>;

enum class OutputMatch { First, Equal, TypeMismatch, CountMismatch, DataMismatch };
OutputMatch compare_output(const CapturedSlot &expected, const void *actual, size_t count);
OutputMatch compare_output(const CapturedSlot &expected, const CapturedSlot &actual);

struct OutputSubmission {
    std::string_view name;
    OutputMap *outputs;
    OutputMap::iterator position;
    bool has_snapshot;
    size_t owner;
    int worker;
    LogicalProcessor cpu;
    std::unique_lock<std::mutex> lock;

    const CapturedSlot &snapshot() const { return position->second; }

    template<typename T>
    OutputMatch submit(const T *data, size_t count, const char *description);
};

struct OutputVote {
    size_t owner;
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
    std::vector<OutputMap> owner_outputs;
    std::mutex mutex;

    void reset(size_t owner_count = 0);
    OutputSubmission output_submission(size_t owner, std::string_view name,
                                       int worker, LogicalProcessor cpu);
    // Called after join; reporting must not change these frozen conclusions.
    std::vector<OutputConclusion> classify_outputs(std::span<const int> successful_workers) const;
};

inline OutputSubmission CrossCheckState::output_submission(size_t owner, std::string_view name,
                                                           int worker, LogicalProcessor cpu)
{
    assert(!name.empty());
    std::unique_lock lock(mutex);
    assert(owner < owner_outputs.size());
    auto &outputs = owner_outputs[owner];
    auto position = outputs.lower_bound(name);
    bool has_snapshot = position != outputs.end() && position->first == name;
    return {name, &outputs, position, has_snapshot, owner, worker, cpu, std::move(lock)};
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

    std::shared_ptr<const void> storage;
    if (count) {
        auto owned = std::make_shared_for_overwrite<T[]>(count);
        // Byte writes preserve NaN payloads without floating-point loads.
        if constexpr (type_real_size(type) == sizeof(T)) {
            std::memcpy(static_cast<void *>(owned.get()), data, count * sizeof(T));
        } else {
            // Copy only meaningful bytes and normalize trailing padding.
            std::memset(static_cast<void *>(owned.get()), 0, count * sizeof(T));
            for (size_t i = 0; i < count; ++i)
                std::memcpy(static_cast<void *>(owned.get() + i), data + i, type_real_size(type));
        }
        storage = std::move(owned);
    }

    return { std::move(storage), count, type, &CAPTURE_TYPE_TOKEN<T>,
             description ? description : "", LogicalProcessor(-1), -1, {} };
}

template<typename T>
OutputMatch OutputSubmission::submit(const T *data, size_t count, const char *description)
{
    static_assert(SandstoneDataDetails::ValidDataType<T> && !std::is_void_v<T>
                  && !std::is_const_v<T> && !std::is_volatile_v<T>
                  && std::is_trivially_copyable_v<T>);
    assert(!name.empty());
    assert(data || count == 0);
    assert(count <= size_t(std::numeric_limits<ptrdiff_t>::max() - 1) / sizeof(T));
    assert(lock.owns_lock());
    OutputMatch match = OutputMatch::First;
    if (has_snapshot) {
        if (position->second.type_token != &CAPTURE_TYPE_TOKEN<T>)
            match = OutputMatch::TypeMismatch;
        else
            match = compare_output(position->second, data, count);
    } else {
        auto slot = make_captured_slot(data, count, description);
        slot.first_worker = worker;
        slot.cpu = cpu;
        if (worker >= 0)
            slot.contributors.push_back(worker);
        position = outputs->emplace_hint(position, name, std::move(slot));
    }
    if (match == OutputMatch::Equal && worker >= 0) {
        auto &slot = position->second;
        if (std::find(slot.contributors.begin(), slot.contributors.end(), worker)
                == slot.contributors.end()) {
            slot.contributors.push_back(worker);
        }
    }
    lock.unlock();
    return match;
}

} // namespace SandstoneCrossCheck

#endif // SANDSTONE_CROSSCHECK_STATE_HPP
