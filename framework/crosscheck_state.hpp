/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_CROSSCHECK_STATE_HPP
#define SANDSTONE_CROSSCHECK_STATE_HPP

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

namespace SandstoneCrossCheck {

template<typename T> inline constexpr char CAPTURE_TYPE_TOKEN = 0;

struct CapturedSlot {
    std::shared_ptr<const void> storage;
    size_t count;
    DataType type;
    const void *type_token;
    std::string description;
    int cpu = -1; // logical processor at the first submission, not at worker completion

    std::span<const std::byte> bytes() const;
};

using OutputMap = std::map<std::string, CapturedSlot, std::less<>>;

enum class OutputMatch { First, Equal, Missing, TypeMismatch, CountMismatch, DataMismatch };
OutputMatch compare_output(const CapturedSlot &expected, const void *actual, size_t count);
OutputMatch compare_output(const CapturedSlot &expected, const CapturedSlot *actual);
const CapturedSlot *find_majority(std::span<const CapturedSlot *const> slots);

struct OutputSubmission {
    std::string_view name;
    OutputMap *outputs;
    OutputMap::iterator position;
    bool existing;
    std::unique_ptr<OutputMap> *missing_outputs = nullptr;

    template<typename T>
    OutputMatch submit(const T *data, size_t count, const char *description);
};

struct CrossCheckState {
    OutputMap inputs;
    OutputMap init_outputs;
    // Only the outer container is initialized before test_init(). Each worker creates
    // its own map and buffers on first submission; it never touches other maps.
    std::vector<std::unique_ptr<OutputMap>> worker_outputs;
    enum class Phase { Inactive, Initializing, Running };
    Phase phase = Phase::Inactive;

    void reset(size_t worker_count = 0);
    OutputSubmission output_submission(size_t worker, std::string_view name);

    template<typename T>
    OutputMatch submit_init(const char *name, const T *data, size_t count, const char *description);
    template<typename T>
    OutputMatch submit_output(size_t worker, const char *name, const T *data, size_t count,
                              const char *description);
};

inline OutputSubmission CrossCheckState::output_submission(size_t worker, std::string_view name)
{
    assert(phase == Phase::Running);
    assert(!name.empty());
    assert(worker < worker_outputs.size());
    auto &outputs = worker_outputs[worker];
    auto position = outputs ? outputs->lower_bound(name) : OutputMap::iterator{};
    bool existing = outputs && position != outputs->end() && position->first == name;
    return {name, outputs.get(), position, existing, outputs ? nullptr : &outputs};
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
             description ? description : "" };
}

template<typename T>
OutputMatch CrossCheckState::submit_init(const char *name, const T *data, size_t count,
                                        const char *description)
{
    assert(phase == Phase::Initializing);
    assert(name && *name);
    auto position = init_outputs.lower_bound(name);
    bool existing = position != init_outputs.end() && position->first == name;
    return OutputSubmission{name, &init_outputs, position, existing}.submit(data, count, description);
}

template<typename T>
OutputMatch CrossCheckState::submit_output(size_t worker, const char *name, const T *data,
                                           size_t count, const char *description)
{
    return output_submission(worker, name).submit(data, count, description);
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
    if (existing) {
        if (position->second.type_token != &CAPTURE_TYPE_TOKEN<T>)
            return OutputMatch::TypeMismatch;
        return compare_output(position->second, data, count);
    }

    if (!outputs) {
        *missing_outputs = std::make_unique<OutputMap>();
        outputs = missing_outputs->get();
        position = outputs->end();
    }
    outputs->emplace_hint(position, name, make_captured_slot(data, count, description));
    return OutputMatch::First;
}

} // namespace SandstoneCrossCheck

#endif // SANDSTONE_CROSSCHECK_STATE_HPP
