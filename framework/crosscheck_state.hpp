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

    std::span<const std::byte> bytes() const;
};

using OutputMap = std::map<std::string, CapturedSlot, std::less<>>;

enum class OutputMatch { First, Equal, Missing, TypeMismatch, CountMismatch, DataMismatch };
OutputMatch compare_output(const CapturedSlot &expected, const void *actual, size_t count);
OutputMatch compare_output(const CapturedSlot &expected, const CapturedSlot *actual);

struct CrossCheckState {
    std::map<std::string, CapturedSlot, std::less<>> inputs;
    OutputMap golden_outputs;
    // Only the outer container is initialized before test_init(). Each worker creates
    // its own map and buffers on first submission; it never touches other maps.
    std::vector<std::unique_ptr<OutputMap>> worker_outputs;
    enum class Phase { Inactive, Initializing, Running };
    Phase phase = Phase::Inactive;

    void reset(size_t worker_count = 0);
    std::map<std::string_view, const CapturedSlot *, std::less<>> consensus_outputs() const;

    template<typename T>
    void capture_golden(const char *name, const T *data, size_t count, const char *description);
    template<typename T>
    OutputMatch submit_output(size_t worker, const char *name, const T *data, size_t count,
                              const char *description);
};

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
        T *owned = new T[count];
        storage = std::shared_ptr<const void>(owned, std::default_delete<T[]>());
        // Byte writes preserve NaN payloads without floating-point loads.
        if constexpr (type_real_size(type) == sizeof(T)) {
            std::memcpy(static_cast<void *>(owned), data, count * sizeof(T));
        } else {
            // Copy only meaningful bytes and normalize trailing padding.
            std::memset(static_cast<void *>(owned), 0, count * sizeof(T));
            for (size_t i = 0; i < count; ++i)
                std::memcpy(static_cast<void *>(owned + i), data + i, type_real_size(type));
        }
    }

    return { std::move(storage), count, type, &CAPTURE_TYPE_TOKEN<T>,
             description ? description : "" };
}

template<typename T>
void CrossCheckState::capture_golden(const char *name, const T *data, size_t count,
                                     const char *description)
{
    assert(phase == Phase::Initializing);
    assert(name && *name);
    assert(!golden_outputs.contains(name) && "golden output already captured in this pass");
    golden_outputs.emplace(name, make_captured_slot(data, count, description));
}

template<typename T>
OutputMatch CrossCheckState::submit_output(size_t worker, const char *name, const T *data,
                                           size_t count, const char *description)
{
    static_assert(SandstoneDataDetails::ValidDataType<T> && !std::is_void_v<T>
                  && !std::is_const_v<T> && !std::is_volatile_v<T>
                  && std::is_trivially_copyable_v<T>);
    assert(phase == Phase::Running);
    assert(name && *name);
    assert(worker < worker_outputs.size());
    assert(data || count == 0);
    assert(count <= size_t(std::numeric_limits<ptrdiff_t>::max() - 1) / sizeof(T));
    auto &outputs = worker_outputs[worker];
    if (!outputs)
        outputs = std::make_unique<OutputMap>();
    auto it = outputs->find(name);
    if (it != outputs->end()) {
        if (it->second.type_token != &CAPTURE_TYPE_TOKEN<T>)
            return OutputMatch::TypeMismatch;
        return compare_output(it->second, data, count);
    }

    auto golden = golden_outputs.find(name);
    if (golden != golden_outputs.end()
            && golden->second.type_token != &CAPTURE_TYPE_TOKEN<T>)
        return OutputMatch::TypeMismatch;
    outputs->emplace(name, make_captured_slot(data, count,
                            golden == golden_outputs.end() ? description : nullptr));
    return OutputMatch::First;
}

} // namespace SandstoneCrossCheck

#endif // SANDSTONE_CROSSCHECK_STATE_HPP
