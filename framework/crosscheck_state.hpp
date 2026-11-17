/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_CROSSCHECK_STATE_HPP
#define SANDSTONE_CROSSCHECK_STATE_HPP

#include <algorithm>
#include <atomic>
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
    std::shared_ptr<const void> storage;
    size_t count;
    DataType type;
    const void *type_token;
    std::string description;
    LogicalProcessor cpu = LogicalProcessor(-1); // observed host CPU, separate from output ownership
    int first_worker = -1; // -1 denotes init; preserved for the snapshot lifetime.

    std::span<const std::byte> bytes() const;
};

using OutputMap = std::map<std::string, CapturedSlot, std::less<>>;

struct CapturedNode {
    // Published nodes stay immutable and alive until quiescent reset.
    std::string name;
    CapturedSlot slot;
    CapturedNode *next = nullptr;
};

struct OwnerOutputs {
    // Complete submissions to this owner must not overlap; readers only borrow published nodes.
    std::atomic<CapturedNode *> head{nullptr};

    const CapturedSlot *find(std::string_view name) const;
};
static_assert(std::atomic<CapturedNode *>::is_always_lock_free);

enum class OutputMatch { First, Equal, TypeMismatch, CountMismatch, DataMismatch };
OutputMatch compare_output(const CapturedSlot &expected, const void *actual, size_t count);
OutputMatch compare_output(const CapturedSlot &expected, const CapturedSlot &actual);

struct OutputSubmission {
    std::string_view name;
    OwnerOutputs *outputs;
    const CapturedSlot *reference;
    size_t owner;
    int worker;
    LogicalProcessor cpu;

    const CapturedSlot &snapshot() const { return *reference; }

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
    std::unique_ptr<OwnerOutputs[]> owner_outputs;
    size_t owner_count = 0;

    ~CrossCheckState();
    std::span<const OwnerOutputs> outputs() const { return {owner_outputs.get(), owner_count}; }

    // No readers or publishers may remain at this lifecycle boundary.
    void reset(size_t owner_count = 0);
    OutputSubmission output_submission(size_t owner, std::string_view name,
                                       int worker, LogicalProcessor cpu);
    // Called after join; reporting must not change these frozen conclusions.
    std::vector<OutputConclusion> classify_outputs() const;
};

inline OutputSubmission CrossCheckState::output_submission(size_t owner, std::string_view name,
                                                           int worker, LogicalProcessor cpu)
{
    assert(!name.empty());
    assert(owner < owner_count);
    auto &outputs = owner_outputs[owner];
    return {name, &outputs, outputs.find(name), owner, worker, cpu};
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
             description ? description : "", LogicalProcessor(-1), -1 };
}

// Keep fixed-size equality compiler-visible despite first-publication capture.
template<typename T>
inline __attribute__((always_inline)) OutputMatch
OutputSubmission::submit(const T *data, size_t count, const char *description)
{
    static_assert(SandstoneDataDetails::ValidDataType<T> && !std::is_void_v<T>
                  && !std::is_const_v<T> && !std::is_volatile_v<T>
                  && std::is_trivially_copyable_v<T>);
    assert(!name.empty());
    assert(data || count == 0);
    assert(count <= size_t(std::numeric_limits<ptrdiff_t>::max() - 1) / sizeof(T));
    if (!reference) {
        auto slot = make_captured_slot(data, count, description);
        slot.first_worker = worker;
        slot.cpu = cpu;
        auto node = std::make_unique<CapturedNode>(CapturedNode{
                std::string(name), std::move(slot), outputs->head.load(std::memory_order_relaxed)});
        reference = &node->slot;
        outputs->head.store(node.release(), std::memory_order_release);
        return OutputMatch::First;
    }
    if (reference->type_token != &CAPTURE_TYPE_TOKEN<T>)
        return OutputMatch::TypeMismatch;
    if (reference->count != count)
        return OutputMatch::CountMismatch;
    return count == 0 || SandstoneDataDetails::memcmp_equal<
                SandstoneDataDetails::TypeToDataType<T>::Type>(
                    data, reference->storage.get(), count * sizeof(T))
            ? OutputMatch::Equal : OutputMatch::DataMismatch;
}

} // namespace SandstoneCrossCheck

#endif // SANDSTONE_CROSSCHECK_STATE_HPP
