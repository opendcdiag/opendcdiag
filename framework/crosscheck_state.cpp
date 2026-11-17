/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck_state.hpp"

#include <set>

namespace SandstoneCrossCheck {

std::span<const std::byte> CapturedSlot::bytes() const
{
    size_t size = SandstoneDataDetails::type_size(type);
    assert(count <= size_t(std::numeric_limits<ptrdiff_t>::max() - 1) / size);
    assert(storage || count == 0);
    return { static_cast<const std::byte *>(storage.get()), count * size };
}

OutputMatch compare_output(const CapturedSlot &expected, const void *actual, size_t count)
{
    if (count != expected.count)
        return OutputMatch::CountMismatch;
    if (count == 0)
        return OutputMatch::Equal;
    assert(actual);
    using namespace SandstoneDataDetails;
    size_t stride = type_size(expected.type);
    assert(count <= size_t(std::numeric_limits<ptrdiff_t>::max() - 1) / stride);
    size_t meaningful = type_real_size(expected.type);
    bool equal = meaningful == stride
            ? std::memcmp(actual, expected.storage.get(), count * stride) == 0
            : memcmp_offset_strided(actual, expected.storage.get(), count * stride,
                                    stride, meaningful) < 0;
    return equal ? OutputMatch::Equal : OutputMatch::DataMismatch;
}

OutputMatch compare_output(const CapturedSlot &expected, const CapturedSlot &actual)
{
    if (expected.type_token != actual.type_token)
        return OutputMatch::TypeMismatch;
    return compare_output(expected, actual.storage.get(), actual.count);
}

const CapturedSlot *OwnerOutputs::find(std::string_view name) const
{
    for (auto *node = head.load(std::memory_order_acquire); node; node = node->next) {
        if (node->name == name)
            return &node->slot;
    }
    return nullptr;
}

CrossCheckState::~CrossCheckState()
{
    reset();
}

void CrossCheckState::reset(size_t new_owner_count)
{
    inputs.clear();
    for (const auto &outputs : this->outputs()) {
        auto *node = outputs.head.load(std::memory_order_relaxed);
        while (node) {
            auto *next = node->next;
            delete node;
            node = next;
        }
    }
    owner_outputs.reset();
    owner_count = 0;
    if (new_owner_count) {
        owner_outputs = std::make_unique<OwnerOutputs[]>(new_owner_count);
        owner_count = new_owner_count;
    }
}

std::vector<OutputConclusion> CrossCheckState::classify_outputs() const
{
    std::vector<OutputConclusion> conclusions;
    std::set<std::string_view> names;
    for (const auto &outputs : this->outputs()) {
        for (auto *node = outputs.head.load(std::memory_order_acquire); node; node = node->next)
            names.insert(node->name);
    }
    for (auto name : names) {
        OutputConclusion result{name, {}, -1, false};
        size_t votes = 0;
        for (size_t owner = 0; owner < owner_count; ++owner) {
            const auto *slot = owner_outputs[owner].find(name);
            if (!slot)
                continue;
            if (!result.groups.empty()) {
                const auto *first = result.groups.front().front().slot;
                if (first->type_token != slot->type_token || first->count != slot->count)
                    result.has_type_or_count_mismatch = true;
            }
            auto group = std::find_if(result.groups.begin(), result.groups.end(), [&](const auto &group) {
                return compare_output(*group.front().slot, *slot) == OutputMatch::Equal;
            });
            if (group == result.groups.end())
                result.groups.push_back({{owner, slot}});
            else
                group->push_back({owner, slot});
            ++votes;
        }
        for (size_t i = 0; i < result.groups.size(); ++i) {
            if (result.groups[i].size() > votes / 2)
                result.majority_group = int(i);
        }
        conclusions.push_back(std::move(result));
    }
    return conclusions;
}

} // namespace SandstoneCrossCheck
