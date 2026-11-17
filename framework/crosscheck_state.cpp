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

void CrossCheckState::reset(size_t owner_count)
{
    inputs.clear();
    std::vector<OutputMap>(owner_count).swap(owner_outputs);
}

std::vector<OutputConclusion> CrossCheckState::classify_outputs(std::span<const int> successful_workers) const
{
    std::vector<OutputConclusion> conclusions;
    if (successful_workers.empty())
        return conclusions;
    auto eligible = [&](const CapturedSlot &slot) {
        return slot.first_worker < 0 || std::any_of(slot.contributors.begin(), slot.contributors.end(),
                [&](int worker) {
            return std::find(successful_workers.begin(), successful_workers.end(), worker)
                    != successful_workers.end();
        });
    };
    std::set<std::string_view> names;
    for (const auto &outputs : owner_outputs) {
        for (const auto &[name, slot] : outputs) {
            if (eligible(slot))
                names.insert(name);
        }
    }
    for (auto name : names) {
        OutputConclusion result{name, {}, -1, false};
        size_t votes = 0;
        for (size_t owner = 0; owner < owner_outputs.size(); ++owner) {
            auto it = owner_outputs[owner].find(name);
            if (it == owner_outputs[owner].end() || !eligible(it->second))
                continue;
            const auto *slot = &it->second;
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
