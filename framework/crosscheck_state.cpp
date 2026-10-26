/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck_state.hpp"

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

OutputMatch compare_output(const CapturedSlot &expected, const CapturedSlot *actual)
{
    if (!actual)
        return OutputMatch::Missing;
    if (expected.type_token != actual->type_token)
        return OutputMatch::TypeMismatch;
    return compare_output(expected, actual->storage.get(), actual->count);
}

void CrossCheckState::reset(size_t worker_count)
{
    inputs.clear();
    golden_outputs.clear();
    std::vector<std::unique_ptr<OutputMap>>(worker_count).swap(worker_outputs);
    phase = Phase::Inactive;
}

} // namespace SandstoneCrossCheck
