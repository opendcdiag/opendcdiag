/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_MULTI_SLICE_GPU_H
#define INC_MULTI_SLICE_GPU_H

#include <boost/functional/hash.hpp>

#include <compare>

/// Struct of indices allowing for full identification of a 'multi-socket' GPU.
/// To avoid confusion, we'd use the term multi-slice GPU.
struct MultiSliceGpu
{
    int gpu_number;      // Contiguous index of a GPU out of all available GPUs. Defined always.
    int device_index;    // When subdevices present, represents a multi-slice GPU index. Otherwise
                         // must be equal to gpu_number.
    int subdevice_index; // When subdevices present, represents an index within a multi-slice GPU.
                         // Otherwise set to -1. Also known as tile or slice.

    friend constexpr std::strong_ordering operator<=>(const MultiSliceGpu& lhs, const MultiSliceGpu& rhs) noexcept = default;
};

template <>
struct std::hash<MultiSliceGpu>
{
    std::size_t operator()(const MultiSliceGpu& key) const {
        std::size_t seed = 0;
        boost::hash_combine(seed, key.gpu_number);
        boost::hash_combine(seed, key.device_index);
        boost::hash_combine(seed, key.subdevice_index);
        return seed;
    }
};

#endif // INC_MULTI_SLICE_GPU_H
