/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_MULTI_SLICE_GPU_H
#define INC_MULTI_SLICE_GPU_H

/// Struct of indices allowing for full identification of a 'multi-socket' GPU.
/// To avoid confusion, we'd use the term multi-slice GPU.
struct MultiSliceGpu
{
    int gpu_number;      // Contiguous index of a GPU out of all available GPUs. Defined always.
    int device_index;    // When subdevices present, represents a multi-slice GPU index. Otherwise
                         // must be equal to gpu_number.
    int subdevice_index; // When subdevices present, represents an index within a multi-slice GPU.
                         // Otherwise set to -1. Also known as tile or slice.
};

template <>
struct std::hash<MultiSliceGpu>
{
    std::size_t operator()(const MultiSliceGpu& key) const {
        // This should be enough, but we may think of hashing other indices as well.
        return key.gpu_number;
    }
};

inline bool operator<(const MultiSliceGpu& lhs, const MultiSliceGpu& rhs)
{
    return lhs.gpu_number < rhs.gpu_number;
}

inline bool operator==(const MultiSliceGpu& lhs, const MultiSliceGpu& rhs)
{
    return lhs.gpu_number == rhs.gpu_number &&
           lhs.device_index == rhs.device_index &&
           lhs.subdevice_index == rhs.subdevice_index;
}

#endif // INC_MULTI_SLICE_GPU_H
