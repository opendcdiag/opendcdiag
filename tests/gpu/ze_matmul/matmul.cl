/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

__kernel void mxm(__global int* a, __global int* b, __global int* out) {
    uint row = get_global_id(0);
    uint col = get_global_id(1);

    // alternatively: uint index = get_global_linear_id();
    uint index = row * get_global_size(0) + col;
    out[index] = a[index] * b[index];
}
