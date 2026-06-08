/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifdef SPIRV_KERNELS_FORMAT
#define GLOBAL_BARRIER // undefined
#else
#define GLOBAL_BARRIER global_barrier();
#endif

__kernel void mxm(__global int* a, __global int* b, __global int* out, const uint cols, const uint internal_loops_n)
{
    uint r = get_local_id(0);
    uint c = get_local_id(1);

    GLOBAL_BARRIER

    uint local_i = r * cols + c;
    // We're using the fact that group count is only 1 dimensional:
    //              - Group Index -   ----------------       Group Size     -------------------
    uint global_i = get_group_id(0) * get_local_size(0) * get_local_size(1) * get_local_size(2) + local_i;

    out[global_i] = 0xffffffff;
    for (uint i = 0; i < internal_loops_n; i++) {
        volatile int res = a[local_i] * b[local_i]; /* volatile: disable compiler optimizations*/
        out[global_i] &= *(int*)(&res);
    }

    GLOBAL_BARRIER
}
