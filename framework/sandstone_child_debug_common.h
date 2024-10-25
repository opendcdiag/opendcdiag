/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_CHILD_DEBUG_COMMON_H
#define SANDSTONE_CHILD_DEBUG_COMMON_H

#include "sandstone_context_dump.h"

#include <stdint.h>

#ifdef __x86_64__
#ifdef SANDSTONE_DEVICE_CPU
#  include "devicedeps/cpu/cpu_features.h"
#endif

#  include <algorithm>
#  include <cpuid.h>

// get the size of the context to transfer
inline int xsave_size_for_bitvector(uint64_t xsave_bv)
{
    uint32_t eax, ebx, ecx, edx;
    int xsave_size = FXSAVE_SIZE;
    if (!__get_cpuid_count(0xd, 0, &eax, &ebx, &ecx, &edx))
        return xsave_size;

    // did the bit vector disable any bits that are in CPUID?
    uint64_t cpuid_bv = eax | uint64_t(edx) << 32;
    if (cpuid_bv & ~xsave_bv) {
        // yes, find the end of the highest state that we *are* transferring
        int bit = 2;
        uint64_t mask = XSave_Ymm_Hi128;
        xsave_bv &= ~(XSave_SseState | XSave_X87);  // included in FXSAVE
        for ( ; xsave_bv; ++bit, mask <<= 1) {
            if ((xsave_bv & mask) == 0)
                continue;
            xsave_bv &= ~mask;
            __cpuid_count(0xd, bit, eax, ebx, ecx, edx);
            int size = eax;
            int offset = ebx;
            xsave_size = std::max(xsave_size, size + offset);
        }
    } else {
        // no, we'll transfer the entire context
        xsave_size = ebx;
    }
    return xsave_size;
}

inline int get_xsave_size()
{
    return xsave_size_for_bitvector(-1);
}
#else
static int get_xsave_size()
{
    return 0;
}
#endif // x86_64

#endif // SANDSTONE_CHILD_DEBUG_COMMON_H
