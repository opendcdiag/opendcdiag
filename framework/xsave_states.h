/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XSAVE_STATES_H
#define XSAVE_STATES_H

// These are only states used for dumping
enum XSave
{
    X87          = 0x0001,            // X87 and MMX state
    SseState     = 0x0002,            // SSE: 128 bits of XMM registers
    Ymm_Hi128    = 0x0004,            // AVX: high 128 bits in YMM registers
    OpMask       = 0x0020,            // AVX512: k0 through k7
    Zmm_Hi256    = 0x0040,            // AVX512: high 256 bits of ZMM0-15
    Hi16_Zmm     = 0x0080,            // AVX512: all 512 bits of ZMM16-31
    Xtilecfg     = 0x20000,           // AMX: XTILECFG register
    Xtiledata    = 0x40000,           // AMX: data in the tiles
    ApxState     = 0x80000,           // APX Extended GPRs
    AvxState     = SseState | Ymm_Hi128,
    Avx512State  = AvxState | OpMask | Zmm_Hi256 | Hi16_Zmm,
    AmxState     = Xtilecfg | Xtiledata,
};

#endif /* XSAVE_STATES_H */
