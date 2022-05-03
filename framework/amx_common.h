/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AMX_COMMON_H
#define AMX_COMMON_H

#ifndef signature_INTEL_ebx
#include <cpuid.h>
#endif
#include <stdint.h>

#if __clang_major__ > 10 || defined(_tile_loadd)
#  define ATTRIBUTE_AMX_TARGET(x)  __attribute__((target(x)))
#else
#  define ATTRIBUTE_AMX_TARGET(x)

// The following was copied from an internal version of Intel's AMX future
// contributions to compilers, dated 2020-03-27. It will match what exists in
// GCC's <amxtileintrin.h>, since the contribution was made from the same tree.
// That file will show up with FSF's Copyright, but as
// <https://www.fsf.org/bulletin/2014/spring/copyright-assignment-at-the-fsf>
// says, "we grant back to contributors a license to use their work as they see
// fit. This means they are free to modify, share, and sublicense their own
// work under terms of their choice."

#define _tile_int8_dp_internal(name,dst,src1,src2)                                      \
      __asm__ volatile                                                      \
        ("{"#name"\t%%tmm"#src2", %%tmm"#src1", %%tmm"#dst"|"#name"\t%%tmm"#dst", %%tmm"#src1", %%tmm"#src2"}" ::)

#define _tile_dpbssd(dst,src1,src2)                                     \
      _tile_int8_dp_internal (tdpbssd, dst, src1, src2)

#define _tile_loadd(dst,base,stride)                                    \
  __asm__ volatile                                                      \
  ("{tileloadd\t(%0,%1,1), %%tmm"#dst"|tileloadd\t%%tmm"#dst", [%0+%1*1]}" \
   :: "r" ((const void*) base), "r" ((long) stride))

#define _tile_stream_loadd(dst,base,stride)                             \
  __asm__ volatile                                                      \
  ("{tileloaddt1\t(%0,%1,1), %%tmm"#dst"|tileloaddt1\t%%tmm"#dst", [%0+%1*1]}"\
   :: "r" ((const void*) base), "r" ((long) stride))

#define _tile_stored(src,base,stride)                                   \
  __asm__ volatile                                                      \
  ("{tilestored\t%%tmm"#src", (%0,%1,1)|tilestored\t[%0+%1*1], %%tmm"#src"}" \
   :: "r" ((void*) base), "r" ((long) stride))

#define _tile_loadconfig(addr)                          \
  __asm__ volatile ("ldtilecfg\t%X0" :: "m" (*((const void **) addr)))

#define _tile_storeconfig(addr)                 \
  __asm__ volatile ("sttilecfg\t%X0" : "=m" (*((void **) addr)) :)

#define _tile_zero(dst)                         \
  __asm__ volatile                              \
  ("tilezero\t%%tmm"#dst ::)

#define _tile_release()                         \
  __asm__ volatile ("tilerelease" ::);
#endif

struct amx_tileconfig
{
    uint8_t palette;
    uint8_t start_row;
    uint8_t reserved[14];

    // Note: documentation lists 8 tile registers, but the layout of this
    // structure (Table 3-1 in the Instruction Set Extension manual revision
    // 040) adds reserved space that matches exactly what it would look like if
    // there were 16 tile registers (which they could access using the REX R, W
    // or B bits, or VEX.vvvv).
    uint16_t colsb[16];
    uint8_t rows[16];
};

struct amx_palette1_info
{
    uint16_t total_tile_bytes;
    uint16_t bytes_per_tile;
    uint16_t bytes_per_row;
    uint16_t max_names;
    uint16_t max_rows;
};

struct tmul_info
{
    long tmul_maxk;
    long tmul_maxn;
};

static inline int amx_tile_max_palette()
{
    unsigned eax, ebx, ecx, edx;
    if (!__get_cpuid_count(0x1d, 0, &eax, &ebx, &ecx, &edx))
        return -1;
    return eax;
}

static inline struct amx_palette1_info amx_palette1_info()
{
    unsigned eax, ebx, ecx, edx;
    struct amx_palette1_info info;
    __cpuid_count(0x1d, 1, eax, ebx, ecx, edx);
    info.total_tile_bytes = eax & 0xffff;
    info.bytes_per_tile = eax >> 16;
    info.bytes_per_row = ebx & 0xffff;
    info.max_names = ebx >> 16;
    info.max_rows = ecx & 0xffff;
    return info;
}

static inline struct tmul_info tmul_info()
{
    unsigned eax, ebx, ecx, edx;
    struct tmul_info info = { -1, -1 };
    if (!__get_cpuid_count(0x1e, 0, &eax, &ebx, &ecx, &edx))
        return info;
    info.tmul_maxk = ebx & 0xff;
    info.tmul_maxn = (ebx >> 8) & 0xffffff;
    return info;
}

#endif
