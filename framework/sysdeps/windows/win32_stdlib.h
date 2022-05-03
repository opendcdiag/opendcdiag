/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

/* meson passes -include through to the assembler for .S files, which clobbers them */
#ifndef __ASSEMBLER__

#ifndef WIN32_STDLIB_H
#define WIN32_STDLIB_H

// Force the assembler to not to emit aligned AVX instructions
//
// printf 'asm(\n'
// for i in vmovapd vmovaps vmovdqa vmovdqa32 vmovdqa64; do
//     printf '    \".macro %s args:vararg\\n\"\n    \"    %s \\\\args\\n\"\n    \".endm\\n\"\n' $i ${i/a/u}
// done
// printf ');\n'
asm(
    ".macro vmovapd args:vararg\n"
    "    vmovupd \\args\n"
    ".endm\n"
    ".macro vmovaps args:vararg\n"
    "    vmovups \\args\n"
    ".endm\n"
    ".macro vmovdqa args:vararg\n"
    "    vmovdqu \\args\n"
    ".endm\n"
    ".macro vmovdqa32 args:vararg\n"
    "    vmovdqu32 \\args\n"
    ".endm\n"
    ".macro vmovdqa64 args:vararg\n"
    "    vmovdqu64 \\args\n"
    ".endm\n"
);

#define _CRT_RAND_S
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef rand_r
#  undef rand_r
#endif

int rand_r(unsigned int *);
long int random(void);
double drand48(void);
long lrand48(void);
long mrand48(void);

int posix_memalign(void **memptr, size_t alignment, size_t size);
void *aligned_alloc(size_t alignment, size_t size);
void *valloc(size_t size);

#ifdef __cplusplus
}
#endif

#endif

#endif /* __ASSEMBLER__ */
