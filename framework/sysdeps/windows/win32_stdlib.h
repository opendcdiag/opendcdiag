/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

/* meson passes -include through to the assembler for .S files, which clobbers them */
#ifndef __ASSEMBLER__

#ifndef WIN32_STDLIB_H
#define WIN32_STDLIB_H

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

/* not stdlib.h, but injected here because we're lazy;
 * prints the GetLastError() message instead of errno. */
void win32_perror(const char *s);

#ifdef __cplusplus
}
#endif

#endif

#endif /* __ASSEMBLER__ */
