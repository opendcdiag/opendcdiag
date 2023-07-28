/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_CONTEXT_DUMP_H
#define SANDSTONE_CONTEXT_DUMP_H


#include <stdio.h>

// macOS doesn't consider itself to be Unix?
#if defined(__unix__) || defined(__APPLE__)
#  include <sys/ucontext.h>
#else
typedef struct _CONTEXT mcontext_t;
#endif  // __unix__

#define FXSAVE_SIZE     0x200

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __APPLE__
extern void dump_gprs(FILE *, const mcontext_t);
#else
extern void dump_gprs(FILE *, const mcontext_t *);
#endif
extern void dump_xsave(FILE *, const void *xsave_area, size_t xsave_size, int xsave_dump_mask);

#ifdef __cplusplus
}
#endif  // __cplusplus


#endif  // SANDSTONE_CONTEXT_DUMP_H
