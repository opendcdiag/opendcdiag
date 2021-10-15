/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_CONTEXT_DUMP_H
#define SANDSTONE_CONTEXT_DUMP_H


#include <stdio.h>

#ifdef __unix__
#  include <sys/ucontext.h>
#else
// do we want to define something for Windows?
typedef struct {} mcontext_t;
#endif  // __unix__

#define FXSAVE_SIZE     0x200

#ifdef __cplusplus
extern "C" {
#endif

extern void dump_gprs(FILE *, const mcontext_t *);
extern void dump_xsave(FILE *, const void *xsave_area, size_t xsave_size, int xsave_dump_mask);

#ifdef __cplusplus
}
#endif  // __cplusplus


#endif  // SANDSTONE_CONTEXT_DUMP_H
