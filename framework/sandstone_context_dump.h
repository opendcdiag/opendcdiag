/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_CONTEXT_DUMP_H
#define SANDSTONE_CONTEXT_DUMP_H

#include <stdio.h>

#if defined(__APPLE__)
#  include <sys/ucontext.h>
typedef mcontext_t SandstoneMachineContext;
#elif defined(__unix__)
#  include <sys/ucontext.h>
typedef const mcontext_t *SandstoneMachineContext;
#else
typedef const struct _CONTEXT *SandstoneMachineContext;
#endif  // __unix__

#define FXSAVE_SIZE     0x200

#ifdef __cplusplus
# include <string>

extern "C" {
#endif

extern void dump_gprs(FILE *, SandstoneMachineContext);
extern void dump_xsave(FILE *, const void *xsave_area, size_t xsave_size, int xsave_dump_mask);

#ifdef __cplusplus
}

void dump_gprs(std::string &out, SandstoneMachineContext);
void dump_xsave(std::string &out, const void *xsave_area, size_t xsave_size, int xsave_dump_mask);
#endif  // __cplusplus

#endif  // SANDSTONE_CONTEXT_DUMP_H
