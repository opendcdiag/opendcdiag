/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include_next <sched.h>     // sched_yield, etc.

#ifndef WIN32_SCHED_H
#define WIN32_SCHED_H

#include <x86intrin.h>

static inline int sched_getcpu(void)
{
    // On Windows, we can use rdtscp from user mode (introduced on HSW)
    unsigned tscaux = -1;

    __rdtscp(&tscaux);  // TSC_AUX

    return (int)tscaux;
}

#endif /* WIN32_SCHED_H */
