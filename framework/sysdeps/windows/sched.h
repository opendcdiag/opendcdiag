/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include_next <sched.h>     // sched_yield, etc.

#ifndef WIN32_SCHED_H
#define WIN32_SCHED_H

// implemened in cpu_affinity.cpp
int sched_getcpu(void);

#endif /* WIN32_SCHED_H */
