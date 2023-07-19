/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SYSDEPS_FREEBSD_GETTID_H
#define SYSDEPS_FREEBSD_GETTID_H

#include <sys/thr.h>

typedef long tid_t;

static inline tid_t gettid()
{
    tid_t result;
    thr_self(&result);
    return result;
}

#endif // SYSDEPS_FREEBSD_GETTID_H
