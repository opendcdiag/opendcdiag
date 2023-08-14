/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SYSDEPS_DARWIN_GETTID_H
#define SYSDEPS_DARWIN_GETTID_H

#include <pthread.h>
#include <stdint.h>

typedef uint64_t tid_t;

static inline tid_t gettid()
{
    tid_t result;
    pthread_threadid_np(NULL, &result);
    return result;
}

#endif // SYSDEPS_DARWIN_GETTID_H
