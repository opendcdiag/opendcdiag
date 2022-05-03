/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DARWIN_PTHREAD_BARRIER_H
#define DARWIN_PTHREAD_BARRIER_H

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pthread_barrier {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    unsigned count;
} pthread_barrier_t;
typedef struct pthread_barrierattr pthread_barrierattr_t;

int pthread_barrier_destroy(pthread_barrier_t *barrier);
int pthread_barrier_init(pthread_barrier_t *barrier,
                         const pthread_barrierattr_t *attr, unsigned count);
int pthread_barrier_wait(pthread_barrier_t *barrier);

#ifdef __cplusplus
}
#endif

#endif // DARWIN_PTHREAD_BARRIER_H
