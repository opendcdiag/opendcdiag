/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pthread_barrier.h"

int pthread_barrier_destroy(pthread_barrier_t *barrier)
{
    pthread_mutex_destroy(&barrier->mutex);
    pthread_cond_destroy(&barrier->cond);
    return 0;
}

int pthread_barrier_init(pthread_barrier_t *barrier,
                         const pthread_barrierattr_t *attr, unsigned count)
{
    pthread_mutex_init(&barrier->mutex, nullptr);
    pthread_cond_init(&barrier->cond, nullptr);
    barrier->count = count;
    return 0;
}

int pthread_barrier_wait(pthread_barrier_t *barrier)
{
    pthread_mutex_lock(&barrier->mutex);
    if (--barrier->count)
        pthread_cond_wait(&barrier->cond, &barrier->mutex);
    else
        pthread_cond_broadcast(&barrier->cond);
    pthread_mutex_unlock(&barrier->mutex);

    // Note: we don't return PTHREAD_BARRIER_SERIAL_THREAD
    return 0;
}
