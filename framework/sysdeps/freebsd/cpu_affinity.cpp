/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <pthread.h>
#include <pthread_np.h>

static void set_thread_name(const char *thread_name)
{
    if (thread_name)
        pthread_set_name_np(pthread_self(), thread_name);
}

// FreeBSD's libc has a "fake Linux" API wrapper for us!
// https://github.com/freebsd/freebsd-src/blob/main/lib/libc/gen/sched_getaffinity.c
// https://github.com/freebsd/freebsd-src/blob/main/lib/libc/gen/sched_setaffinity.c
#include "../linux/cpu_affinity.cpp"
