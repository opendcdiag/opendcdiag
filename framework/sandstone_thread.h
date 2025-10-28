/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_THREAD
#define SANDSTONE_THREAD

#include <functional>

#include <pthread.h>
#include <stdint.h>

struct SandstoneTestThread
{
    using RunnerFunction = uintptr_t (int);
    void start(RunnerFunction*, int);
    uintptr_t join();

    pthread_t thread;
    RunnerFunction *target;
    int thread_num;
};

#endif // SANDSTONE_THREAD
