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
    SandstoneTestThread(RunnerFunction *f, int cpu = 0);
    ~SandstoneTestThread();

    bool join();

    pthread_t thread;
    RunnerFunction* const target{ nullptr };

    const int thread_num{ -1 };
    bool started{ false };
};

#endif // SANDSTONE_THREAD
