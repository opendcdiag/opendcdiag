/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_thread.h"
#include "sandstone_p.h"

#include "gettid.h"

namespace {
struct SandstoneTestThreadAttributes
{
    pthread_attr_t thread_attr;
    SandstoneTestThreadAttributes()
    {
        pthread_attr_init(&thread_attr);
        pthread_attr_setstacksize(&thread_attr, THREAD_STACK_SIZE);
    }
    ~SandstoneTestThreadAttributes()
    {
        pthread_attr_destroy(&thread_attr);
    }
    SandstoneTestThreadAttributes(const SandstoneTestThreadAttributes &) = delete;
    SandstoneTestThreadAttributes &operator=(const SandstoneTestThreadAttributes &) = delete;
};
} // unnamed namespace

[[maybe_unused]] static bool check_run_from_correct_thread()
{
#ifdef __linux__
    // only tested for Linux
    return getpid() == gettid();
#else
    return true;
#endif
}

void SandstoneTestThread::start(RunnerFunction *f, int cpu)
{
    assert(check_run_from_correct_thread());

    static SandstoneTestThreadAttributes thread_attributes;
    auto runner = +[](void *ptr) {
        auto self = static_cast<SandstoneTestThread *>(ptr);
        ::thread_num = self->thread_num;
        return reinterpret_cast<void *>(self->target(self->thread_num));
    };

    thread_num = cpu;
    target = f;
    pthread_create(&thread, &thread_attributes.thread_attr, runner, this);
}

uintptr_t SandstoneTestThread::join()
{
    void *result;
    pthread_join(thread, &result);
    return uintptr_t(result);
}
