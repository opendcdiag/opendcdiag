/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_thread.h"
#include "sandstone_p.h"

#include "gettid.h"

#include <sys/mman.h>

namespace {
struct SandstoneTestThreadAttributes
{
    static constexpr size_t GuardSize = 8192;
    pthread_attr_t thread_attr;
    unsigned char *stacks_block;
    SandstoneTestThreadAttributes()
        : stacks_block(allocate_stack_block())
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

    static unsigned char *allocate_stack_block();
    void update_with_stack_for(int cpu);
};
} // unnamed namespace

#ifndef _WIN32
unsigned char *SandstoneTestThreadAttributes::allocate_stack_block()
{
    size_t size = num_cpus() * (THREAD_STACK_SIZE + GuardSize);
    void *map = mmap(nullptr, size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (map == MAP_FAILED)
        return nullptr;

    auto ptr = static_cast<unsigned char *>(map);
    for (int i = 0; i < num_cpus(); ++i) {
        ptr += GuardSize;
        IGNORE_RETVAL(mprotect(ptr, THREAD_STACK_SIZE, PROT_READ | PROT_WRITE));
        ptr += THREAD_STACK_SIZE;
    }
    return ptr;
}

void SandstoneTestThreadAttributes::update_with_stack_for(int cpu)
{
    if (!stacks_block)
        return;
    unsigned char *stacktop = stacks_block;
    stacktop -= (THREAD_STACK_SIZE + GuardSize) * unsigned(cpu);
    pthread_attr_setstack(&thread_attr, stacktop - THREAD_STACK_SIZE, THREAD_STACK_SIZE);
}
#else
unsigned char *SandstoneTestThreadAttributes::allocate_stack_block()
{
    return nullptr;
}
void SandstoneTestThreadAttributes::update_with_stack_for(int)
{
}
#endif


[[maybe_unused]] static bool check_run_from_correct_thread()
{
#ifdef __linux__
    // only tested for Linux
    return getpid() == gettid();
#else
    return true;
#endif
}

SandstoneTestThread::SandstoneTestThread(RunnerFunction *f, int cpu):
    target(f),
    thread_num(cpu)
{
    assert(check_run_from_correct_thread());

    static SandstoneTestThreadAttributes thread_attributes;
    auto runner = +[](void *ptr) {
        auto self = static_cast<SandstoneTestThread *>(ptr);
        ::thread_num = self->thread_num;
        sApp->test_thread_data(self->thread_num)->tid.store(gettid());
        auto clear_tid = scopeExit([self] { sApp->test_thread_data(self->thread_num)->tid.store(0, std::memory_order_relaxed); });
        return reinterpret_cast<void *>(self->target(self->thread_num));
    };

    thread_attributes.update_with_stack_for(cpu);
    int err = pthread_create(&thread, &thread_attributes.thread_attr, runner, this);
    if (err == 0) {
        started = true;
    } else {
        errno = err; perror("SandstoneTestThread");
    }
}

SandstoneTestThread::~SandstoneTestThread()
{
    // join if not joined explicitly yet..
    join();
}

bool SandstoneTestThread::join()
{
    if (started) {
        void *result = nullptr;
        pthread_join(thread, &result);
        started = false;
        return true;
    }
    return false;
}
