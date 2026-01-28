/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_TEST_DATA_H
#define INC_TEST_DATA_H

#include "sandstone_chrono.h"

#include <atomic>
#include "gettid.h"

enum ThreadState : int {
    thread_not_started = 0,
    thread_running = 1,
    thread_failed = 2,
    thread_debugged = 3,
    thread_succeeded = -1,
    thread_skipped = -2,
};

namespace PerThreadData {
struct Common
{
    std::atomic<ThreadState> thread_state;

    /* file descriptor for logging */
    int log_fd;

    /* Records number of messages logged per thread of each test */
    std::atomic<int> messages_logged;

    /* Records the number of bytes log_data'ed per thread */
    std::atomic<unsigned> data_bytes_logged;

    enum class Flag {
        CallbackCalled = 0x0001,
    };
    uint32_t thread_flags;
    friend constexpr inline uint32_t operator|(Flag f1, Flag f2)
    {
        return unsigned(f1) | unsigned(f2);
    }
    friend constexpr inline uint32_t operator&(uint32_t flags, Flag f2)
    {
        return flags & unsigned(f2);
    }

    MonotonicTimePoint fail_time;
    bool has_failed() const
    {
        return fail_time > MonotonicTimePoint{};
    }
    bool has_skipped() const
    {
        return fail_time < MonotonicTimePoint{};
    }

    void init()
    {
        thread_state.store(thread_not_started, std::memory_order_relaxed);
        messages_logged.store(0, std::memory_order_relaxed);
        data_bytes_logged.store(0, std::memory_order_relaxed);
        fail_time = MonotonicTimePoint{};
        thread_flags = {};
    }
};

struct alignas(64) Main : Common
{
    DeviceRange device_range;
};

struct alignas(64) TestCommon : Common
{
    /* Number of iterations of the inner loop (aka #times test_time_condition called) */
    uint32_t inner_loop_count;
    uint32_t inner_loop_count_at_fail;

    /* Thread ID */
    std::atomic<tid_t> tid;

    void init()
    {
        Common::init();
        inner_loop_count = inner_loop_count_at_fail = 0;
    }
};
} // namespace PerThreadData

#endif /* INC_TEST_DATA_H */
