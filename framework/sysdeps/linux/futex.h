/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SYSDEPS_LINUX_FUTEX_H
#define SYSDEPS_LINUX_FUTEX_H

#include <limits.h>
#include <linux/futex.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

static constexpr bool FutexAvailable = true;

static inline int futex(void *uaddr, int futex_op, uint32_t val = 0,
                        const struct timespec *timeout = nullptr, uint32_t *uaddr2 = nullptr,
                        uint32_t val3 = 0)
{
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr, val3);
}

static inline int futex_wait(void *ptr, int expected)
{
    return futex(ptr, FUTEX_WAIT, expected);
}

static inline int futex_wake_one(void *ptr)
{
    return futex(ptr, FUTEX_WAKE, 1);
}

static inline int futex_wake_all(void *ptr)
{
    return futex(ptr, FUTEX_WAKE, INT_MAX);
}

#endif // SYSDEPS_LINUX_FUTEX_H
