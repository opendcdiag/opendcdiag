/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SYSDEPS_FREEBSD_FUTEX_H
#define SYSDEPS_FREEBSD_FUTEX_H

#include <sys/types.h>
#include <limits.h>

// https://man.freebsd.org/cgi/man.cgi?query=_umtx_op
#include <sys/umtx.h>

static constexpr bool FutexAvailable = true;

static inline int futex_wait(void *ptr, int expected)
{
    return _umtx_op(ptr, UMTX_OP_WAIT_UINT, u_long(expected), nullptr, nullptr);
}

static inline int futex_wake_one(void *ptr)
{
    return _umtx_op(ptr, UMTX_OP_WAKE, 1, nullptr, nullptr);
}

static inline int futex_wake_all(void *ptr)
{
    return _umtx_op(ptr, UMTX_OP_WAKE, INT_MAX, nullptr, nullptr);
}

#endif // SYSDEPS_FREEBSD_FUTEX_H
