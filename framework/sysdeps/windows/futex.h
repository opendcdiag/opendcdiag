/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SYSDEPS_WIN32_FUTEX_H
#define SYSDEPS_WIN32_FUTEX_H

#include <windows.h>

static constexpr bool FutexAvailable = true;

static inline int futex_wait(void *ptr, int expected)
{
    return WaitOnAddress(ptr, &expected, sizeof(expected), INFINITE) ? 0 : -1;
}

static inline int futex_wake_one(void *ptr)
{
    WakeByAddressOne(ptr);
    return 0;
}

static inline int futex_wake_all(void *ptr)
{
    WakeByAddressAll(ptr);
    return 0;
}

#endif // SYSDEPS_WIN32_FUTEX_H
