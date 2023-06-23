/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SYSDEPS_GENERIC_FUTEX_H
#define SYSDEPS_GENERIC_FUTEX_H

static constexpr bool FutexAvailable = false;

static inline int futex_wait(void *ptr, int expected)
{
    return -1;
}

static inline int futex_wake_one(void *ptr)
{
    return -1;
}

static inline int futex_wake_all(void *ptr)
{
    return -1;
}

#endif // SYSDEPS_GENERIC_FUTEX_H
