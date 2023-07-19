/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SYSDEPS_WIN32_GETTID_H
#define SYSDEPS_WIN32_GETTID_H

#include <windows.h>

typedef DWORD tid_t;

static inline tid_t gettid()
{
    return GetCurrentThreadId();
}

#endif // SYSDEPS_WIN32_GETTID_H
