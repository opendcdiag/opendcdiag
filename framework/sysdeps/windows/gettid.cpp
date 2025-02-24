/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gettid.h"

#include <windows.h>

tid_t gettid() noexcept
{
    return GetCurrentThreadId();
}
