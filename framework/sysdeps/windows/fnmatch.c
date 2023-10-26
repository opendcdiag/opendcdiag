/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "fnmatch.h"

#include <assert.h>
#include <shlwapi.h>

int fnmatch(const char *pattern, const char *name, int flags)
{
    assert(flags == 0);
    (void) flags;

    return PathMatchSpecA(name, pattern) ? 0 : 1;
}
