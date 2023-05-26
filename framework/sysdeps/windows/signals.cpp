/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sandstone_system.h>
#include <sandstone.h>

#include <windows.h>

#warning "Check if we need to handle SIGINT in one or both of these functions"
void signals_init_global()
{
    SetErrorMode(SEM_FAILCRITICALERRORS);
}

void signals_init_child()
{
    SetErrorMode(SEM_FAILCRITICALERRORS);
}
