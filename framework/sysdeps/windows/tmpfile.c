/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include "sandstone_p.h"
#include "sandstone_config.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <windows.h>

#ifndef RtlGenRandom
#  define RtlGenRandom SystemFunction036
#endif

#define WIN_TEMP_MAX_RETIRES            16

DECLSPEC_IMPORT BOOLEAN WINAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);

static unsigned next_random()
{
    static _Atomic(unsigned) counter = 0;

    unsigned result;
    // let's use RtlGenRandom first
    if (RtlGenRandom(&result, sizeof(result)))
        return result;

    // rand_s instead
    if (rand_s(&result) == 0)
        return result;

    // no random
    result = atomic_fetch_add_explicit(&counter, 1, memory_order_relaxed);
    return result;
}

int open_memfd(enum MemfdCloexecFlag flag)
{
    wchar_t tmpname[sizeof SANDSTONE_STRINGIFY(UINT_MAX) ".tmp"];
    wchar_t tmppath[MAX_PATH];

    HANDLE hFile = INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = (flag == MemfdInheritOnExec);
    sa.lpSecurityDescriptor = NULL;

    DWORD getTempPathRes = GetTempPathW(MAX_PATH, tmppath);

    if (getTempPathRes == 0)
        return -1;

    size_t pathlen = wcslen(tmppath);
    if (pathlen >= MAX_PATH - sizeof(tmpname))
        return -1;

    for (int i = 0; hFile == INVALID_HANDLE_VALUE && i < WIN_TEMP_MAX_RETIRES; ++i) {
        wcscat(_ultow(next_random(), tmpname, 36), L".tmp");            // yes, base 36
        DWORD access = GENERIC_READ | GENERIC_WRITE;
        DWORD sharemode = FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE;
        DWORD creation = CREATE_NEW;
        DWORD flags = FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE;

        tmppath[pathlen] = L'\0';
        hFile = CreateFileW(wcscat(tmppath, tmpname), access, sharemode, &sa, creation, flags, NULL);
    }
    if (hFile != INVALID_HANDLE_VALUE)
        return _open_osfhandle((intptr_t)hFile, _O_BINARY | (sa.bInheritHandle ? 0 : _O_NOINHERIT));

    return -1;
}
