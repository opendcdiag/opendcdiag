/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include "sandstone_p.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <io.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <windows.h>

#ifndef RtlGenRandom
#  define RtlGenRandom SystemFunction036
#endif
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

static bool is_dir_writable(const wchar_t *dir)
{
    if (!dir)
        return false;

    size_t len = wcslen(dir);
    if (!len)
        return false;
    if (dir[len - 1] == L'\\')
        return _waccess(dir, W_OK) == 0;

    // append a backslash so we confirm it's a directory
    wchar_t path[MAX_PATH];
    wcscpy(path, dir);
    wcscat(path, L"\\");
    return _waccess(path, W_OK) == 0;
}

static const wchar_t *find_alternate_temp_dir()
{
    static const wchar_t *dirname = NULL;
    if (dirname)
        return dirname;

    dirname = _wgetenv(L"TEMP");
    if (is_dir_writable(dirname))
        return dirname;

    dirname = _wgetenv(L"TMP");
    if (is_dir_writable(dirname))
        return dirname;

    return NULL;
}

// fills in the temporary directory in tmpname and returns the length of the path
// (including the terminating backslash)
static size_t fill_tmpdir(wchar_t tmpname[MAX_PATH])
{
    size_t len = GetTempPathW(MAX_PATH, tmpname);
    if (len) {
        wcscat(tmpname, L"\\");
        if (is_dir_writable(tmpname))
            return len;
    }

    const wchar_t *othertmp = find_alternate_temp_dir();
    if (!othertmp) {
        // use the CWD as a last resort
        wcscpy(tmpname, L".\\");
        return 2;
    }

    wcscpy(tmpname, othertmp);
    wcscat(tmpname, L"\\");
    return wcslen(tmpname);
}

int open_memfd(enum MemfdCloexecFlag flag)
{
    wchar_t tmppath[MAX_PATH];
    wchar_t *tmpname = tmppath + fill_tmpdir(tmppath);
    HANDLE hFile = INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = (flag == MemfdInheritOnExec);
    sa.lpSecurityDescriptor = NULL;

    for (int i = 0; hFile == INVALID_HANDLE_VALUE && i < 16; ++i) {
        wcscat(_ultow(next_random(), tmpname, 36), L".tmp");            // yes, base 36
        DWORD access = GENERIC_READ | GENERIC_WRITE;
        DWORD sharemode = FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE;
        DWORD creation = CREATE_NEW;
        DWORD flags = FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE;
        hFile = CreateFileW(tmppath, access, sharemode, &sa, creation, flags, NULL);
    }
    if (hFile != INVALID_HANDLE_VALUE)
        return _open_osfhandle((intptr_t)hFile, _O_BINARY | (sa.bInheritHandle ? 0 : _O_NOINHERIT));

    return -1;
}

