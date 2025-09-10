/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sys/mman.h"

#include <assert.h>
#include <errno.h>
#include <io.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "windows.h"
#include "memoryapi.h"

#define PROT_MASK       (PROT_READ | PROT_WRITE | PROT_EXEC)
static_assert(PROT_MASK == 7, "PROT_xxx macro values inconsistent");

extern void set_errno_from_last_error(DWORD error); // in errno.cpp

static DWORD map_protection(int prot, int flags)
{
    static const DWORD mapping[] = {
        [PROT_NONE] = PAGE_NOACCESS,
        [PROT_READ] = PAGE_READONLY,
        [PROT_WRITE] = PAGE_READWRITE,
        [PROT_READ | PROT_WRITE] = PAGE_READWRITE,
        [PROT_READ | PROT_EXEC] = PAGE_EXECUTE_READWRITE,
        [PROT_WRITE | PROT_EXEC] = PAGE_EXECUTE_READWRITE,
        [PROT_READ | PROT_WRITE | PROT_EXEC] = PAGE_EXECUTE_READWRITE
    };
    static const DWORD priv_mapping[] = {
        [PROT_NONE] = PAGE_NOACCESS,
        [PROT_READ] = PAGE_WRITECOPY,
        [PROT_WRITE] = PAGE_WRITECOPY,
        [PROT_READ | PROT_WRITE] = PAGE_WRITECOPY,
        [PROT_READ | PROT_EXEC] = PAGE_EXECUTE_WRITECOPY,
        [PROT_WRITE | PROT_EXEC] = PAGE_EXECUTE_WRITECOPY,
        [PROT_READ | PROT_WRITE | PROT_EXEC] = PAGE_EXECUTE_WRITECOPY
    };
    DWORD flProtect = PAGE_NOACCESS;
    if (flags & MAP_PRIVATE) {
        flProtect = priv_mapping[prot & PROT_MASK];
    } else {
        flProtect = mapping[prot & PROT_MASK];
    }
    if (flProtect == 0)
        return 0;
    if (flags & MAP_HUGETLB)
        flProtect |= SEC_LARGE_PAGES;
    return flProtect;
}

static DWORD map_max_protection(int prot, int flags)
{
    static const DWORD mapping[] = {
        [PROT_NONE] = PAGE_NOACCESS,
        [PROT_READ] = PAGE_READWRITE,
        [PROT_WRITE] = PAGE_READWRITE,
        [PROT_READ | PROT_WRITE] = PAGE_READWRITE,
        [PROT_READ | PROT_EXEC] = PAGE_EXECUTE_READWRITE,
        [PROT_WRITE | PROT_EXEC] = PAGE_EXECUTE_READWRITE,
        [PROT_READ | PROT_WRITE | PROT_EXEC] = PAGE_EXECUTE_READWRITE
    };
    static const DWORD priv_mapping[] = {
        [PROT_NONE] = PAGE_NOACCESS,
        [PROT_READ] = PAGE_WRITECOPY,
        [PROT_WRITE] = PAGE_WRITECOPY,
        [PROT_READ | PROT_WRITE] = PAGE_WRITECOPY,
        [PROT_READ | PROT_EXEC] = PAGE_EXECUTE_WRITECOPY,
        [PROT_WRITE | PROT_EXEC] = PAGE_EXECUTE_WRITECOPY,
        [PROT_READ | PROT_WRITE | PROT_EXEC] = PAGE_EXECUTE_WRITECOPY
    };
    DWORD flProtect = PAGE_NOACCESS;
    if (flags & MAP_PRIVATE) {
        if (flags & MAP_ANONYMOUS)
            flProtect = PAGE_EXECUTE_WRITECOPY;
        else
            flProtect = priv_mapping[prot & PROT_MASK];
    } else {
        flProtect = mapping[prot & PROT_MASK];
    }
    if (flags & MAP_HUGETLB)
        flProtect |= SEC_LARGE_PAGES;
    return flProtect;
}

static DWORD map_access(int prot, int flags)
{
    DWORD dwDesiredAccess = 0;
    switch (flags & (MAP_PRIVATE | MAP_SHARED | MAP_ANONYMOUS)) {
    case MAP_PRIVATE | MAP_SHARED:
    case MAP_PRIVATE | MAP_SHARED | MAP_ANONYMOUS:
    case 0:
        return 0;

    case MAP_SHARED | MAP_ANONYMOUS:
    case MAP_ANONYMOUS:
        // Grant full access initially and then restrict it because
        // VirtualProtect requires that new protection be compatible
        // with protection specified when the view was mapped
        dwDesiredAccess = FILE_MAP_EXECUTE;
        break;

    case MAP_PRIVATE | MAP_ANONYMOUS:
        dwDesiredAccess = FILE_MAP_EXECUTE | FILE_MAP_COPY;
        break;

    case MAP_PRIVATE:
        if (prot & PROT_EXEC)
            dwDesiredAccess = FILE_MAP_EXECUTE | FILE_MAP_COPY;
        else
            dwDesiredAccess = FILE_MAP_COPY;
        break;

    case MAP_SHARED:
        if (prot & PROT_EXEC)
            dwDesiredAccess |= FILE_MAP_EXECUTE;
        if (prot & PROT_WRITE)
            dwDesiredAccess |= FILE_MAP_WRITE;
        if (prot & PROT_READ)
            dwDesiredAccess |= FILE_MAP_READ;
        break;
    }

    if (flags & MAP_HUGETLB)
        dwDesiredAccess |= FILE_MAP_LARGE_PAGES;

    return dwDesiredAccess;
}

void *mmap(void *addr, size_t length, int prot, int flags, int fildes, off_t off)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;

    DWORD flProtect = map_protection(prot, flags);
    DWORD dwDesiredAccess = map_access(prot, flags);
    if (flProtect == 0 || dwDesiredAccess == 0) {
        errno = EINVAL;
        return MAP_FAILED;
    }

    // address requested for MapViewOfFileEx must be aligned to 64KB
    if (((uintptr_t) addr & 0xFFFF) != 0) {
        if (flags & MAP_FIXED) {
           errno = EINVAL;
           return MAP_FAILED;
        } else {                     // otherwise, let the OS choose the address
            addr = NULL;
        }
    }

    if ((flags & MAP_ANONYMOUS) == 0) {
        // if fd == -1, we'll get an error here, so go along with the flow
        struct _stat64 st;
        if (_fstat64(fildes, &st) < 0)
            return MAP_FAILED;       //"mmap: could not determine filesize"

        if ((length + off) > st.st_size)
            length = st.st_size - off;

        hFile = (HANDLE)_get_osfhandle(fildes);
    }

    uint32_t lsize = length & 0xFFFFFFFF;
    uint32_t hsize = (length >> 32) & 0xFFFFFFFF;
    LPSECURITY_ATTRIBUTES lpFileMappingAttributes = NULL;
    LPCWSTR lpName = NULL;
    DWORD flMaxProtect = map_max_protection(prot, flags);
    HANDLE hmap = CreateFileMappingW(hFile, lpFileMappingAttributes, flMaxProtect,
                                     hsize, lsize, lpName);
    if (!hmap) {
        set_errno_from_last_error(GetLastError());
        return MAP_FAILED;
    }

    uint32_t l = off;
    uint32_t h = (uint64_t)off >> 32;
    void *temp = MapViewOfFileEx(hmap, dwDesiredAccess, h, l, length, addr);

    if (!temp) {
        DWORD err = GetLastError();
        CloseHandle(hmap);
        SetLastError(err);
        set_errno_from_last_error(err);
        return MAP_FAILED;
    }

    if ((flags & MAP_FIXED) && temp != addr) {
       CloseHandle(hmap);
       UnmapViewOfFile(temp);
       errno = EEXIST;      // similar to Linux's MAP_FIXED_NOREPLACE
       return MAP_FAILED;
    }

    // Revert to requested protection for anonymous maps
    DWORD flOldProtect;
    if (!VirtualProtect(temp, length, flProtect, &flOldProtect)) {
        DWORD err = GetLastError();
        CloseHandle(hmap);
        UnmapViewOfFile(temp);
        SetLastError(err);
        set_errno_from_last_error(GetLastError());
        return MAP_FAILED;
    }

    // ignore errors
    CloseHandle(hmap);

    return temp;
}

int munmap(void *addr, size_t len)
{
    return !UnmapViewOfFile(addr);
}

int mprotect(void *addr, size_t len, int prot)
{
    DWORD dwOldProtect;
    // find out if the original mapping was done with MAP_PRIVATE
    int flags = 0;
    MEMORY_BASIC_INFORMATION meminfo = {0};
    if (sizeof(meminfo) != VirtualQuery(addr, &meminfo, sizeof(meminfo)))
        return -1;
    if ((meminfo.AllocationProtect & PAGE_WRITECOPY) || (meminfo.AllocationProtect & PAGE_EXECUTE_WRITECOPY))
        flags = MAP_PRIVATE;

    DWORD flNewProtect = map_protection(prot, flags);
    errno = EINVAL;
    if (!VirtualProtect(addr,
                        len,
                        flNewProtect,
                        &dwOldProtect  //old setting
                        ))
        return -1;
    return 0;
}

int madvise(void *addr, size_t length, int advice)
{
    if (advice == MADV_DONTNEED) {
        if (DiscardVirtualMemory(addr, length) == ERROR_SUCCESS)
            return 0;
        set_errno_from_last_error(GetLastError());
        return -1;
    }

    errno = EINVAL;
    return -1;

}
