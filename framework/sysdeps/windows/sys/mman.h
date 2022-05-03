/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WIN32_SYS_MMAN_H
#define WIN32_SYS_MMAN_H

/* Emulate the POSIX mmap() function with VirtualAlloc
 * https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
 * https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
 * https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree
 * https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-discardvirtualmemory
 */

#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PROT_NONE       0x00
#define PROT_READ       0x01
#define PROT_WRITE      0x02
#define PROT_EXEC       0x04

#define MAP_SHARED      0x01
#define MAP_PRIVATE     0x02
#define MAP_FIXED       0x04
#define MAP_ANON        0x10
#define MAP_ANONYMOUS   MAP_ANON
#define MAP_HUGETLB     0x08

#define MAP_FAILED      ((void *)-1)

// We don't support replacing, so all MAP_FIXED is implicitly MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE MAP_FIXED

void *mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off);
int munmap(void *addr, size_t len);
int mprotect(void *addr, size_t len, int prot);

/* Linux-specific */

#define MADV_DONTNEED   0x01        /* will use DiscardVirtualMemory() */

int madvise(void *addr, size_t length, int advice);

#ifdef __cplusplus
}
#endif

#endif
