/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "win32_stdlib.h"

#include <errno.h>
#include <malloc.h>
#include <string.h>

#include <sandstone_p.h>

#include <new>

#include <windows.h>

#define DEFAULT_ALIGNMENT       2*__alignof(void *)

static __attribute__((noinline, noreturn)) void null_pointer_consumption(void *ptr)
{
    static const char msg[] = "Out of memory condition\n";
    (void) ptr;
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
    OutputDebugStringA(msg);

    TerminateProcess((HANDLE)-1, STATUS_NO_MEMORY);
    __builtin_unreachable();
}

static inline void *check_null_pointer(void *ptr)
{
    if (__builtin_expect(!ptr, 0))
        null_pointer_consumption(ptr);
    return ptr;
}

extern "C" {
void *aligned_alloc(size_t alignment, size_t size)
{
#ifdef _UCRT
    // Use ucrt's _aligned_recalloc
    return check_null_pointer(_aligned_recalloc(NULL, 1, size, alignment));
#endif

    // old VC6 CRT doesn't have _aligned_recalloc, so we align and memset
    void *ptr = check_null_pointer(_aligned_malloc(size, alignment));
    return memset(ptr, 0, size);
}

int posix_memalign(void **newptr, size_t alignment, size_t size)
{
    *newptr = aligned_alloc(alignment, size);
    return *newptr ? 0 : errno;
}

void *valloc(size_t size)
{
    return aligned_alloc(4096, size);
}

// pvalloc is valloc rounding up to the actual page size
void *pvalloc(size_t bytes)
{
    bytes = ROUND_UP_TO_PAGE(bytes);
    return valloc(bytes);
}

/*
 * POSIX requires that we be able to free the memory returned above
 * with free(), so we need to override it and everything that uses it too.
 */
void *malloc(size_t size)
{
    return aligned_alloc(DEFAULT_ALIGNMENT, size);
}

// need to override calloc so we use the _aligned_xxx functions instead
// (because of free() below)
void *calloc(size_t n, size_t size)
{
    size_t total;
    if (__builtin_mul_overflow(n, size, &total))
        return check_null_pointer(NULL);
    return aligned_alloc(DEFAULT_ALIGNMENT, total);
}

size_t aligned_msize(void *ptr)
{
    if (ptr) {
        return _msize(((void**)ptr)[-1]) - DEFAULT_ALIGNMENT - sizeof(void*) + 1;
    }
    return 0;
}

void *realloc(void *ptr, size_t size)
{
#ifdef _UCRT
    // Use ucrt's _aligned_recalloc
    return check_null_pointer(_aligned_recalloc(ptr, 1, size, DEFAULT_ALIGNMENT));
#endif

    size_t oldsize = aligned_msize(ptr);
    void *newptr = check_null_pointer(_aligned_realloc(ptr, size, DEFAULT_ALIGNMENT));
    size = aligned_msize(newptr);

    ptrdiff_t bytestoclear = size - oldsize;
    if (bytestoclear > 0)
        memset((char *)newptr + oldsize, 0, bytestoclear);
    return newptr;
}

void free(void *ptr)
{
    _aligned_free(ptr);
}

char *strdup(const char *str)
{
    auto newstr = static_cast<char *>(malloc(strlen(str) + 1));
    return static_cast<char *>(memcpy(newstr, str, strlen(str) + 1));
}

char *strndup(const char *str, size_t n)
{
    size_t len = strnlen(str, n);
    auto newstr = static_cast<char *>(malloc(len + 1));
    newstr = static_cast<char *>(memcpy(newstr, str, len));
    newstr[len] = '\0';
    return newstr;
}
} // extern "C"

// Provide C++ operators new and delete. For each overload, there should be
// three functions: the operator new, the (old) unsized operator delete and the
// C++14 sized deallocation. We provide that even if __cpp_sized_deallocation
// isn't defined.

// regular new and delete
void *operator new(size_t size)
{
    return aligned_alloc(DEFAULT_ALIGNMENT, size);
}

void operator delete(void *ptr) noexcept
{
    free(ptr);
}

void operator delete(void *ptr, size_t) noexcept
{
    free(ptr);
}

// array new and delete
void *operator new[](size_t size)
{
    return operator new(size);
}

void operator delete[](void *ptr) noexcept
{
    free(ptr);
}

void operator delete[](void *ptr, size_t) noexcept
{
    free(ptr);
}

// aligning new and delete
void *operator new(size_t size, std::align_val_t alignment)
{
    return aligned_alloc(size_t(alignment), size);
}

void operator delete(void *ptr, std::align_val_t) noexcept
{
    free(ptr);
}

void operator delete(void *ptr, size_t, std::align_val_t) noexcept
{
    free(ptr);
}

// array, aligning new and delete
void *operator new[](size_t size, std::align_val_t alignment)
{
    return operator new(size, alignment);
}

void operator delete[](void *ptr, std::align_val_t) noexcept
{
    free(ptr);
}

void operator delete[](void *ptr, size_t, std::align_val_t) noexcept
{
    free(ptr);
}

// nothrow new and delete
// (the compiler never generates calls to the nothrow delete)
void *operator new(size_t size, std::nothrow_t) noexcept
{
    return operator new(size);
}

void operator delete(void *ptr, std::nothrow_t) noexcept
{
    free(ptr);
}

void operator delete(void *ptr, size_t, std::nothrow_t) noexcept
{
    free(ptr);
}

// nothrow array new and delete
void *operator new[](size_t size, std::nothrow_t) noexcept
{
    return operator new(size);
}

void operator delete[](void *ptr, std::nothrow_t) noexcept
{
    free(ptr);
}

void operator delete[](void *ptr, size_t, std::nothrow_t) noexcept
{
    free(ptr);
}

// nothrow aligning new and delete
void *operator new(size_t size, std::align_val_t alignment, std::nothrow_t) noexcept
{
    return operator new(size, alignment);
}

void operator delete(void *ptr, std::align_val_t, std::nothrow_t) noexcept
{
    free(ptr);
}

void operator delete(void *ptr, size_t, std::align_val_t, std::nothrow_t) noexcept
{
    free(ptr);
}

// nothrow array, aligning new and delete
void *operator new[](size_t size, std::align_val_t alignment, std::nothrow_t) noexcept
{
    return operator new(size, alignment);
}

void operator delete[](void *ptr, std::align_val_t, std::nothrow_t) noexcept
{
    free(ptr);
}

void operator delete[](void *ptr, size_t, std::align_val_t, std::nothrow_t) noexcept
{
    free(ptr);
}
