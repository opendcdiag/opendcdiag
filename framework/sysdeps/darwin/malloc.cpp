/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sandstone_p.h>

#include <errno.h>
#include <malloc/malloc.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#ifndef __SANITIZE_ADDRESS__
static void *bzero_block(void *ptr, size_t len)
{
    return memset(ptr, 0, len);
}

static __attribute__((noinline, noreturn)) void null_pointer_consumption(void *ptr, size_t size)
{
    static const char msg[] = "Out of memory condition\n";
    (void) ptr;
    IGNORE_RETVAL(write(STDERR_FILENO, msg, sizeof(msg) - 1));

    // if the size is non-silly, simulate the Linux OOM killer
    if (size < 256 * 1024 * 1024)
        raise(SIGKILL);
    abort();
}

static inline void *check_null_pointer(void *ptr, size_t size, size_t count = 1)
{
    if (__builtin_expect(!ptr, 0))
        null_pointer_consumption(ptr, size * count);
    return ptr;
}

static inline void *checked_allocation(size_t size, void *block)
{
    check_null_pointer(block, size);
    size = malloc_size(block);
    return bzero_block(block, size);
}

// different from all the rest
int posix_memalign(void **newptr, size_t alignment, size_t size)
{
    *newptr = aligned_alloc(alignment, size);
    return *newptr ? 0 : errno;
}

// pvalloc is valloc rounding up to the actual page size
void *pvalloc(size_t bytes)
{
    bytes = ROUND_UP_TO_PAGE(bytes);
    return valloc(bytes);
}

void *aligned_alloc(size_t alignment, size_t size)
{
    return checked_allocation(size, malloc_zone_memalign(malloc_default_zone(), alignment, size));
}

void *memalign(size_t alignment, size_t size)
{
    return checked_allocation(size, malloc_zone_memalign(malloc_default_zone(), alignment, size));
}

void *valloc(size_t size)
{
    return checked_allocation(size, malloc_zone_valloc(malloc_default_zone(), size));
}

void *malloc(size_t size)
{
    return checked_allocation(size, malloc_zone_malloc(malloc_default_zone(), size));
}

void *calloc(size_t n, size_t size)
{
    // calloc always zeroes memory, so we don't need to do it ourselves
    return check_null_pointer(malloc_zone_calloc(malloc_default_zone(), n, size), n, size);
}

void *realloc(void *ptr, size_t size)
{
    size_t oldsize = malloc_size(ptr);
    void *newptr = check_null_pointer(malloc_zone_realloc(malloc_default_zone(), ptr, size), size);
    size = malloc_size(newptr);

    ptrdiff_t bytestoclear = size - oldsize;
    if (bytestoclear > 0)
        bzero_block(reinterpret_cast<uint8_t *>(newptr) + oldsize, bytestoclear);
    return newptr;
}
#endif // __SANITIZE_ADDRESS__
