/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sandstone_p.h>

#include <errno.h>
#include <malloc_np.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>            // for MALLOC_ALLIGN's use of ffsl()
#include <unistd.h>

#ifndef __SANITIZE_ADDRESS__
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

static inline void *check_null_pointer(void *ptr, size_t size)
{
    if (__builtin_expect(!ptr, 0))
        null_pointer_consumption(ptr, size);
    return ptr;
}

static inline void *checked_allocation(size_t size, void *block)
{
    return check_null_pointer(block, size);
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
    return checked_allocation(size, mallocx(size, MALLOCX_ZERO | MALLOCX_ALIGN(alignment)));
}

void *memalign(size_t alignment, size_t size)
{
    return aligned_alloc(alignment, size);
}

void *valloc(size_t size)
{
    return checked_allocation(size, mallocx(size, MALLOCX_ZERO | MALLOCX_ALIGN(4096)));
}

void *malloc(size_t size)
{
    return checked_allocation(size, mallocx(size, MALLOCX_ZERO));
}

void *calloc(size_t n, size_t size)
{
    // calloc always zeroes memory, so we don't need to do it ourselves
    return check_null_pointer(mallocx(size * n, MALLOCX_ZERO), size);
}

void *realloc(void *ptr, size_t size)
{
    return check_null_pointer(rallocx(ptr, size, MALLOCX_ZERO), size);
}
#endif // __SANITIZE_ADDRESS__
