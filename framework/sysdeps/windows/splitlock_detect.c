/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdalign.h>
#include <stdbool.h>
#include <windows.h>

/* Yes, this is a correct use of volatile! */
static volatile int splitlock_cached_result = 0;   /* positive: enabled; negative: disabled */

static LONG WINAPI splitlock_exception_handler(EXCEPTION_POINTERS *info)
{
    (void) info;

    splitlock_cached_result = 1;
    return EXCEPTION_CONTINUE_SEARCH;
}

static void do_detection()
{
    alignas(64) char buffer[64 + sizeof(int)];
    int *misaligned = (int*)&buffer[64 - 2];
    int v = 1;

    __asm__ volatile ("lock xchg %1, %0" : "=m" (*misaligned), "+r" (v));
}

bool splitlock_enforcement_enabled()
{
    int v = splitlock_cached_result;
    if (v)
        return v > 0;

    // Add an exception handler, run the test, then remove it
    PVOID h = AddVectoredExceptionHandler(true, splitlock_exception_handler);
    splitlock_cached_result = -1;
    do_detection();

    RemoveVectoredExceptionHandler(h);

    return splitlock_cached_result > 0;
}
