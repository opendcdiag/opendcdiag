/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SYSDEPS_DARWIN_FUTEX_H
#define SYSDEPS_DARWIN_FUTEX_H

#include <limits.h>
#include <stdint.h>

// The Darwin kernel exposes a set of __ulock_{wait,wait2,wake} APIs in
// https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.81.2/bsd/sys/ulock.h,
extern "C" {
// -------- BEGIN OS Declarations --------
extern int __ulock_wait2(uint32_t operation, void *addr, uint64_t value,
    uint64_t timeout, uint64_t value2);
extern int __ulock_wake(uint32_t operation, void *addr, uint64_t wake_value);

/*
 * operation bits [7, 0] contain the operation code.
 */
#define UL_COMPARE_AND_WAIT             1
#define UL_COMPARE_AND_WAIT_SHARED      3
#define UL_COMPARE_AND_WAIT64           5
#define UL_COMPARE_AND_WAIT64_SHARED    6

/*
 * operation bits [15, 8] contain the flags for __ulock_wake
 */
#define ULF_WAKE_ALL                    0x00000100
#define ULF_WAKE_THREAD                 0x00000200
#define ULF_WAKE_ALLOW_NON_OWNER        0x00000400

/*
 * operation bits [15, 8] contain the flags for __ulock_wake
 */
#define ULF_WAKE_ALL                    0x00000100
#define ULF_WAKE_THREAD                 0x00000200
#define ULF_WAKE_ALLOW_NON_OWNER        0x00000400

/*
 * operation bits [31, 24] contain the generic flags
 */
#define ULF_NO_ERRNO                    0x01000000

// -------- END OS Declarations --------
} // extern "C"

static constexpr bool FutexAvailable = true;

static inline int futex_wait(void *ptr, int expected)
{
    return __ulock_wait2(UL_COMPARE_AND_WAIT, ptr, uint64_t(expected), UINT64_MAX, 0);
}

static inline int futex_wake_one(void *ptr)
{
    return __ulock_wake(UL_COMPARE_AND_WAIT, ptr, 0);
}

static inline int futex_wake_all(void *ptr)
{
    return __ulock_wake(UL_COMPARE_AND_WAIT | ULF_WAKE_ALL, ptr, 0);
}

#endif // SYSDEPS_DARWIN_FUTEX_H
