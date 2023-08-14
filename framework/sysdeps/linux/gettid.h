/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SYSDEPS_LINUX_GETTID_H
#define SYSDEPS_LINUX_GETTID_H

#include <unistd.h>

typedef pid_t tid_t;

#if (__GLIBC__ * 10000 + __GLIBC_MINOR__) < 20030
#  include <sys/syscall.h>
static inline tid_t gettid()
{
    return syscall(SYS_gettid);
}
#endif

#endif // SYSDEPS_LINUX_GETTID_H
