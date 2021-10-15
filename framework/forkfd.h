/*
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(__unix__)
#  include "forkfd/forkfd.h"
#elif !defined(SANDSTONE_FORKFD_H)
#define SANDSTONE_FORKFD_H

#include <sys/types.h>
#include <errno.h>
#include <stdint.h>

#if _POSIX_SPAWN > 0
#  include <spawn.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define FFD_CLOEXEC  1
#define FFD_NONBLOCK 2

#define FFD_CHILD_PROCESS (-2)

struct forkfd_info {
    int32_t code;
    int32_t status;
};

static int forkfd(int flags, pid_t *ppid)
{
    (void) flags;
    *ppid = -1;
    errno = ENOSYS;
    return -1;
}
int forkfd_wait(int ffd, struct forkfd_info *info, ...)
{
    (void) ffd;
    (void) info;
    errno = ENOSYS;
    return -1;
}
int forkfd_close(int ffd)
{
    (void) ffd;
    errno = ENOSYS;
    return -1;
}


#ifdef __cplusplus
}
#endif

#endif // FORKFD_H
