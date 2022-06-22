/****************************************************************************
**
** Copyright (C) 2019 Intel Corporation.
**
** Permission is hereby granted, free of charge, to any person obtaining a copy
** of this software and associated documentation files (the "Software"), to deal
** in the Software without restriction, including without limitation the rights
** to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
** copies of the Software, and to permit persons to whom the Software is
** furnished to do so, subject to the following conditions:
**
** The above copyright notice and this permission notice shall be included in
** all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
** THE SOFTWARE.
**
****************************************************************************/

#ifndef FORKFD_H
#define FORKFD_H

#include <fcntl.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h> // to get the POSIX flags

#if _POSIX_SPAWN > 0
#  include <spawn.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define FFD_CLOEXEC             1
#define FFD_NONBLOCK            2
#define FFD_USE_FORK            4

#define FFD_CHILD_PROCESS (-2)

#define FFDW_NOHANG             1       /* WNOHANG */
#define FFDW_NOWAIT             2       /* WNOWAIT */

struct forkfd_info {
    int32_t code;
    int32_t status;
};

int forkfd(int flags, pid_t *ppid);
int vforkfd(int flags, pid_t *ppid, int (*childFn)(void *), void *token);
int forkfd_wait4(int ffd, struct forkfd_info *info, int options, struct rusage *rusage);
static inline int forkfd_wait(int ffd, struct forkfd_info *info, struct rusage *rusage)
{
    return forkfd_wait4(ffd, info, 0, rusage);
}
int forkfd_close(int ffd);

#if _POSIX_SPAWN > 0
/* only for spawnfd: */
#  define FFD_SPAWN_SEARCH_PATH   O_RDWR

int spawnfd(int flags, pid_t *ppid, const char *path, const posix_spawn_file_actions_t *file_actions,
            posix_spawnattr_t *attrp, char *const argv[], char *const envp[]);
#endif

#ifdef __cplusplus
}
#endif

#endif // FORKFD_H
