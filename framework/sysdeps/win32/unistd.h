/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WIN32_UNISTD_H
#define WIN32_UNISTD_H

#include_next <unistd.h>
#include <stdlib.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PIPE_BUF        4096

/* Extra POSIX fucntions we need */

int pipe(int pipefd[2]);

ssize_t pread(int fd, void *buf, size_t count, off_t offset);
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset);

int getpagesize(void);

void sync(void);

#ifdef __cplusplus
}
#endif

#endif
