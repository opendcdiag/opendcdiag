/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "unistd.h"

#include <io.h>
#include <fcntl.h>

#include <windows.h>

int pipe(int pipefd[2])
{
    return _pipe(pipefd, PIPE_BUF, _O_BINARY);
}

int getpagesize()
{
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return sysinfo.dwPageSize;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
    off_t old = _lseek(fd, offset, SEEK_SET);
    if (old < 0)
        return old;

    count = read(fd, buf, count);
    old = _lseek(fd, old, SEEK_SET);
    if (old < 0)
        return old;
    return count;
}

void sync()
{
    /* nothing to do */
}
