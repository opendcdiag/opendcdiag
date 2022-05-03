/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"
#include "sandstone_p.h"

#include <assert.h>
#include <fcntl.h>
#include <unistd.h>

size_t memfpt_current_high_water_mark()
{
    if (!SandstoneConfig::Debug)
        return 0;

    int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
    if (fd == -1)
        return 0;

    char buf[4096];     // should suffice for now
    ssize_t nread = read(fd, buf, sizeof buf);
    if (nread < 0)
        return 0;
    close(fd);

    assert(nread < ssize_t(sizeof(buf)));
    buf[nread] = '\0';

    // find the "VmHWM" line, which was added to the kernel on v2.6.17
    // (since it's never the first, we can search using the line break)
    static const char hwmtext[] = "\nVmHWM:";
    char *hwm = strstr(buf, hwmtext);
    if (hwm == nullptr)
        return 0;

    hwm += strlen(hwmtext);

    // strtoull skips whitespaces
    return strtoull(hwm, nullptr, 10);
}
