/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sandstone_p.h"

static atomic_bool msr_access_denied = ATOMIC_VAR_INIT(false);

static void try_load_kmod()
{
    // this is not thread safe, the atomic is just to prevent data races
    static atomic_bool tried;
    if (atomic_load_explicit(&tried, memory_order_relaxed))
        return;

    if (access("/sys/module/msr", F_OK) < 0) {
        // try loading the module
        pid_t child = fork();
        if (child == 0) {
            // child process
            int devnull = open(_PATH_DEVNULL, O_RDWR | O_CLOEXEC);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            execl("/sbin/modprobe", "/sbin/modprobe", "msr", NULL);
            _exit(1);
        } else if (child > 0) {
            // parent process
            int status;
            int ret;
            EINTR_LOOP(ret, waitpid(child, &status, 0));

            // we don't care if modprobe succeeded or not
        }
    }

    atomic_store_explicit(&tried, true, memory_order_relaxed);
}

bool read_msr(int cpu, uint32_t msr, uint64_t * value)
{
    int fd;
    bool ret = false;
    char filename[sizeof "/dev/cpu/2147483647/msr" + 1];

    if (atomic_load_explicit(&msr_access_denied, memory_order_relaxed)) {
        errno = EACCES;
        return false;
    }
    try_load_kmod();

    sprintf(filename, "/dev/cpu/%i/msr", cpu);
    fd = open(filename, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        if (errno == EACCES)
            atomic_store_explicit(&msr_access_denied, true, memory_order_relaxed);
        return false;
    }
    if (pread(fd, value, sizeof(*value), msr) == sizeof(*value))
        ret = true;

    close(fd);
    return ret;
}

bool write_msr(int cpu, uint32_t msr, uint64_t value)
{
    int fd;
    bool ret = false;
    char filename[sizeof "/dev/cpu/2147483647/msr" + 1];

    if (atomic_load_explicit(&msr_access_denied, memory_order_relaxed)) {
        errno = EACCES;
        return false;
    }
    try_load_kmod();

    sprintf(filename, "/dev/cpu/%i/msr", cpu);
    fd = open(filename, O_WRONLY | O_CLOEXEC);
    if (fd == -1) {
        if (errno == EACCES)
            atomic_store_explicit(&msr_access_denied, true, memory_order_relaxed);
        return false;
    }
    if (pwrite(fd, &value, sizeof(value), msr) == sizeof(value))
        ret = true;

    close(fd);
    return ret;
}
