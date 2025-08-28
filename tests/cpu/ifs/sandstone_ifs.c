/*
 * Copyright 2022-2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE 1
#include <sandstone.h>

#if defined(__x86_64__) && defined(__linux__)

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sandstone_ifs.h"

bool compare_error_codes(unsigned long long code, unsigned long long expected)
{
    /* Error code is stored in 39:32 bits */
    if (((code >> 32) & 0xFF) == expected)
        return true;

    return false;
}

bool write_file(int dfd, const char *filename, const char* value)
{
        size_t l = strlen(value);
        int fd = openat(dfd, filename, O_WRONLY | O_CLOEXEC);
        if (fd == -1)
                return false;
        if (write(fd, value, l) != l) {
                close(fd);
                return false;
        }
        close(fd);
        return true;
}

ssize_t read_file_fd(int fd, char buf[BUFLEN])
{
        ssize_t n = read(fd, buf, BUFLEN);
        close(fd);

        /* trim newlines */
        while (n > 0 && buf[n - 1] == '\n') {
                buf[n - 1] = '\0';
                --n;
        }
        return n;
}

ssize_t read_file(int dfd, const char *filename, char buf[BUFLEN])
{
        int fd = openat(dfd, filename, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            return fd;

        return read_file_fd(fd, buf);
}

int open_sysfs_ifs_base(const char *sys_path)
{
        /* see if driver is loaded, otherwise try to load it */
        int sys_ifs_fd = open(sys_path, O_DIRECTORY | O_PATH | O_CLOEXEC);
        if (sys_ifs_fd < 0) {
                /* modprobe kernel driver, ignore errors entirely here */
                pid_t pid = fork();
                if (pid == 0) {
                        execl("/sbin/modprobe", "/sbin/modprobe", "-q", "intel_ifs", NULL);

                        /* don't print an error if /sbin/modprobe wasn't found, but
                           log_debug() is fine (since the parent is waiting, we can
                           write to the FILE* because it's unbuffered) */
                        log_debug("Failed to run modprobe: %s", strerror(errno));
                        _exit(errno);
                } else if (pid > 0) {
                        /* wait for child */
                        int status, ret;
                        do {
                            ret = waitpid(pid, &status, 0);
                        } while (ret < 0 && errno == EINTR);
                } else {
                        /* ignore failure to fork() -- extremely unlikely */
                }

                /* try opening again now that we've potentially modprobe'd */
                sys_ifs_fd = open(sys_path, O_DIRECTORY | O_PATH | O_CLOEXEC);
        }
    return sys_ifs_fd;
}

#endif
