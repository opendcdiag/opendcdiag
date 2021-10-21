/*
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include "sandstone_p.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>

#if !defined(__linux__)
#  define memfd_create(name, flags)     -1
#  define gettid()                      getpid()
#else
#  define gettid()                      syscall(SYS_gettid)

#  ifndef MFD_CLOEXEC
/* probably an old glibc */
#    ifndef __x86_64__
#      error Unsupported architecture
#    endif
#    define MFD_CLOEXEC 1U
#    define memfd_create(name, flags)     syscall(319, name, flags)
# endif
#endif

#ifndef O_TMPFILE
#  define O_TMPFILE         0
#endif

static int try_open_tmpfile(const char *dir, int ocloexec)
{
    if (dir == NULL || O_TMPFILE == 0)
        return -1;

    return open(dir, O_RDWR | O_TMPFILE | ocloexec, 0600);
}

static int try_open_regular_tmpfile(const char *dir, int ocloexec)
{
    /* opens a regular, temporary file but deletes it before returning */
    static atomic_uint seq_nr = ATOMIC_VAR_INIT(0);
    char *name;
    int fd;
    int saved_errno;

    if (dir == NULL)
        return -1;

    const char *tool_name = strrchr(program_invocation_name, '/');
    if (!tool_name)
        tool_name = program_invocation_name;

    if (asprintf(&name, "%s/%s.tmp.%" PRIdMAX ".%u", dir, tool_name,
                 (intmax_t)gettid(), atomic_fetch_add(&seq_nr, 1)) < 0)
        return -1;
    fd = open(name, O_RDWR | O_CREAT | O_EXCL | ocloexec, 0600);
    saved_errno = errno;
    if (fd >= 0)
        unlink(name);
    free(name);
    errno = saved_errno;
    return fd;
}

int open_memfd(enum MemfdCloexecFlag flag)
{
    int ocloexec = flag ? O_CLOEXEC : 0;
    int fd = memfd_create("", flag ? MFD_CLOEXEC : 0);
    if (fd >= 0)
        return fd;

    // try O_TMPFILE
    static _Atomic(const char *) s_dir = ATOMIC_VAR_INIT(NULL);
    const char *dir = atomic_load_explicit(&s_dir, memory_order_acquire);
    __auto_type opener = &try_open_tmpfile;

    while (true) {
        if (dir == NULL) {
            dir = getenv("XDG_RUNTIME_DIR");
            fd = opener(dir, ocloexec);
        }
        if (fd == -1) {
            dir = getenv("TMPDIR");
            fd = opener(dir, ocloexec);
        }
        if (fd == -1) {
            dir = "/tmp";
            fd = opener(dir, ocloexec);
        }
        if (fd == -1) {
            dir = "/var/tmp";
            fd = opener(dir, ocloexec);
        }

        if (opener == try_open_regular_tmpfile)
            break;
        opener = try_open_regular_tmpfile;
        dir = NULL;
    }

    if (fd == -1) {
        fprintf(stderr, "Could not open memfd (%s) nor regular file (%m)\n",
                strerror(errno));
        abort();
    }

    atomic_store_explicit(&s_dir, dir, memory_order_release);
    return fd;
}

