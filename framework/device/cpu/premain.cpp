/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(__AVX__) || defined(__SSE4_1__)
#  error "You probably want to compile this file for a lower CPU."
#endif

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __ELF__
#  include <elf.h>
#  include <sys/auxv.h>
#endif

#include "sandstone.h"
#include "cpuid_internal.h"

// from cpu_device.cpp
extern const cpu_features_t minimum_cpu_features;

#if defined(AT_EXECPATH) && !defined(AT_EXECFN)
// FreeBSD uses AT_EXECPATH instead of AT_EXECFN
//#  define AT_EXECFN AT_EXECPATH
#endif
#if defined(AT_EXECFN)
#  if !defined(__GLIBC_PREREQ) || !__GLIBC_PREREQ(2, 16)
// On some ELF systems (Linux, FreeBSD, etc.), there's actually a fourth
// permissible main() parameter:
//
//   int main(int argc, char **argv, char **environ, void *auxv)
//
// Glibc only passes it on PowerPC platform. On other platforms, we can get to
// it by going past the NULL pointer that terminates the 'environ' array (see
// figure 3.9 in https://www.uclibc.org/docs/psABI-x86_64.pdf for more info).
//
// getauxval() was added to glibc 2.16.
static unsigned long getauxval(int type)
{
    static const auto auxv_base = []() {
        char **ptr = environ;       // unistd.h
        while (*ptr)
            ++ptr;
        ++ptr;
        return reinterpret_cast<const Elf_Auxinfo *>(ptr);
    }();
    for (auto ptr = auxv_base; ptr->a_type != AT_NULL; ++ptr) {
        if (ptr->a_type == type)
            return ptr->a_un.a_val;
    }
    return 0;
}
#  endif

static void fallback_exec(char **argv)
{
    static const char fallback[] = SANDSTONE_FALLBACK_EXEC;
    char buf[PATH_MAX];

    if (strlen(fallback) == 0)
        return;

    // AT_EXECFN was added to Linux on 2.6.27, so we should be fine. We use
    // AT_EXECFN instead of argv[0] because the kernel always gives us the full
    // path to the executable, whereas argv[0] is what our parent process
    // decided to give us. Alternative: readlink("/proc/self/exe").
    const char *execfn = reinterpret_cast<const char *>(getauxval(AT_EXECFN));
    if (!execfn || strlen(execfn) >= sizeof(buf))
        return;

    strcpy(buf, execfn);
    char *lastslash = strrchr(buf, '/');
    if (!lastslash || (buf + sizeof(buf) - lastslash) < sizeof(fallback))
        return;

    *++lastslash = '\0';
    strcpy(lastslash, fallback);

    // Security check: only execute that binary if it is either owned by the
    // current user, by root, or by the same user that owns the current
    // executable.
    struct stat st;
    int fd = open(buf, O_PATH);
    if (fd == -1)
        return;
    if (fstat(fd, &st) == -1)
        goto noexec;
    if (st.st_uid != 0 && st.st_uid != getuid()) {
        struct stat stself;
        if (stat("/proc/self/exe", &stself) == -1)
            goto noexec;
        if (st.st_uid != stself.st_uid)
            goto noexec;
    }

    IGNORE_RETVAL(fexecve(fd, argv, environ));

noexec:
    close(fd);
}
#else
static void fallback_exec(char **) {}
#endif

extern "C" {
__attribute__((constructor(101), used))
static void premain(int argc, char **argv, char **envp)
{
    (void) argc;
    (void) envp;

    // initialize CPU detection
    cpu_features = detect_cpu();
    if (minimum_cpu_features & ~cpu_features)
        fallback_exec(argv);
    check_missing_features(cpu_features, minimum_cpu_features);
}
}
