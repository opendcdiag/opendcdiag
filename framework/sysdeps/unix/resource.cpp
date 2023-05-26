/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sandstone_system.h>
#include <sandstone_config.h>
#include <sandstone_p.h>

#include <algorithm>

#include <stdlib.h>
#include <stdio.h>
#include <sys/resource.h>

void resource_init_global()
{
    // rounded up so it doesn't look precise
    static const int FileDescriptorOverhead = 64;
    static const int FileDescriptorsPerThread = 4;
    rlim_t desired_fd_count = num_cpus() * FileDescriptorsPerThread + FileDescriptorOverhead;
    desired_fd_count = ROUND_UP_TO(desired_fd_count, 256);

    struct rlimit oldlimit;
    if (getrlimit(RLIMIT_NOFILE, &oldlimit) < 0) {
        perror("getrlimit");
        exit(EX_OSERR);
    }
    if (oldlimit.rlim_cur < desired_fd_count) {
        // increase it
        struct rlimit newlimit;
        newlimit.rlim_cur = desired_fd_count;
        newlimit.rlim_max = std::max(desired_fd_count, oldlimit.rlim_max);
        if (setrlimit(RLIMIT_NOFILE, &newlimit) < 0) {
            int exit_reason = errno == EPERM ? EXIT_NOPERMISSION : EX_OSERR;
            fprintf(stderr, "%s: failed to increase file descriptor limit: %m\n",
                    program_invocation_name);
            fprintf(stderr, "The number of file descriptors for this system (soft %zu, hard %zu) is "
                            "too low for the number of CPUs being tested (%d).\n"
                            "Either increase the number of allowed file descriptors to %zu or "
                            "decrease the number of CPUs being tested, using taskset(1)"
#if SANDSTONE_RESTRICTED_CMDLINE
                            " or schedtool(1).\n"
#else
                            ", or schedtool(1), or the --cpuset command-line option.\n"
#endif
                            "If using bash, type 'help ulimit' for information on increasing the "
                            "file descriptor limit.\n",
                    oldlimit.rlim_cur, oldlimit.rlim_max, num_cpus(), desired_fd_count);
            exit(exit_reason);
        }
    }
}
