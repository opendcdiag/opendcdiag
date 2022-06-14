/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 *
 * Run 'In Field Scan' test provided by the Linux kernel on compatible hardware
 *
 * Requires `ifs.ko` to be loaded in the Linux kernel, as well as
 * firmware test blob data in `/lib/firmware/...`. Supported since
 * 5.17.0.
 *
 */

#define _GNU_SOURCE 1
#include <sandstone.h>

#if defined(__x86_64__) && defined(__linux__)

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#define PATH_SYS_IFS_BASE "/sys/devices/virtual/misc/"

#define BUFLEN 256 // kernel module prints at most a 64bit value

static bool write_file(int dfd, const char *filename, const char* value)
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

static ssize_t read_file(int dfd, const char *filename, char buf[static restrict BUFLEN])
{
        int fd = openat(dfd, filename, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            return fd;

        ssize_t n = read(fd, buf, BUFLEN);
        close(fd);

        /* trim newlines */
        while (n > 0 && buf[n - 1] == '\n') {
                buf[n - 1] = '\0';
                --n;
        }
        return n;
}

static int scan_init(struct test *test)
{
        int ifs0 = open(PATH_SYS_IFS_BASE "intel_ifs_0", O_DIRECTORY | O_PATH | O_CLOEXEC);
        if (ifs0 < 0) {
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
                ifs0 = open(PATH_SYS_IFS_BASE "intel_ifs_0", O_DIRECTORY | O_PATH | O_CLOEXEC);
        }


        if (ifs0 < 0 || faccessat(ifs0, "run_test", R_OK, 0) < 0 ||
                faccessat(ifs0, "status", R_OK, 0) < 0 || faccessat(ifs0, "details", R_OK, 0) < 0) {
                log_info("not supported (missing kernel module, firmware, or invalid HW)");
                close(ifs0);
                return -EOPNOTSUPP;
        }

        /* see if we can open run_test for writing */
        int fd = openat(ifs0, "run_test", O_WRONLY);
        int saved_errno = errno;
        close(fd);
        close(ifs0);
        if (fd < 0) {
                log_info("could not open intel_ifs_0/run_test for writing (not running as root?): %m");
                close(fd);
                return -saved_errno;
        }

        return EXIT_SUCCESS;
}

static int scan_run(struct test *test, int cpu)
{
        char result[BUFLEN], my_cpu[BUFLEN];
        DIR *base;
        int basefd;
        bool any_test_succeded = false;

        if (cpu_info[cpu].thread_id != 0)
                return EXIT_SKIP;

        basefd = open(PATH_SYS_IFS_BASE, O_DIRECTORY | O_CLOEXEC);
        if (basefd < 0)
                return -errno;      // shouldn't happen
        base = fdopendir(basefd);
        if (base == NULL)
            return -errno;          // shouldn't happen

        snprintf(my_cpu, sizeof(my_cpu), "%d\n", cpu_info[cpu].cpu_number);

        struct dirent *ent;
        while ((ent = readdir(base)) != NULL) {
                static const char prefix[] = "intel_ifs_";
                const char *d_name = ent->d_name;
                if (ent->d_type != DT_DIR || memcmp(ent->d_name, prefix, strlen(prefix)) != 0)
                        continue;

                int ifsfd = openat(basefd, d_name, O_DIRECTORY | O_PATH | O_CLOEXEC);
                if (ifsfd < 0) {
                        log_warning("Could not start test for \"%s\": %m", d_name);
                        continue;
                }

                /* start the test; this blocks until the test has finished */
                if (!write_file(ifsfd, "run_test", my_cpu)) {
                        log_warning("Could not start test for \"%s\": %m", d_name);
                        close(ifsfd);
                        continue;
                }

                /* read result */
                if (read_file(ifsfd, "status", result) < 0) {
                        log_warning("Could not obtain result for \"%s\": %m", d_name);
                        close(ifsfd);
                        continue;
                }

                if (memcmp(result, "fail", strlen("fail")) == 0) {
                        /* failed, get status code */
                        ssize_t n = read_file(ifsfd, "details", result);
                        close(ifsfd);
                        if (n < 0) {
                                log_error("Test \"%s\" failed but could not retrieve error condition", d_name);
                        } else {
                                log_error("Test \"%s\" failed with condition: %s", d_name, result);
                        }
                        break;
                } else if (memcmp(result, "pass", strlen("pass")) == 0) {
                        log_debug("Test \"%s\" passed", d_name);
                        any_test_succeded = true;
                }

                close(ifsfd);
        }

        closedir(base);
        return any_test_succeded ? EXIT_SUCCESS : EXIT_SKIP;
}

DECLARE_TEST(ifs, "Intel In-Field Scan (IFS) hardware selftest")
    .quality_level = TEST_QUALITY_PROD,
    .test_init = scan_init,
    .test_run = scan_run,
    .desired_duration = -1,
    .fracture_loop_count = -1,
    .max_threads = 1,
END_DECLARE_TEST

#endif // __x86_64__ && __linux__
