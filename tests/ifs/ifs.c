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

#include <sandstone.h>

#if defined(__x86_64__) && defined(__linux__)

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static pthread_mutex_t scanmutex = PTHREAD_MUTEX_INITIALIZER;

#define BUFLEN 256 // kernel module prints at most a 64bit value

static bool write_file(const char* filename, const char* value)
{
        size_t l = strlen(value);

        int fd = open(filename, O_WRONLY);
        if (fd == -1)
                return false;
        if (write(fd, value, l) != l) {
                close(fd);
                return false;
        }
        close(fd);
        return true;
}

static int scan_init(struct test *test)
{
        if (access("/sys/devices/system/cpu/cpu0/ifs/status", R_OK) != 0) {
                /* modprobe kernel driver, ignore errors entirely here */
                pid_t pid = fork();
                if (pid == 0) {
                        execl("/sbin/modprobe", "/sbin/modprobe", "intel_ifs", NULL);

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
        }

        /* first check if there is basic kernel support with the API we support */
        if ((access("/sys/devices/system/cpu/ifs/run_test", W_OK) != 0) ||
            (access("/sys/devices/system/cpu/cpu0/ifs/status", R_OK) != 0) != 0 ) {
                log_info("not supported (missing kernel module, firmware, or invalid HW)");
                return EXIT_SKIP;
        }

        if (!write_file("/sys/devices/system/cpu/ifs/run_test", "1\n")) {
                log_info("run_test write failed");
                return EXIT_SKIP;
        }

        return 0;
}

static int scan_run(struct test *test, int cpu)
{
        FILE *file;
        char filename[PATH_MAX];
        char result[BUFLEN];

        pthread_mutex_lock(&scanmutex);

        sprintf(filename, "/sys/devices/system/cpu/cpu%d/ifs/status", cpu_info[cpu].cpu_number);

        for (;;) {
                int r = 0;

                file = fopen(filename, "r");
                if (!file) {
                        pthread_mutex_unlock(&scanmutex);
                        log_info("status fopen(): %m");
                        return EXIT_SKIP;
                }
                result[0] = 0;
                if (!fgets(result, sizeof(result), file)) {
                        int e = errno;
                        pthread_mutex_unlock(&scanmutex);
                        if (e == EBUSY) {
                                if (r++ > 80) { // 2sec max
                                        log_warning("timed out waiting for test to complete");
                                        return EXIT_SKIP;
                                }
                                fclose(file);
                                usleep(25000); // 25ms
                                continue;
                        }

                        log_info("status fgets(): %m");
                        return EXIT_SKIP;
                }

                fclose(file);
                break;
        }

        pthread_mutex_unlock(&scanmutex);

        if (strncmp(result, "fail", BUFLEN) == 0)
                // core is defective, should be offlined by user
                report_fail_msg("IFS: cpu failed self-test");

        return 0;
}

DECLARE_TEST(ifs, "IFS hardware selftest")
    .quality_level = TEST_QUALITY_BETA,
    .test_init = scan_init,
    .test_run = scan_run,
    .desired_duration = -1,
    .fracture_loop_count = -1,
    .max_threads = 1,
END_DECLARE_TEST

#endif // __x86_64__ && __linux__