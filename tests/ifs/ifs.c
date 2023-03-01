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
 * 6.2
 *
 */

#define _GNU_SOURCE 1
#include <sandstone.h>

#if defined(__x86_64__) && defined(__linux__)

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sandstone_ifs.h"


static bool load_test_file(int dfd, int batch_fd, struct test *test, ifs_test_t *ifs_info)
{
    char current_buf[BUFLEN], status_buf[BUFLEN];
    int next_test, current_test, enforce_run;

    /* read both files status and current_batch */
    read_file(dfd, "status", status_buf);
    read_file_fd(batch_fd, current_buf);

    /* when previous run has a status of fail, skip test */
    enforce_run = get_testspecific_knob_value_uint(test, "enforce_run", -1);
    if (memcmp(status_buf, "fail", strlen("fail")) == 0 && enforce_run != 1 )
    {
        log_warning("Previous run failure found! Refusing to run");
        return false;
    }

    /* get interactive test file if provided by user */
    next_test = get_testspecific_knob_value_uint(test, "test_file", -1);
    if (next_test == -1)
    {
        if (memcmp(current_buf, "none", strlen("none")) == 0)
            next_test = DEFAULT_TEST_ID;
        else
        {
            current_test = (int) strtoul(current_buf, NULL, 0);
            if (current_test < 0 && errno == ERANGE)
            {
                log_info("Cannot parse current_batch value: %s", current_buf);
                return false;
            }

            if (memcmp(status_buf, "untested", strlen("untested")) == 0)
            {
                log_info("Test file %s remains untested, so try again", current_buf);
                next_test = current_test;
            }
            else
                next_test = current_test + 1;
        }
    }

    /* write next test file ID */
    sprintf(ifs_info->image_id, "%#x", next_test);
    if (write_file(dfd, "current_batch", ifs_info->image_id))
    {
        return true;
    }
    else if (errno == ENOENT)
    {
        /* when next blob does not exists, it will fail with
         * ENOENT error. Then, start from the begining */
        log_info("Test file %s, does not exists. Starting over from 0x%x", ifs_info->image_id, DEFAULT_TEST_ID);
        sprintf(ifs_info->image_id, "%#x", DEFAULT_TEST_ID);
        if (write_file(dfd, "current_batch", ifs_info->image_id))
        {
            return true;
        }
    }

    return false;
}

static int scan_common_init(struct test *test)
{
        /* Get info struct */
        ifs_test_t *ifs_info = test->data;

        /* see if driver is loaded */
        char sys_path[PATH_LEN];
        int n = snprintf(sys_path, PATH_LEN, PATH_SYS_IFS_BASE "%s", ifs_info->sys_dir);
        assert(n < sizeof(sys_path));
        int ifs_fd = kernel_driver_is_loaded(sys_path);

        /* see if we can open run_test for writing */
        int run_fd = openat(ifs_fd, "run_test", O_WRONLY);
        int saved_errno = errno;
        if (run_fd < 0) {
                log_info("could not open %s/run_test for writing (not running as root?): %m", ifs_info->sys_dir);
                close(run_fd);
                return -saved_errno;
        }

        /* Check on images if supported */
        if (ifs_info->image_support)
        {
            /* see if we can open current_batch for writing */
            int batch_fd = openat(ifs_fd, "current_batch", O_RDWR);
            saved_errno = errno;
            if (batch_fd < 0) {
                    log_info("could not open %s/current_batch for writing (not running as root?): %m", ifs_info->sys_dir);
                    close(batch_fd);
                    return -saved_errno;
            }
            close(run_fd);

            /* load test file */
            if (!load_test_file(ifs_fd, batch_fd, test, ifs_info))
                return EXIT_SKIP;

            /* read image version if available and log it */
            if (read_file(ifs_fd, "image_version", ifs_info->image_version) <= 0) {
                    strncpy(ifs_info->image_version, "unknown", BUFLEN);
            }
            log_info("Test image ID: %s version: %s", ifs_info->image_id, ifs_info->image_version);
        }
        else
        {
            /* When images are not supported, mark them as Not Applicable */
            strncpy(ifs_info->image_id, "NA", BUFLEN);
            strncpy(ifs_info->image_version, "NA", BUFLEN);
        }

        close(ifs_fd);
        return EXIT_SUCCESS;
}

static int scan_run(struct test *test, int cpu)
{
        /* Get info struct */
        ifs_test_t *ifs_info = test->data;
        char result[BUFLEN], my_cpu[BUFLEN];

        if (cpu_info[cpu].thread_id != 0)
                return EXIT_SKIP;

        snprintf(my_cpu, sizeof(my_cpu), "%d\n", cpu_info[cpu].cpu_number);

        char sys_path[PATH_LEN];
        int n = snprintf(sys_path, PATH_LEN, PATH_SYS_IFS_BASE "%s", ifs_info->sys_dir);
        assert(n < sizeof(sys_path));
        int ifsfd = open(sys_path, O_DIRECTORY | O_PATH | O_CLOEXEC);
        if (ifsfd < 0) {
                log_warning("Could not start test for \"%s\": %m", ifs_info->sys_dir);
                return EXIT_SKIP;
        }

        /* start the test; this blocks until the test has finished */
        if (!write_file(ifsfd, "run_test", my_cpu)) {
                log_warning("Could not start test for \"%s\": %m", ifs_info->sys_dir);
                close(ifsfd);
                return EXIT_SKIP;
        }

        /* read result */
        if (read_file(ifsfd, "status", result) < 0) {
                log_warning("Could not obtain result for \"%s\": %m", ifs_info->sys_dir);
                close(ifsfd);
                return EXIT_SKIP;
        }

        if (memcmp(result, "fail", strlen("fail")) == 0) {
                /* failed, get status code */
                unsigned long long code;
                ssize_t n = read_file(ifsfd, "details", result);
                close(ifsfd);

                if (n < 0) {
                        report_fail_msg("Test \"%s\" failed but could not retrieve error condition. Image ID: %s  version: %s", ifs_info->sys_dir, ifs_info->image_id, ifs_info->image_version);
                } else {
                        if (sscanf(result, "%llx", &code) == 1 && is_result_code_skip(code)) {
                                log_warning("Test \"%s\" did not run to completion, code: %s image ID: %s version: %s", ifs_info->sys_dir, result, ifs_info->image_id, ifs_info->image_version);
                                return EXIT_SKIP; // not a failure condition
                        }
                        report_fail_msg("Test \"%s\" failed with condition: %s image: %s version: %s", ifs_info->sys_dir, result, ifs_info->image_id, ifs_info->image_version);
                }
                //break;
        } else if (memcmp(result, "untested", strlen("untested")) == 0) {
                log_warning("Test \"%s\" remains unstested, code: %s image ID: %s version: %s", ifs_info->sys_dir, result, ifs_info->image_id, ifs_info->image_version);
                return EXIT_SKIP;
        } else if (memcmp(result, "pass", strlen("pass")) == 0) {
                log_debug("Test \"%s\" passed", ifs_info->sys_dir);
        }

        close(ifsfd);
        return EXIT_SUCCESS;
}

static int scan_saf_init(struct test *test)
{
    ifs_test_t *data = (ifs_test_t *) malloc(sizeof(ifs_test_t));

    data->sys_dir = "intel_ifs_0";
    data->image_support = true;

    test->data = data;
    return scan_common_init(test);
}

DECLARE_TEST(ifs, "Intel In-Field Scan (IFS) hardware selftest")
    .quality_level = TEST_QUALITY_PROD,
    .test_init = scan_saf_init,
    .test_run = scan_run,
    .desired_duration = -1,
    .fracture_loop_count = -1,
END_DECLARE_TEST

#endif // __x86_64__ && __linux__
