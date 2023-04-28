/*
 * Copyright 2022-2023 Intel Corporation.
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
#include <unistd.h>

#include "sandstone_ifs.h"


static bool load_test_file(int dfd, int batch_fd, struct test *test, ifs_test_t *ifs_info)
{
    char current_buf[BUFLEN] = {}, status_buf[BUFLEN] = {};
    int next_test, current_test, enforce_run;

    /* read both files status and current_batch */
    read_file(dfd, "status", status_buf);
    read_file_fd(batch_fd, current_buf);

    /* when previous run has a status of fail, skip test */
    enforce_run = get_testspecific_knob_value_uint(test, "enforce_run", -1);
    if (memcmp(status_buf, "fail", strlen("fail")) == 0 && enforce_run != 1 )
    {
        log_warning("Previous run failure found! This test will skip until enforced adding flag: "
                    "-O %s.enforce_run=1", test->id);
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

    /* when next blob does not exist, it will fail with ENOENT error */
    else if (errno == ENOENT)
    {
        /* when not even default image is available, test cannot proceed. */
        if (next_test == DEFAULT_TEST_ID)
        {
            log_info("There are no images available for this system or they are not located in the"
                    " right directory");
            return false;
        }

        /* when reached the latest image available, start from the begining */
        log_info("Test file %s, does not exist. Starting over from 0x%x", ifs_info->image_id, DEFAULT_TEST_ID);
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
        ifs_test_t *ifs_info = (ifs_test_t *) test->data;

        /* see if driver is loaded */
        char sys_path[PATH_MAX];
        int n = snprintf(sys_path, PATH_MAX, PATH_SYS_IFS_BASE "%s", ifs_info->sys_dir);
        assert(n < sizeof(sys_path));
        int ifs_fd = open_sysfs_ifs_base(sys_path);
        if (ifs_fd < 0) {
            int saved_errno = errno;
            log_info("could not find IFS control files in %s: either IFS is not supported on this system"
                     " or this kernel does not support IFS (%m)", ifs_info->sys_dir);
            return -saved_errno;
        }

        /* see if we can open run_test for writing */
        int run_fd = openat(ifs_fd, "run_test", O_WRONLY);
        int saved_errno = errno;
        if (run_fd < 0) {
                log_info("could not open %s/run_test for writing (not running as root?): %m", ifs_info->sys_dir);
                close(run_fd);
                return -saved_errno;
        }

        /* try open current_batch for writing */
        int batch_fd = openat(ifs_fd, "current_batch", O_RDWR);
        saved_errno = errno;
        if (saved_errno == ENOENT)
        {
            /* when curren_batch file does not exist, we assume there are not image support */
            ifs_info->image_support = false;

            /* when images are not supported, mark them as Not Applicable */
            strncpy(ifs_info->image_id, "NA", BUFLEN);
            strncpy(ifs_info->image_version, "NA", BUFLEN);
        }
        else {
            ifs_info->image_support = true;

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

        close(ifs_fd);
        return EXIT_SUCCESS;
}

static int scan_run_helper(struct test *test, int cpu)
{
        /* Get info struct */
        ifs_test_t *ifs_info = (ifs_test_t *) test->data;
        char result[BUFLEN] = {}, my_cpu[BUFLEN] = {};
        unsigned long long code;

        /* HACK: Shadows global variable that log_warning() uses
         * DON'T use report_fail_msg() */
        int thread_num = cpu;

        if (cpu_info[cpu].thread_id != 0)
                return EXIT_SKIP;

        snprintf(my_cpu, sizeof(my_cpu), "%d\n", cpu_info[cpu].cpu_number);

        char sys_path[PATH_MAX];
        int n = snprintf(sys_path, PATH_MAX, PATH_SYS_IFS_BASE "%s", ifs_info->sys_dir);
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
                ssize_t n = read_file(ifsfd, "details", result);
                close(ifsfd);

                if (n < 0) {
                        log_error("Test \"%s\" failed but could not retrieve error condition. Image ID: %s  version: %s", ifs_info->sys_dir, ifs_info->image_id, ifs_info->image_version);
                        return EXIT_FAILURE;
                } else {
                        // Compare common driver error codes
                        if (sscanf(result, "%llx", &code) == 1 && (compare_error_codes(code, IFS_SW_TIMEOUT) || compare_error_codes(code, IFS_SW_PARTIAL_COMPLETION))) {
                                log_warning("Test \"%s\" did not run to completion, code: %s image ID: %s version: %s", ifs_info->sys_dir, result, ifs_info->image_id, ifs_info->image_version);
                                return EXIT_SKIP; // not a failure condition
                        }
                        log_error("Test \"%s\" failed with condition: %s image: %s version: %s", ifs_info->sys_dir, result, ifs_info->image_id, ifs_info->image_version);
                        return EXIT_FAILURE;
                }
                //break;
        } else if (memcmp(result, "untested", strlen("untested")) == 0) {
                ssize_t n = read_file(ifsfd, "details", result);
                if (n < 0)
                {
                    strncpy(result, "unknown", BUFLEN);
                    log_warning("Test \"%s\" remains unstested, code: %s image ID: %s version: %s", ifs_info->sys_dir, result, ifs_info->image_id, ifs_info->image_version);
                }
                else
                {
                    if (sscanf(result, "%llx", &code) == 1 && compare_error_codes(code, IFS_SW_SCAN_CANNOT_START))
                    {
                        log_info("Test \"%s\" cannot be started at the moment, code: %s image ID: %s version: %s", ifs_info->sys_dir, result, ifs_info->image_id, ifs_info->image_version);
                        return IFS_SW_SCAN_CANNOT_START;
                    }
                }
                return EXIT_SKIP;
        } else if (memcmp(result, "pass", strlen("pass")) == 0) {
                log_debug("Test \"%s\" passed", ifs_info->sys_dir);
        }

        close(ifsfd);
        return EXIT_SUCCESS;
}

static int scan_run(struct test *test, int cpu)
{
    /* cpu 0 will orchestrate the execution for all cpus */
    if (cpu != 0)
        return EXIT_SKIP;

    int count = num_cpus();
    for (int i = 0; i < count; i++)
    {
        int scan_ret = scan_run_helper(test, i);
        if (scan_ret >= EXIT_FAILURE)
        {
            /* scan_run_helper has called log error, so the thread "i" has been
             * mark as failed. */
            break;
        }
        else if (scan_ret == IFS_EXIT_CANNOT_START)
        {
            return EXIT_SKIP;
        }
    }

    return EXIT_SUCCESS;
}

static int scan_saf_init(struct test *test)
{
    ifs_test_t *data = (ifs_test_t *) malloc(sizeof(ifs_test_t));
    data->sys_dir = "intel_ifs_0";
    test->data = data;

    return scan_common_init(test);
}

DECLARE_TEST(ifs, "Intel In-Field Scan (IFS) hardware selftest")
    .test_init = scan_saf_init,
    .test_run = scan_run,
    .desired_duration = -1,
    .fracture_loop_count = -1,
    .quality_level = TEST_QUALITY_PROD,
END_DECLARE_TEST

#endif // __x86_64__ && __linux__
