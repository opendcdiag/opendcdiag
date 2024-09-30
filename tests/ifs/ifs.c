/*
 * Copyright 2022-2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @test ifs
 *
 * Run 'In Field Scan' test provided by the Linux kernel on compatible hardware
 *
 * Requires `ifs.ko` to be loaded in the Linux kernel, as well as
 * firmware test blob data in `/lib/firmware/...`. Supported since
 * 6.2
 *
 * @test ifs_array_bist
 *
 * Run 'Array BIST' test provided by the Linux kernel on compatible hardware
 *
 * Array BIST is a new type of core test introduced under the Intel Infield
 * Scan (IFS) suite of tests.
 *
 * Array BIST performs tests on some portions of the core logic such as
 * caches and register files. These are different portions of the silicon
 * compared to the parts tested by Scan at Field (SAF).
 *
 * Requires `ifs.ko` to be loaded in the Linux kernel, supported since 6.4
 *
 * @test ifs_sbaf
 *
 * Run Structural Based Functional Test at Field 'SBAF' test provided by the
 * Linux kernel on compatible hardware.
 *
 * Requires `ifs.ko` to be loaded in the Linux kernel, supported since 6.12
 *
 */

#define _GNU_SOURCE 1
#include <sandstone.h>

#if defined(__x86_64__)
#if defined(__linux__)

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <stdio.h>
#include <unistd.h>

#include "sandstone_ifs.h"


static bool load_test_file(int dfd, int batch_fd, struct test *test, ifs_test_t *ifs_info,
                           const char *status_buf)
{
    char current_buf[BUFLEN] = {};
    int next_test, current_test;

    /* read current_batch */
    read_file_fd(batch_fd, current_buf);

    /* get interactive test file if provided by user */
    next_test = get_testspecific_knob_value_int(test, "test_file", -1);
    if (next_test == -1)
    {
        if (memcmp(current_buf, "none", strlen("none")) == 0)
            next_test = DEFAULT_TEST_ID;
        else
        {
            /* parse current test */
            char *end_ptr;
            current_test = (int) strtoul(current_buf, &end_ptr, 16);
            int saved_errno = errno;
            /* assure the buffer was completely parsed and we have no errors */
            if (strcmp(end_ptr, "\0") != 0 || saved_errno == ERANGE)
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
        assert(n < sizeof(sys_path)); (void) n;
        int ifs_fd = open_sysfs_ifs_base(sys_path);
        if (ifs_fd < 0) {
            int saved_errno = errno;
            log_skip(OsNotSupportedSkipCategory, "could not find IFS control files in %s: either IFS is not supported on this system"
                     " or this kernel does not support IFS (%m)", ifs_info->sys_dir);
            return -saved_errno;
        }

        /* when previous run has a status of fail, skip test */
        char status_buf[BUFLEN] = {};
        read_file(ifs_fd, "status", status_buf);
        int enforce_run = get_testspecific_knob_value_int(test, "enforce_run", -1);
        if (memcmp(status_buf, "fail", strlen("fail")) == 0 && enforce_run != 1 )
        {
            log_skip(TestResourceIssueSkipCategory, "Previous run failure found! This test will skip until enforced adding flag: "
                        "-O %s.enforce_run=1", test->id);
            return EXIT_SKIP;
        }

        /* see if we can open run_test for writing */
        int run_fd = openat(ifs_fd, "run_test", O_WRONLY);
        int saved_errno = errno;
        if (run_fd < 0) {
                log_skip(OSResourceIssueSkipCategory, "could not open %s/run_test for writing (not running as root?): %m", ifs_info->sys_dir);
                close(run_fd);
                return -saved_errno;
        }
        close(run_fd);

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
                    log_skip(OSResourceIssueSkipCategory, "could not open %s/current_batch for writing (not running as root?): %m", ifs_info->sys_dir);
                    close(batch_fd);
                    return -saved_errno;
            }

            /* load test file */
            if (!load_test_file(ifs_fd, batch_fd, test, ifs_info, status_buf)) {
                log_skip(TestResourceIssueSkipCategory, "cannot load test file");
                return EXIT_SKIP;
            }

            /* read image version if available and log it */
            if (read_file(ifs_fd, "image_version", ifs_info->image_version) <= 0) {
                    strncpy(ifs_info->image_version, "unknown", BUFLEN);
            }
            log_info("Test image ID: %s version: %s", ifs_info->image_id, ifs_info->image_version);
        }

        close(ifs_fd);
        return EXIT_SUCCESS;
}

static int scan_run(struct test *test, int cpu)
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
        assert(n < sizeof(sys_path)); (void) n;
        int ifsfd = open(sys_path, O_DIRECTORY | O_PATH | O_CLOEXEC);
        if (ifsfd < 0) {
                log_skip(OSResourceIssueSkipCategory, "Could not start test for \"%s\": %m", ifs_info->sys_dir);
                return EXIT_SKIP;
        }

        /* start the test; this blocks until the test has finished */
        if (!write_file(ifsfd, "run_test", my_cpu)) {
                log_skip(OSResourceIssueSkipCategory, "Could not start test for \"%s\": %m", ifs_info->sys_dir);
                close(ifsfd);
                return EXIT_SKIP;
        }

        /* read result */
        if (read_file(ifsfd, "status", result) < 0) {
                log_skip(OSResourceIssueSkipCategory, "Could not obtain result for \"%s\": %m", ifs_info->sys_dir);
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
                                log_skip(TestResourceIssueSkipCategory, "Test \"%s\" did not run to completion, code: %s image ID: %s version: %s", ifs_info->sys_dir, result, ifs_info->image_id, ifs_info->image_version);
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
                    log_skip(OSResourceIssueSkipCategory, "Test \"%s\" remains untested, code: %s image ID: %s version: %s", ifs_info->sys_dir, result, ifs_info->image_id, ifs_info->image_version);
                }
                else
                {
                    if (sscanf(result, "%llx", &code) == 1 && compare_error_codes(code, IFS_SW_SCAN_CANNOT_START))
                    {
                        log_skip(TestResourceIssueSkipCategory,
                                 "Test \"%s\" cannot be started at the moment, code: %s image ID: %s version: %s",
                                 ifs_info->sys_dir, result, ifs_info->image_id, ifs_info->image_version);
                    }
                    else
                    {
                        log_skip(TestResourceIssueSkipCategory,
                                 "Test \"%s\" did not complete scanning, code: %s image ID: %s version: %s",
                                 ifs_info->sys_dir, result, ifs_info->image_id, ifs_info->image_version);
                    }
                }
                return -EAGAIN;     // Try again
        } else if (memcmp(result, "pass", strlen("pass")) == 0) {
                log_debug("Test \"%s\" passed", ifs_info->sys_dir);
        }

        close(ifsfd);
        return EXIT_SUCCESS;
}

static int scan_preinit(struct test *test)
{
    /*
     * Intel documentation says that each core can take up to 200 ms to run.
     * Note num_cpus() counts logical processors, so this may overestimate the
     * number of cores.
     */
    test->minimum_duration = num_cpus() * 200;
    return EXIT_SUCCESS;
}

static int scan_saf_init(struct test *test)
{
    ifs_test_t *data = (ifs_test_t *) malloc(sizeof(ifs_test_t));
    data->sys_dir = "intel_ifs_0";
    test->data = data;

    return scan_common_init(test);
}

static int scan_array_init(struct test *test)
{
    ifs_test_t *data = (ifs_test_t *) malloc(sizeof(ifs_test_t));
    data->sys_dir = "intel_ifs_1";
    test->data = data;

    return scan_common_init(test);
}

static int scan_sbaf_init(struct test *test)
{
    ifs_test_t *data = (ifs_test_t *) malloc(sizeof(ifs_test_t));
    data->sys_dir = "intel_ifs_2";
    test->data = data;

    return scan_common_init(test);
}

#else // !__linux__

static int scan_preinit(struct test *test)
{
    return EXIT_SUCCESS;
}

static int scan_saf_init(struct test *test)
{
    log_skip(OsNotSupportedSkipCategory, "Not supported on this OS");
    return EXIT_SKIP;
}

static int scan_run(struct test *test, int cpu)
{
    __builtin_unreachable();
}

static int scan_array_init(struct test *test)
{
    log_skip(OsNotSupportedSkipCategory, "Not supported on this OS");
    return EXIT_SKIP;
}

static int scan_sbaf_init(struct test *test)
{
    log_skip(OsNotSupportedSkipCategory, "Not supported on this OS");
    return EXIT_SKIP;
}

#endif // __linux__

DECLARE_TEST(ifs, "Intel In-Field Scan (IFS) hardware selftest")
    .test_preinit = scan_preinit,
    .test_init = scan_saf_init,
    .test_run = scan_run,
    .desired_duration = -1,
    .fracture_loop_count = -1,
    .quality_level = TEST_QUALITY_PROD,
    .flags = test_schedule_sequential,
END_DECLARE_TEST

DECLARE_TEST(ifs_array_bist, "Array BIST: Intel In-Field Scan (IFS) hardware selftest for cache and registers")
    .test_preinit = scan_preinit,
    .test_init = scan_array_init,
    .test_run = scan_run,
    .desired_duration = -1,
    .fracture_loop_count = -1,
    .quality_level = TEST_QUALITY_PROD,
    .flags = test_schedule_sequential,
END_DECLARE_TEST

DECLARE_TEST(ifs_sbaf, "SBAF: Intel In-Field Scan (IFS) hardware functional selftest")
    .test_init = scan_sbaf_init,
    .test_run = scan_run,
    .desired_duration = -1,
    .fracture_loop_count = -1,
    .quality_level = TEST_QUALITY_BETA,
    .flags = test_schedule_sequential,
END_DECLARE_TEST

#endif // __x86_64__
