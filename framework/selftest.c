/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE 1
#include "selftest_p.h"
#include "sandstone.h"

#include <stdint.h>
#include <stdlib.h>

static int selftest_memcmp_c_run(struct test *test, int thread)
{
    uint32_t actual[] = { thread, 0x11111111, thread + 1 };
    uint32_t expected[] = { thread, 0x22222222, thread + 1 };

    memcmp_or_fail(actual, expected, 3, "C worker stack-local mismatch");
    log_error("C worker unexpectedly continued after memcmp_or_fail: %u, %u",
              actual[0], expected[0]);
    return EXIT_SUCCESS;
}

static int selftest_memcmp_c_cleanup(struct test *test)
{
    log_info("C worker memcmp cleanup after join");
    return EXIT_SUCCESS;
}

static char *selftest_datacompare_fail_double_cb(void *token, ptrdiff_t idx)
{
    // same content as formatter lambda in selftest_datacomparefail_run()
    char *buf;
    asprintf(&buf, "data of type '%s' at index %td\n"
                   "rare: false\n"
                   "modified_at: %td\n"
                   "count: %zu",
             "double", idx, idx, *(size_t *)token);
    return buf;
}

void selftest_datacomparefail_run_double(const double *actual, const double *expected, size_t size)
{
    // test memcmp_or_fail_cb, which is only provided as a C macro
    memcmp_or_fail_cb(actual, expected, size, selftest_datacompare_fail_double_cb, &size);
}

DECLARE_SELFTEST(selftest_memcmp_c, "Fails by calling memcmp_or_fail() from a C worker")
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_memcmp_c_run,
    .test_cleanup = selftest_memcmp_c_cleanup,
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_PROD,
END_DECLARE_TEST
