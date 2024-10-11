/**
 * @file
 *
 * @copyright
 * Copyright 2024 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b fuzzer_memset_random
 * This test serves as an entry point for fuzzing `memset_random` with AFL++.
 * 
 * @test @b fuzzer_memcmp_or_fail
 * This test serves as an entry point for fuzzing `memcmp_or_fail` with AFL++.
 */

#include <afl-record-compat.h>
#include <sandstone.h>

#define AFL_LOOP_COUNT (1000)

static int fuzzer_init(struct test *test) {
    __AFL_INIT();
    test->data = __AFL_FUZZ_TESTCASE_BUF;
    return EXIT_SUCCESS;
}

static int fuzzer_memset_random(struct test *test, int cpu) {
    ssize_t len = __AFL_FUZZ_TESTCASE_LEN;

    while(__AFL_LOOP(AFL_LOOP_COUNT)) {
        unsigned char* test_buf = (unsigned char *)malloc(len);
        memset_random(test_buf, len);
        free(test_buf);
    }
    return EXIT_SUCCESS;
}

static int fuzzer_memcmp_or_fail(struct test *test, int cpu) {
    unsigned char *buf = (unsigned char*)test->data;
    ssize_t len = __AFL_FUZZ_TESTCASE_LEN;

    while(__AFL_LOOP(AFL_LOOP_COUNT)) {
        memcmp_or_fail(buf, buf, len);
    }
    return EXIT_SUCCESS;
}

static int fuzzer_cleanup(struct test *test) {
    test->data = NULL;
    return EXIT_SUCCESS;
}

DECLARE_TEST(fuzz_memset_random, "Fuzz memset_random() with AFL++")
    .test_init = fuzzer_init,
    .test_run = fuzzer_memset_random,
    .test_cleanup = fuzzer_cleanup,
    .quality_level = TEST_QUALITY_BETA,
    .flags = test_schedule_sequential,
    .groups = DECLARE_TEST_GROUPS(&group_fuzzing),
END_DECLARE_TEST

DECLARE_TEST(fuzz_memcmp_or_fail, "Fuzz memcmp_or_fail with AFL++")
    .test_init = fuzzer_init,
    .test_run = fuzzer_memcmp_or_fail,
    .test_cleanup = fuzzer_cleanup,
    .quality_level = TEST_QUALITY_BETA,
    .flags = test_schedule_sequential,
    .groups = DECLARE_TEST_GROUPS(&group_fuzzing),
END_DECLARE_TEST
