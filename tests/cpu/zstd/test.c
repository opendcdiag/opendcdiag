/**
 * @file
 *
 * @copyright
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b zstd
 * This test performs ZStandard compression and decompression on random data.
 * Because random data is not very compressible, it emphasizes different
 * codepaths compared to the other ZStandard tests.
 *
 * @note This test requires at least 2 threads to run.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <sandstone.h>

#include <zstd.h>
#include <zstd_errors.h>

#ifndef ZSTD_CLEVEL_DEFAULT
#define ZSTD_CLEVEL_DEFAULT 3
#endif

#define BUF_MAX (size_t)(1024 * 1024 * 32)
#define BUF_MAX_AAA (size_t)(1024 * 1024 * 4)

struct zstd_parameters
{
    int compression;
    unsigned maxbuffersize;
};

static void zstd_gen_buffer(size_t *bufsz, uint8_t ** buf, unsigned max)
{
    *bufsz = (random32() % max) + 4096;

    *buf = malloc(*bufsz + 16);
    memset_random(*buf, *bufsz);
}

static void __attribute__((cold, noreturn)) zstd_report_fail(const char *name, size_t errc)
{
    ZSTD_ErrorCode code = ZSTD_getErrorCode(errc);
    if (code == ZSTD_error_memory_allocation)
        // memory errors shouldn't happen in Sandstone
        log_platform_message(SANDSTONE_LOG_ERROR "%s reported memory allocation error", name);

    report_fail_msg("%s failed: %d (%s)", name, code, ZSTD_getErrorString(code));
}

static void zstd_check(size_t bufsz, uint8_t * buf, int level)
{
    uint8_t *comp_buf, *back_buf;
    size_t compsz, bnd, backsz;

    bnd = ZSTD_compressBound(bufsz);

    comp_buf = malloc(bnd);
    back_buf = malloc(bufsz);
    compsz = ZSTD_compress(comp_buf, bnd, buf, bufsz, level);
    if (ZSTD_isError(compsz)) {
        zstd_report_fail("ZSTD_compress", compsz);
    }

    backsz = ZSTD_decompress(back_buf, bufsz, comp_buf, compsz);
    if (ZSTD_isError(backsz)) {
        zstd_report_fail("ZSTD_decompress", backsz);
    }

    memcmp_or_fail(&backsz, &bufsz, 1, "decompressed data length");
    memcmp_or_fail(back_buf, buf, bufsz, "decompressed data");

    free(back_buf);
    free(comp_buf);
}

static int zstd_init_common(struct test *test, int level)
{
    static_assert(BUF_MAX == (unsigned)BUF_MAX, "Size doesn't fit!");
    unsigned max = BUF_MAX;

    /*
     * for legacy reasons, default level runs at max size. All other levels we reduce
     * for memory consumption and runtime reasons
     */
    if (level != ZSTD_CLEVEL_DEFAULT)
        max = max / 4;

    /* for very high levels, reduce even more to keep runtime in control */
    if (level > 12)
        max = max / 4;

    if (level == ZSTD_CLEVEL_DEFAULT)
        level = get_testspecific_knob_value_int(test, "level", level);
    max = get_testspecific_knob_value_uint(test, "maxbuffersize", max);

    struct zstd_parameters p = { .compression = level, .maxbuffersize = max };
    static_assert(sizeof(p) == sizeof(test->data),
        "Internal assumption broken: change me to allocate memory instead");
    memcpy(&test->data, &p, sizeof(p));
    return EXIT_SUCCESS;
}

static int zstd_run_common(struct test *test, int cpu)
{
    struct zstd_parameters p;
    memcpy(&p, &test->data, sizeof(p));
    TEST_LOOP(test, 1) {
        uint8_t *buf;
        size_t bufsz;

        zstd_gen_buffer(&bufsz, &buf, p.maxbuffersize);
        zstd_check(bufsz, buf, p.compression);

        free(buf);
    }
    return EXIT_SUCCESS;
}

static int zstd_init(struct test *test)
{
    return zstd_init_common(test, ZSTD_CLEVEL_DEFAULT);
}

static int zstd1_init(struct test *test)
{
    return zstd_init_common(test, 1);
}

static int zstd19_init(struct test *test)
{
    return zstd_init_common(test, 19);
}

static int zstd_aaa_init(struct test *test)
{
    static_assert(BUF_MAX_AAA == (unsigned)BUF_MAX_AAA, "Size doesn't fit!");
    struct zstd_parameters p = {
        .compression = get_testspecific_knob_value_int(test, "level", 19),
        .maxbuffersize = get_testspecific_knob_value_uint(test, "maxbuffersize", BUF_MAX_AAA)
    };
    memcpy(&test->data, &p, sizeof(p));
    return EXIT_SUCCESS;
}

static int zstd_aaa_run(struct test *test, int cpu)
{
    struct zstd_parameters p;
    memcpy(&p, &test->data, sizeof(p));

    TEST_LOOP(test, 1) {
        uint8_t *buf;

        buf = malloc(p.maxbuffersize);
        memset(buf, 'a', p.maxbuffersize);
        zstd_check(p.maxbuffersize, buf, p.compression);

        free(buf);
    }

    return EXIT_SUCCESS;
}

DECLARE_TEST(zstd_aaa, "ZStandard compression test (aaa...) - ZStandard compression and decompression with highly compressible data")
        .groups = DECLARE_TEST_GROUPS(&group_compression),
        .quality_level = TEST_QUALITY_PROD,
        .test_init = zstd_aaa_init,
        .test_run = zstd_aaa_run,
END_DECLARE_TEST

DECLARE_TEST(zstd1, "ZStandard compression test - ZStandard compression and decompression with random data (level 1)")
        .groups = DECLARE_TEST_GROUPS(&group_compression),
        .quality_level = TEST_QUALITY_PROD,
        .test_init = zstd1_init,
        .test_run = zstd_run_common,
        .fracture_loop_count = 3,
END_DECLARE_TEST

DECLARE_TEST(zstd, "ZStandard compression test - ZStandard compression and decompression with random data (default level)")
        .groups = DECLARE_TEST_GROUPS(&group_compression),
        .quality_level = TEST_QUALITY_PROD,
        .test_init = zstd_init,
        .test_run = zstd_run_common,
        .fracture_loop_count = 3,
        .flags = test_flag_ignore_memory_use
END_DECLARE_TEST

DECLARE_TEST(zstd19, "ZStandard compression test - ZStandard compression and decompression with random data (level 19)")
        .groups = DECLARE_TEST_GROUPS(&group_compression),
        .quality_level = TEST_QUALITY_PROD,
        .test_init = zstd19_init,
        .test_run = zstd_run_common,
        .fracture_loop_count = 3,
        .desired_duration = 3000,
END_DECLARE_TEST

