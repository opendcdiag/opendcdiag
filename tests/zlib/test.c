/**
 * @file
 *
 * @copyright
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b zlib
 * @parblock
 * This test performs GZIP compression and decompression on random data.
 * Because random data is not very compressible, it emphasizes different
 * codepaths compared to the other Zlib tests. For this test, level 6
 * compression is used.
 *
 * @note This test requires at least 2 threads to run.
 * @endparblock
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <sandstone.h>

#include <zlib.h>

#define BUF_MAX (size_t)(1024 * 1024 * 4)

struct zlib_parameters
{
    int level;
    unsigned maxbuffersize;
};

extern void x86_check_features(void);

static void __attribute__((cold, noreturn)) print_zlib_error(const char *func, int status)
{
    const char *err_str = zError(status);
    if (status == Z_MEM_ERROR)
        log_platform_message(SANDSTONE_LOG_ERROR "%s reported memory allocation problems", func);
    if (err_str == NULL)
        err_str = "unknown error message";

    report_fail_msg("%s failed: %s (%d)", func, err_str, status);
}

static void zlib_gen_buffer(size_t *bufsz, uint8_t ** buf, unsigned maxbuffersize)
{
    *bufsz = (random32() % maxbuffersize) + 4096;

    *buf = malloc(*bufsz + 16);
    memset_random(*buf, *bufsz);
}

static void zcheck(size_t bufsz, uint8_t * buf, int level)
{
    int status;
    uint8_t *out, *back;
    size_t csize;
    z_stream strm;

    out = malloc(bufsz * 2);
    back = malloc(bufsz);
    memset(&strm, 0, sizeof(strm));

    status = deflateInit2(&strm, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
    if (status != Z_OK)
        print_zlib_error("deflateInit2", status);

    strm.next_in = buf;
    strm.avail_in = bufsz;
    strm.next_out = out;
    strm.avail_out = bufsz * 2;

    do {
        status = deflate(&strm, Z_FINISH);
        if (status == Z_STREAM_ERROR || status == Z_BUF_ERROR) {
            print_zlib_error("deflate", status);
        }
    } while (status != Z_STREAM_END);

    deflateEnd(&strm);

    csize = (bufsz * 2) - strm.avail_out;

    memset(&strm, 0, sizeof(strm));

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    strm.avail_in = csize;
    strm.next_in = out;
    strm.next_out = back;
    strm.avail_out = bufsz;

    status = inflateInit2(&strm, 15 + 16);
    if (status != Z_OK) {
        print_zlib_error("inflateInit2", status);
    }

    do {
        status = inflate(&strm, Z_FINISH);
        if (status == Z_NEED_DICT || status == Z_DATA_ERROR ||
            status == Z_MEM_ERROR || status == Z_STREAM_ERROR) {
            print_zlib_error("inflate", status);
        }
    } while (status != Z_STREAM_END);

    inflateEnd(&strm);

    memcmp_or_fail(back, buf, bufsz, "decompressed data");

    free(back);
    free(out);
}

static int zlib_init_common(struct test *test, int level)
{
#ifdef __x86_64__
    x86_check_features();
#endif

    // negative value from caller implies they want to add an option
    if (level < 0)
        level = get_testspecific_knob_value_int(test, "level", -level);

    struct zlib_parameters p = {
        .level = level,
        .maxbuffersize = get_testspecific_knob_value_uint(test, "maxbuffersize", BUF_MAX)
    };
    static_assert(sizeof(p) == sizeof(test->data),
        "Internal assumption broken: change me to allocate memory instead");
    memcpy(&test->data, &p, sizeof(p));
    return EXIT_SUCCESS;
}

static int zlib_run_common(struct test *test, int cpu)
{
    struct zlib_parameters p;
    memcpy(&p, &test->data, sizeof(p));

    TEST_LOOP(test, 1) {
        uint8_t *buf;
        size_t bufsz;

        zlib_gen_buffer(&bufsz, &buf, p.maxbuffersize);
        zcheck(bufsz, buf, p.level);
        free(buf);
    }

    return EXIT_SUCCESS;
}

static int zlib1_init(struct test *test)
{
    return zlib_init_common(test, 1);
}

static int zlib_init(struct test *test)
{
    return zlib_init_common(test, -6);  // negative to allow override
}

static int zlib9_init(struct test *test)
{
    return zlib_init_common(test, 6);
}

static int zlib_aaa_init(struct test *test)
{
    return zlib_init_common(test, -9);  // negative to allow override
}

static int zlib_aaa_run(struct test *test, int cpu)
{
    struct zlib_parameters p;
    memcpy(&p, &test->data, sizeof(p));

    TEST_LOOP(test, 1) {
        uint8_t *buf;

        buf = malloc(p.maxbuffersize);
        memset(buf, 'a', p.maxbuffersize);

        zcheck(BUF_MAX, buf, p.level);

        free(buf);
    }

    return EXIT_SUCCESS;
}

DECLARE_TEST(zlib_aaa, "Zlib compression test (aaa...) - Zlib compression and decompression with highly compressible data")
        .groups = DECLARE_TEST_GROUPS(&group_compression),
        .quality_level = TEST_QUALITY_PROD,
        .test_init = zlib_aaa_init,
        .test_run = zlib_aaa_run,
END_DECLARE_TEST

DECLARE_TEST(zlib1, "Zlib compression test -  Zlib compression and decompression with random data (level 1)")
        .groups = DECLARE_TEST_GROUPS(&group_compression),
        .quality_level = TEST_QUALITY_PROD,
        .test_init = zlib1_init,
        .test_run = zlib_run_common,
        .desired_duration = 1000,
        .fracture_loop_count = 3,
END_DECLARE_TEST

DECLARE_TEST(zlib, "Zlib compression test -  Zlib compression and decompression with random data (level 6)")
        .groups = DECLARE_TEST_GROUPS(&group_compression),
        .quality_level = TEST_QUALITY_PROD,
        .test_init = zlib_init,
        .test_run = zlib_run_common,
        .desired_duration = 2000,
        .fracture_loop_count = 3,
END_DECLARE_TEST

DECLARE_TEST(zlib9, "Zlib compression test -  Zlib compression and decompression with random data (level 9)")
        .quality_level = TEST_QUALITY_PROD,
        .test_init = zlib9_init,
        .test_run = zlib_run_common,
        .desired_duration = 2000,
        .fracture_loop_count = 3,
END_DECLARE_TEST
