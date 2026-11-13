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
 * Init sets input bytes and a compression level for each pass. Workers get
 * those inputs and submit decompressed bytes for cross-checking. Init submits
 * the original bytes as a participant, not as a trusted reference. Each
 * worker's later results must match its first. Inputs remain fixed within a
 * fracture pass; subsequent passes generate new inputs.
 *
 * @note One successful worker plus init provides cross-check coverage.
 * @endparblock
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>

#include <sandstone.h>
#include "crosscheck.h"

#include <zlib.h>

#define BUF_MAX (size_t)(1024 * 1024 * 4)

CROSSCHECK_INPUT(zlib_bytes, uint8_t);
CROSSCHECK_INPUT(zlib_level, int32_t);
CROSSCHECK_OUTPUT(zlib_decompressed, uint8_t);

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
    if (*buf == NULL)
        print_zlib_error("malloc", Z_MEM_ERROR);
    memset_random(*buf, *bufsz);
}

static void zcheck(size_t bufsz, const uint8_t *buf, int level)
{
    int status;
    uint8_t *out, *back;
    size_t csize, outsz;
    z_stream strm;

    memset(&strm, 0, sizeof(strm));

    status = deflateInit2(&strm, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
    if (status != Z_OK)
        print_zlib_error("deflateInit2", status);

    outsz = deflateBound(&strm, bufsz);
    out = malloc(outsz);
    back = malloc(bufsz);
    if (out == NULL || back == NULL)
        print_zlib_error("malloc", Z_MEM_ERROR);

    strm.next_in = (uint8_t *)buf;
    strm.avail_in = bufsz;
    strm.next_out = out;
    strm.avail_out = outsz;

    do {
        status = deflate(&strm, Z_FINISH);
        if (status != Z_OK && status != Z_STREAM_END) {
            print_zlib_error("deflate", status);
        }
    } while (status != Z_STREAM_END);

    deflateEnd(&strm);

    csize = outsz - strm.avail_out;

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
        if (status != Z_OK && status != Z_STREAM_END) {
            print_zlib_error("inflate", status);
        }
    } while (status != Z_STREAM_END);

    size_t backsz = strm.total_out;
    inflateEnd(&strm);

    if (backsz != bufsz)
        report_fail_msg("Decompressed length mismatch: got %zu, expected %zu", backsz, bufsz);
    submit_output(zlib_decompressed, back, backsz, "Decompressed data");

    free(back);
    free(out);
}

static int zlib_init_common(struct test *test, int level, bool compressible)
{
    // negative value from caller implies they want to add an option
    if (level < 0)
        level = get_testspecific_knob_value_int(test, "level", -level);

    uint64_t maxbuffersize = get_testspecific_knob_value_uint(test, "maxbuffersize", BUF_MAX);
    // Keep source sizes and deflateBound() within zlib's uInt buffer extents.
    if (maxbuffersize == 0 || maxbuffersize > UINT_MAX / 2 - 4096)
        report_fail_msg("Invalid maxbuffersize: %" PRIu64, maxbuffersize);

    uint8_t *buf;
    size_t bufsz;
    if (compressible) {
        bufsz = maxbuffersize;
        buf = malloc(bufsz);
        if (buf == NULL)
            print_zlib_error("malloc", Z_MEM_ERROR);
        memset(buf, 'a', bufsz);
    } else {
        zlib_gen_buffer(&bufsz, &buf, maxbuffersize);
    }
    set_input(zlib_bytes, buf, bufsz, "Uncompressed input");
    free(buf);
    int32_t captured_level = level;
    set_input(zlib_level, &captured_level, 1, "Compression level");
    __auto_type input = get_input(zlib_bytes);
    submit_output(zlib_decompressed, input.data, input.count, "Decompressed data");
    return EXIT_SUCCESS;
}

static int zlib_run_common(struct test *test, int cpu)
{
    __auto_type input = get_input(zlib_bytes);
    int level = get_input(zlib_level).data[0];

    TEST_LOOP(test, 1) {
        zcheck(input.count, input.data, level);
    }

    return EXIT_SUCCESS;
}

static int zlib1_init(struct test *test)
{
    return zlib_init_common(test, 1, false);
}

static int zlib_init(struct test *test)
{
    return zlib_init_common(test, -6, false);  // negative to allow override
}

static int zlib9_init(struct test *test)
{
    return zlib_init_common(test, 6, false);
}

static int zlib_aaa_init(struct test *test)
{
    return zlib_init_common(test, -9, true);  // negative to allow override
}

DECLARE_TEST(zlib_aaa, "Zlib compression test (aaa...) - Zlib compression and decompression with highly compressible data")
        .groups = DECLARE_TEST_GROUPS(&group_compression),
        .quality_level = TEST_QUALITY_PROD,
        .test_init = zlib_aaa_init,
        .test_run = zlib_run_common,
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
