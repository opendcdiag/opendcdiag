/**
 * @file
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b zlib_aaa
 * This test performs GZIP compression and decompression on a buffer
 * comprised of a single repeating character. Because this data is highly
 * compressible, it emphasizes different codepaths compared to the other
 * Zlib tests. For this test, level 9 compression is used.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <immintrin.h>

#include <sandstone.h>

#include <zlib.h>

#define BUF_MAX (size_t)(1024 * 1024 * 4)

static void print_zlib_error(const char *const func, const int status)
{
    const char *err_str = zError(status);
    if (err_str == NULL)
        err_str = "unknown error message";

    log_error("%s failed: %s (%d)", func, err_str, status);
}

static int zcheck_aaa(uint8_t *buf, size_t bufsz, int level)
{
    int ret = -1, status;
    uint8_t *out, *back;
    size_t csize;
    z_stream strm;

    out = malloc(BUF_MAX);
    if (out == NULL) {
        log_error("Out of Memory : 1");
            goto done;
    }

    back = malloc(BUF_MAX);
    if (back == NULL) {
        log_error("Out of Memory : 2");
            goto done_0;
    }

    memset(&strm, 0, sizeof(strm));

    status = deflateInit2(&strm, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
    if (status != Z_OK) {
        print_zlib_error("deflateInit2", status);
            goto done_1;
    }

    strm.next_in = buf;
    strm.avail_in = BUF_MAX;
    strm.next_out = out;
    strm.avail_out = BUF_MAX;

    status = deflate(&strm, Z_FINISH);
    if (status != Z_STREAM_END) {
        print_zlib_error("deflate", status);
            deflateEnd(&strm);
            goto done_1;
    }

    deflateEnd(&strm);

    csize = BUF_MAX - strm.avail_out;

    memset(&strm, 0, sizeof(strm));

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    strm.avail_in = csize;
    strm.next_in = out;
    strm.next_out = back;
    strm.avail_out = BUF_MAX;

    status = inflateInit2(&strm, 15 + 16);
    if (status != Z_OK) {
        print_zlib_error("inflateInit2", status);
            goto done_1;
    }

    status = inflate(&strm, Z_FINISH);
    if (status != Z_STREAM_END) {
        print_zlib_error("inflate", status);
            inflateEnd(&strm);
            goto done_1;
    }

    inflateEnd(&strm);

    memcmp_or_fail(back, buf, BUF_MAX, "decompressed data");

    ret = 0;

done_1:
    free(back);
done_0:
    free(out);
done:
    return ret;
}


static int zlib_aaa_run(struct test *test, int cpu)
{
    do {
        uint8_t *buf;

        buf = malloc(BUF_MAX);
        if (buf == NULL) {
            log_error("Out of memory : 0");
            report_fail(test);
            return EXIT_FAILURE;
        }

        memset(buf, 'a', BUF_MAX);

        if (zcheck_aaa(buf, BUF_MAX, 9) != 0) {
            free(buf);
            report_fail(test);
            return EXIT_FAILURE;
        }

        free(buf);
    } while (test_time_condition(test));

    return EXIT_SUCCESS;
}

DECLARE_TEST(zlib_aaa, "Zlib compression test (aaa...) - Zlib compression and decompression with highly compressible data")
        .groups = DECLARE_TEST_GROUPS(&group_compression),
        .quality_level = TEST_QUALITY_PROD,
        .test_run = zlib_aaa_run,
END_DECLARE_TEST
