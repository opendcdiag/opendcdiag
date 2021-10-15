/**
 * @file
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b zstd_aaa
 * This test performs ZStandard compression and decompression on a buffer
 * comprised of a single repeating character. Because this data is highly
 * compressible, it emphasizes different codepaths compared to the other
 * ZStandard tests.
 *
 * @note This test requires at least 2 threads to run.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <sandstone.h>

#include <zstd.h>

#define BUF_MAX (size_t)(1024 * 1024 * 4)

static int zstd_aaa_init(struct test *test)
{
        return EXIT_SUCCESS;
}

static int zstd_aaa_check(uint8_t *buf, size_t bufsz)
{
    int ret = -1;
    uint8_t *comp_buf, *back_buf;
    size_t compsz, bnd, backsz;

    bnd = ZSTD_compressBound(BUF_MAX);

    comp_buf = malloc(bnd);
    back_buf = malloc(bufsz);
    compsz = ZSTD_compress(comp_buf, bnd, buf, bufsz, 19);
    if (ZSTD_isError(compsz)) {
        goto done_1;
    }

    backsz = ZSTD_decompress(back_buf, bufsz, comp_buf, compsz);
    if (ZSTD_isError(backsz)) {
        goto done_1;
    }

    memcmp_or_fail(&backsz, &bufsz, 1, "decompressed data length");
    memcmp_or_fail(back_buf, buf, bufsz, "decompressed data");

    ret = 0;
  done_1:
    free(back_buf);
    free(comp_buf);
    return ret;
}

static int zstd_aaa_run(struct test *test, int cpu)
{
    /* Put your test code here.
     * This function is called on each thread and `cpu' contains
     * the CPU number */

    do {
        uint8_t *buf;

        buf = malloc(BUF_MAX);
        if (buf == NULL) {
                report_fail(test);
                return EXIT_FAILURE;
        }

        memset(buf, 'a', BUF_MAX);

        if (zstd_aaa_check(buf, BUF_MAX) != 0) {
            report_fail(test);
            free(buf);
            return EXIT_FAILURE;
        }

        free(buf);
    } while (test_time_condition(test));

    /* you may want to do some final data check here */

    return EXIT_SUCCESS;
}

static int zstd_aaa_finish(struct test *test)
{
    return EXIT_SUCCESS;
}

DECLARE_TEST(zstd_aaa, "ZStandard compression test (aaa...) - ZStandard compression and decompression with highly compressible data")
        .groups = DECLARE_TEST_GROUPS(&group_compression),
        .quality_level = TEST_QUALITY_PROD,
        .test_init = zstd_aaa_init,
        .test_run = zstd_aaa_run,
        .test_cleanup = zstd_aaa_finish,
END_DECLARE_TEST
