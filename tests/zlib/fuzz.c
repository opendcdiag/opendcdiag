/**
 * @file
 *
 * @copyright
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b zfuzz
 * @parblock
 * This test performs GZIP compression and decompression on buffers of
 * varying compressibility. Some buffers are random data, and therefore not
 * very compressible. Other buffers are still random, but are limited to
 * uppercase ASCII characters [A-Z], and therefore more compressible. For this
 * test, a random compression level is used.
 * @endparblock
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <sandstone.h>

#include <zlib.h>

#define BUF_MAX (size_t)(1024 * 1024 * 4)

static uint32_t zfuzz_gen_buffer(uint8_t *buf, size_t bufsz)
{
    uint32_t crc;

    if (bufsz % 2 == 0) {
        size_t i;
        for (i = 0; i < bufsz; i++)
                buf[i] = (uint8_t)((random32() % 26) + 'A');
    } else {
        memset_random(buf, bufsz);
    }

    crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, buf, bufsz);
    return crc;
}

static size_t zfuzz_zcomp(int level,
        const uint8_t *const inbuf, const size_t inbufsz,
        uint8_t *const outbuf, const size_t outbufsz, uint32_t *const crc)
{
        int ret;
        size_t compsz;
        z_stream strm;

        memset(&strm, 0, sizeof(strm));

        ret = deflateInit2(&strm, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
        if (ret != Z_OK)
                return 0;

        strm.next_in = (uint8_t *)inbuf;
        strm.avail_in = inbufsz;
        strm.next_out = outbuf;
        strm.avail_out = outbufsz;

        do {
                ret = deflate(&strm, Z_FINISH);
                if (ret == Z_STREAM_ERROR)
                        return 0;
        } while (ret != Z_STREAM_END);

        *crc = strm.adler;
        compsz = outbufsz - strm.avail_out;
        deflateEnd(&strm);
        return compsz;
}

static size_t zfuzz_decomp(const uint8_t *const compbuf, const size_t compsz,
        uint8_t *const backbuf, const size_t backsz)
{
        int ret;
        size_t decompsz;
        z_stream strm;

        memset(&strm, 0, sizeof(strm));
        strm.zalloc = Z_NULL;
        strm.zfree  = Z_NULL;
        strm.opaque = Z_NULL;

        strm.next_in = (uint8_t *)compbuf;
        strm.avail_in = compsz;
        strm.next_out = backbuf;
        strm.avail_out = backsz;

        ret = inflateInit2(&strm, 15 + 16);
        if (ret != Z_OK)
                return 0;

        do {
                ret = inflate(&strm, Z_FINISH);
                if (ret == Z_NEED_DICT || ret == Z_DATA_ERROR ||
                    ret == Z_MEM_ERROR || ret == Z_STREAM_ERROR) {
                      inflateEnd(&strm);
                    return 0;
                }
        } while (ret != Z_STREAM_END);

        decompsz = backsz - strm.avail_out;

        inflateEnd(&strm);
        return decompsz;
}


static int zfuzz_run(struct test *test, int cpu)
{
    int ret = EXIT_FAILURE;
    uint8_t *in = NULL, *out = NULL, *back = NULL;
    size_t outsz;

    in = malloc(BUF_MAX);
    back = malloc(BUF_MAX);
    outsz = BUF_MAX * 2;
    out = malloc(outsz);
    if (in == NULL || out == NULL || back == NULL)
            goto done;

    TEST_LOOP(test, 1) {
        size_t bufsz, compsz, backsz;
        uint32_t in_crc, out_crc;
        int level;

        bufsz = (random32() % (BUF_MAX-4096)) + 4096;
        in_crc = zfuzz_gen_buffer(in, bufsz);

        level = (random32() % 9) + 1;

        compsz = zfuzz_zcomp(level, in, bufsz, out, outsz, &out_crc);
        if (compsz == 0 || out_crc != in_crc)
                goto done;

        backsz = zfuzz_decomp(out, compsz, back, BUF_MAX);
        if (backsz == 0)
                goto done;

        if (backsz != bufsz)
                goto done;
        memcmp_or_fail(back, in, bufsz, "decompressed data");
    }

    ret = EXIT_SUCCESS;
done:
    free(in);
    free(out);
    free(back);
    return ret;
}

DECLARE_TEST(zfuzz, "Zlib fuzz test")
        .groups = DECLARE_TEST_GROUPS(&group_compression),
        .quality_level = TEST_QUALITY_PROD,
        .test_run = zfuzz_run,
END_DECLARE_TEST
