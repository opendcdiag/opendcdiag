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
 * Init sets one buffer of each kind, random levels, and expected CRCs as inputs.
 * Workers get those inputs and submit decompressed bytes for cross-checking.
 * Init submits the original bytes as a participant, not as a trusted reference.
 * Each worker's later results must match its first. Workers repeat both cases
 * within each pass; subsequent fracture passes generate new cases.
 *
 * @note One successful worker plus init provides cross-check coverage.
 * @endparblock
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <sandstone.h>
#include "crosscheck.h"

#include <zlib.h>

#define BUF_MAX (size_t)(1024 * 1024 * 4)

CROSSCHECK_INPUT(zfuzz_bytes, uint8_t);
CROSSCHECK_INPUT(zfuzz_ascii, uint8_t);
CROSSCHECK_INPUT(zfuzz_levels, int32_t);
CROSSCHECK_INPUT(zfuzz_crcs, uint32_t);
CROSSCHECK_OUTPUT(zfuzz_bytes_decompressed, uint8_t);
CROSSCHECK_OUTPUT(zfuzz_ascii_decompressed, uint8_t);

static void zfuzz_gen_buffer(uint8_t *buf, size_t bufsz)
{
    if (bufsz % 2 == 0) {
        size_t i;
        for (i = 0; i < bufsz; i++)
                buf[i] = (uint8_t)((random32() % 26) + 'A');
    } else {
        memset_random(buf, bufsz);
    }
}

static int zfuzz_init(struct test *test)
{
    uint8_t *buf = malloc(BUF_MAX);
    if (buf == NULL)
        return EXIT_FAILURE;

    size_t bufsz = ((random32() % (BUF_MAX - 4096)) + 4096) | 1;
    zfuzz_gen_buffer(buf, bufsz);
    set_input(zfuzz_bytes, buf, bufsz, "Arbitrary bytes");
    bufsz = ((random32() % (BUF_MAX - 4096)) + 4096) & ~(size_t)1;
    zfuzz_gen_buffer(buf, bufsz);
    set_input(zfuzz_ascii, buf, bufsz, "Uppercase ASCII");
    free(buf);

    int32_t levels[] = { (random32() % 9) + 1, (random32() % 9) + 1 };
    set_input(zfuzz_levels, levels, 2, "Compression levels");
    __auto_type bytes = get_input(zfuzz_bytes);
    __auto_type ascii = get_input(zfuzz_ascii);
    uint32_t crcs[] = {
        crc32(crc32(0L, Z_NULL, 0), bytes.data, bytes.count),
        crc32(crc32(0L, Z_NULL, 0), ascii.data, ascii.count)
    };
    set_input(zfuzz_crcs, crcs, 2, "Expected compression CRCs");
    submit_output(zfuzz_bytes_decompressed, bytes.data, bytes.count, "Decompressed arbitrary bytes");
    submit_output(zfuzz_ascii_decompressed, ascii.data, ascii.count, "Decompressed uppercase ASCII");
    return EXIT_SUCCESS;
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
                if (ret != Z_OK && ret != Z_STREAM_END) {
                        deflateEnd(&strm);
                        return 0;
                }
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
                if (ret != Z_OK && ret != Z_STREAM_END) {
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
    uint8_t *out = NULL, *back = NULL;
    size_t outsz;
    __auto_type bytes = get_input(zfuzz_bytes);
    __auto_type ascii = get_input(zfuzz_ascii);
    const uint8_t *inputs[] = { bytes.data, ascii.data };
    size_t sizes[] = { bytes.count, ascii.count };
    const int32_t *levels = get_input(zfuzz_levels).data;
    const uint32_t *crcs = get_input(zfuzz_crcs).data;

    back = malloc(BUF_MAX);
    outsz = BUF_MAX * 2;
    out = malloc(outsz);
    if (out == NULL || back == NULL)
            goto done;

    do {
        for (size_t i = 0; i < 2; ++i) {
            size_t compsz, backsz;
            uint32_t out_crc;
            compsz = zfuzz_zcomp(levels[i], inputs[i], sizes[i], out, outsz, &out_crc);
            if (compsz == 0 || out_crc != crcs[i])
                goto done;

            backsz = zfuzz_decomp(out, compsz, back, BUF_MAX);
            if (backsz == 0)
                goto done;

            if (backsz != sizes[i])
                goto done;
            if (i == 0)
                submit_output(zfuzz_bytes_decompressed, back, backsz, "Decompressed arbitrary bytes");
            else
                submit_output(zfuzz_ascii_decompressed, back, backsz, "Decompressed uppercase ASCII");
        }
    } while (test_time_condition(test));

    ret = EXIT_SUCCESS;
done:
    free(out);
    free(back);
    return ret;
}

DECLARE_TEST(zfuzz, "Zlib fuzz test")
        .groups = DECLARE_TEST_GROUPS(&group_compression),
        .quality_level = TEST_QUALITY_PROD,
        .test_init = zfuzz_init,
        .test_run = zfuzz_run,
END_DECLARE_TEST
