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
 * Init sets input bytes and a compression level for each pass. Workers get
 * those inputs and submit decompressed bytes for cross-checking. Init submits
 * the original bytes as a participant, not as a trusted reference. Each
 * worker's later results must match its first. Inputs remain fixed within a
 * fracture pass; subsequent passes generate new inputs.
 *
 * @note One successful worker plus init provides cross-check coverage.
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

#include <zstd.h>
#include <zstd_errors.h>

#ifndef ZSTD_CLEVEL_DEFAULT
#define ZSTD_CLEVEL_DEFAULT 3
#endif

#define BUF_MAX (size_t)(1024 * 1024 * 32)
#define BUF_MAX_AAA (size_t)(1024 * 1024 * 4)

CROSSCHECK_INPUT(zstd_bytes, uint8_t);
CROSSCHECK_INPUT(zstd_level, int32_t);
CROSSCHECK_OUTPUT(zstd_decompressed, uint8_t);

static void zstd_gen_buffer(size_t *bufsz, uint8_t ** buf, unsigned max)
{
    *bufsz = (random32() % max) + 4096;

    *buf = malloc(*bufsz + 16);
    if (*buf == NULL)
        report_fail_msg("Could not allocate zstd input buffer");
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

static void zstd_check(size_t bufsz, const uint8_t *buf, int level)
{
    uint8_t *comp_buf, *back_buf;
    size_t compsz, bnd, backsz;

    bnd = ZSTD_compressBound(bufsz);
    if (ZSTD_isError(bnd))
        zstd_report_fail("ZSTD_compressBound", bnd);

    comp_buf = malloc(bnd);
    back_buf = malloc(bufsz);
    if (comp_buf == NULL || back_buf == NULL)
        report_fail_msg("Could not allocate zstd round-trip buffers");
    compsz = ZSTD_compress(comp_buf, bnd, buf, bufsz, level);
    if (ZSTD_isError(compsz)) {
        zstd_report_fail("ZSTD_compress", compsz);
    }

    backsz = ZSTD_decompress(back_buf, bufsz, comp_buf, compsz);
    if (ZSTD_isError(backsz)) {
        zstd_report_fail("ZSTD_decompress", backsz);
    }

    if (backsz != bufsz)
        report_fail_msg("Decompressed length mismatch: got %zu, expected %zu", backsz, bufsz);
    submit_output(zstd_decompressed, back_buf, backsz, "Decompressed data");

    free(back_buf);
    free(comp_buf);
}

static int zstd_init_workload(int level, uint64_t max, bool compressible)
{
    // Validate before narrowing to the generator's unsigned modulus.
    if (max == 0 || max > UINT_MAX - (compressible ? 0u : 4096u))
        report_fail_msg("Invalid maxbuffersize: %" PRIu64, max);

    uint8_t *buf;
    size_t bufsz;
    if (compressible) {
        bufsz = max;
        buf = malloc(bufsz);
        if (buf == NULL)
            report_fail_msg("Could not allocate zstd input buffer");
        memset(buf, 'a', bufsz);
    } else {
        zstd_gen_buffer(&bufsz, &buf, max);
    }
    set_input(zstd_bytes, buf, bufsz, "Uncompressed input");
    free(buf);
    int32_t captured_level = level;
    set_input(zstd_level, &captured_level, 1, "Compression level");
    __auto_type input = get_input(zstd_bytes);
    submit_output(zstd_decompressed, input.data, input.count, "Decompressed data");
    return EXIT_SUCCESS;
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
    return zstd_init_workload(level,
            get_testspecific_knob_value_uint(test, "maxbuffersize", max), false);
}

static int zstd_run_common(struct test *test, int cpu)
{
    __auto_type input = get_input(zstd_bytes);
    int level = get_input(zstd_level).data[0];
    TEST_LOOP(test, 1) {
        zstd_check(input.count, input.data, level);
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
    int level = get_testspecific_knob_value_int(test, "level", 19);
    return zstd_init_workload(level,
            get_testspecific_knob_value_uint(test, "maxbuffersize", BUF_MAX_AAA), true);
}

DECLARE_TEST(zstd_aaa, "ZStandard compression test (aaa...) - ZStandard compression and decompression with highly compressible data")
        .groups = DECLARE_TEST_GROUPS(&group_compression),
        .quality_level = TEST_QUALITY_PROD,
        .test_init = zstd_aaa_init,
        .test_run = zstd_run_common,
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
