/**
 * @copyright
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b vector_add
 * @parblock
 * vector_add repeatedly adds two arrays of random numbers together using
 * AVX-512 instructions, checking output invariance and agreement among workers.
 * @endparblock
 */

#include "sandstone.h"
#include "crosscheck.h"

#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define VECTOR_ADD_ELEMENTS (1u << 10)
#define VECTOR_ADD_BUF_SIZE (VECTOR_ADD_ELEMENTS * sizeof(uint32_t))

CROSSCHECK_INPUT(vector_add_a, uint32_t);
CROSSCHECK_INPUT(vector_add_b, uint32_t);
CROSSCHECK_OUTPUT(vector_add_sum, uint32_t);

static void vector_add_do_add(const uint32_t *a, const uint32_t *b, uint32_t *res)
{
    for (size_t i = 0; i < VECTOR_ADD_ELEMENTS / 16; i++) {
        __m512i r1 = _mm512_loadu_epi32(&a[i*16]);
        __m512i r2 = _mm512_loadu_epi32(&b[i*16]);
        __m512i r3 = _mm512_add_epi32(r1, r2);
        _mm512_store_epi32(&res[i*16], r3);
    }
}

static int vector_add_init(struct test *test)
{
    uint32_t *scratch = malloc(VECTOR_ADD_BUF_SIZE);

    memset_random(scratch, VECTOR_ADD_BUF_SIZE);
    set_input(vector_add_a, scratch, VECTOR_ADD_ELEMENTS, "First array of addends");
    memset_random(scratch, VECTOR_ADD_BUF_SIZE);
    set_input(vector_add_b, scratch, VECTOR_ADD_ELEMENTS, "Second array of addends");
    free(scratch);

    return EXIT_SUCCESS;
}

static int vector_add_run(struct test *test, int cpu)
{
    const __auto_type a = get_input(vector_add_a);
    const __auto_type b = get_input(vector_add_b);
    uint32_t *res = aligned_alloc(64, VECTOR_ADD_BUF_SIZE);

    TEST_LOOP(test, 1 << 13) {
        memset(res, 0, VECTOR_ADD_BUF_SIZE);
        vector_add_do_add(a.data, b.data, res);
        submit_output(vector_add_sum, res, VECTOR_ADD_ELEMENTS, "Element-wise unsigned sums");
    }

    free(res);

    return EXIT_SUCCESS;
}

DECLARE_TEST(vector_add, "Repeatedly add arrays of unsigned integers using AVX-512 instructions")
    .test_init = vector_add_init,
    .test_run = vector_add_run,
    .crosscheck = CrossCheckConsensus,
    .minimum_cpu = cpu_skylake_avx512,
    .quality_level = TEST_QUALITY_BETA,
END_DECLARE_TEST
