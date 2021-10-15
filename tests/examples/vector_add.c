/**
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b vector_add
 * @parblock
 * vector_add repeatedly adds two arrays of random numbers together using
 * AVX-512 instructions and checks that their output is correct.
 * @endparblock
 */

#include "sandstone.h"

#include <immintrin.h>

#define VECTOR_ADD_ELEMENTS (1u << 10)
#define VECTOR_ADD_BUF_SIZE (VECTOR_ADD_ELEMENTS * sizeof(uint32_t))

struct vector_add_t_ {
        uint32_t *a;
        uint32_t *b;
        uint32_t *golden;
};
typedef struct vector_add_t_ vector_add_t;

static void prv_do_add(const uint32_t *a, const uint32_t *b, uint32_t *res)
{
        for (size_t i = 0; i < VECTOR_ADD_ELEMENTS / 16; i++) {
                __m512i r1 = _mm512_load_epi32(&a[i*16]);
                __m512i r2 = _mm512_load_epi32(&b[i*16]);
                __m512i r3 = _mm512_add_epi32(r1, r2);
                _mm512_store_epi32(&res[i*16], r3);
        }
}

static int vector_add_init(struct test *test)
{
        vector_add_t *va = malloc(sizeof(*va));

        va->a = aligned_alloc(64, VECTOR_ADD_BUF_SIZE);
        va->b = aligned_alloc(64, VECTOR_ADD_BUF_SIZE);
        va->golden = aligned_alloc_safe(64, VECTOR_ADD_BUF_SIZE);

        memset_random(va->a, VECTOR_ADD_BUF_SIZE);
        memset_random(va->b, VECTOR_ADD_BUF_SIZE);
        prv_do_add(va->a, va->b, va->golden);

        test->data = va;

        return EXIT_SUCCESS;
}

static int vector_add_run(struct test *test, int cpu)
{
        vector_add_t *va = test->data;
        uint32_t *res = aligned_alloc(64, VECTOR_ADD_BUF_SIZE);

        TEST_LOOP(test, 1 << 13) {
                memset(res, 0, VECTOR_ADD_BUF_SIZE);
                prv_do_add(va->a, va->b, res);
                memcmp_or_fail(res, va->golden, VECTOR_ADD_ELEMENTS);
        }

        free(res);

        return EXIT_SUCCESS;
}

static int vector_add_cleanup(struct test *test)
{
        vector_add_t *va = test->data;

        if (va) {
                free(va->golden);
                free(va->b);
                free(va->a);
                free(va);
        }

        return EXIT_SUCCESS;
}

DECLARE_TEST(vector_add, "Repeatedly add arrays of unsigned integers using AVX-512 instructions")
        .test_init = vector_add_init,
        .test_run = vector_add_run,
        .test_cleanup = vector_add_cleanup,
        .minimum_cpu = cpu_skylake_avx512,
        .quality_level = TEST_QUALITY_BETA,
END_DECLARE_TEST
