#include <sandstone.h>
#include <stdlib.h>

#define NUM_ELEMENTS 256

static int init(struct test *test) {
    test->data = malloc(NUM_ELEMENTS * sizeof(uint32_t));
    memset_random(test->data, NUM_ELEMENTS * sizeof(uint32_t));

    return EXIT_SUCCESS;
}

static void scramble(uint32_t* dst, const uint32_t* src, size_t size) {
    memset(dst, 0, (size * sizeof(uint32_t)));
    for (size_t j = 0; j < size; ++j) {
        dst[j] |= src[j];
        for (size_t i = 0; i < size; ++i) {
            dst[j] ^= src[i];
        }
    }
}

static int run(struct test *test, int cpu) {
    uint32_t dst[NUM_ELEMENTS];

    TEST_LOOP(test, 1) {
        scramble(dst, (const uint32_t*)test->data, NUM_ELEMENTS);
        cross_compare_or_fail("golden", dst, NUM_ELEMENTS);
    }

    return EXIT_SUCCESS;
}

static int cleanup(struct test *test) {

    free(test->data);

    return EXIT_SUCCESS;
}


DECLARE_TEST(cross_compare_demo, "")
        .quality_level = TEST_QUALITY_BETA,
        .test_init = init,
        .test_run = run,
        .test_cleanup = cleanup,
END_DECLARE_TEST
