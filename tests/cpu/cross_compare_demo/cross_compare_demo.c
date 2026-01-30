#include <sandstone.h>
#include <stdlib.h>

#define BUFSZ 1024

static int init(struct test *test) {
    test->data = malloc(BUFSZ);
    memset_random((char*)test->data, BUFSZ);

    return EXIT_SUCCESS;
}

static void xor_scramble(char* dst, const char* src, size_t size) {
    memset(dst, 0, size);
    for (size_t j = 0; j < size; ++j) {
        dst[j] |= src[j];
        for (size_t i = 0; i < size; ++i) {
            dst[j] ^= src[i];
        }
    }
}

static int run(struct test *test, int cpu) {
    char dst[BUFSZ];

    TEST_LOOP(test, 1) {
        xor_scramble(dst, (const char*)test->data, BUFSZ);
        cross_compare_or_fail(test, "golden", dst, BUFSZ);
    }

    return EXIT_SUCCESS;
}

static int cleanup(struct test *test) {

    free(test->data);

    return EXIT_SUCCESS;
}


DECLARE_TEST(cross_compare_demo, "")
        .groups = DECLARE_TEST_GROUPS(&group_compression),
        .quality_level = TEST_QUALITY_BETA,
        .test_init = init,
        .test_run = run,
        .test_cleanup = cleanup,
END_DECLARE_TEST
