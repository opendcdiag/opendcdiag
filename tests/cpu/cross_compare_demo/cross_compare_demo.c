#include <sandstone.h>
#include <stdlib.h>

#define BUFSZ 1024

static int init(struct test *test) {
    cross_compare_init(test, 1);
    cross_compare_set_size(test, 0, BUFSZ);

    test->data = malloc(BUFSZ);
    memset_random((char*)test->data, BUFSZ);

    return EXIT_SUCCESS;
}

static void xor_scramble(char* dst, const char* src, size_t size) {
    memset(dst, 0, size);
    for (size_t j = 0; j < size; ++j) {
        for (size_t i = 0; i < size; ++i) {
            dst[i] ^= src[i];
        }
    }
}

static int run(struct test *test, int cpu) {
    char dst[BUFSZ];

    TEST_LOOP(test, 1) {
        xor_scramble(dst, (const char*)test->data, BUFSZ);
        cross_compare_or_fail(test, 0, dst);
    }

    return EXIT_SUCCESS;
}

static int cleanup(struct test *test) {
    cross_compare_cleanup(test);

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
