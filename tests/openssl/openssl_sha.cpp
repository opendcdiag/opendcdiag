/**
 *
 * @copyright
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test ssl_sha
 *
 * The test calculates 3 different checksums (sha256, sha384 and sha512) for a
 * given random-generated buffer and compares the results against
 * pre-calculated golden values.
 *
 */

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/mman.h>

#include "sandstone.h"
#include "sandstone_ssl.h"

#define PLAINTEXT_SIZE              (512UL)
#define SHA_GOLDEN_ELEMS            (1024UL)
#define SHA_MAX_OFFSET              (512UL)

struct sha_elem
{
    uint8_t plain_text[PLAINTEXT_SIZE];
    uint8_t sha256sum[SHA256_DIGEST_LENGTH];
    uint8_t sha384sum[SHA384_DIGEST_LENGTH];
    uint8_t sha512sum[SHA512_DIGEST_LENGTH];
};

struct sha_test
{
    uint8_t *arena;
    uint8_t arena_size;
    sha_elem golden_elements[SHA_GOLDEN_ELEMS];
};

static void ssl_sha256(sha_elem *target)
{
    /* Create Context */
    EVP_MD_CTX *mdctx = s_EVP_MD_CTX_new();

    /* Fetch algorithm */
    const EVP_MD *md = s_EVP_get_digestbyname("sha256");

    /* Digest */
    unsigned int md_len = 0;
    s_EVP_DigestInit_ex(mdctx, md, NULL);
    s_EVP_DigestUpdate(mdctx, &target->plain_text[0], PLAINTEXT_SIZE);
    s_EVP_DigestFinal_ex(mdctx, &target->sha256sum[0], &md_len);
}

static void ssl_sha384(sha_elem *target)
{
    /* Create Context */
    EVP_MD_CTX *mdctx = s_EVP_MD_CTX_new();

    /* Fetch algorithm */
    const EVP_MD *md = s_EVP_get_digestbyname("sha384");

    /* Digest */
    unsigned int md_len = 0;
    s_EVP_DigestInit_ex(mdctx, md, NULL);
    s_EVP_DigestUpdate(mdctx, &target->plain_text[0], PLAINTEXT_SIZE);
    s_EVP_DigestFinal_ex(mdctx, &target->sha384sum[0], &md_len);
}

static void ssl_sha512(sha_elem *target)
{
    /* Create Context */
    EVP_MD_CTX *mdctx = s_EVP_MD_CTX_new();

    /* Fetch algorithm */
    const EVP_MD *md = s_EVP_get_digestbyname("sha512");

    /* Digest */
    unsigned int md_len = 0;
    s_EVP_DigestInit_ex(mdctx, md, NULL);
    s_EVP_DigestUpdate(mdctx, &target->plain_text[0], PLAINTEXT_SIZE);
    s_EVP_DigestFinal_ex(mdctx, &target->sha512sum[0], &md_len);
}

static int ssl_sha_init(struct test* test)
{
    if (s_EVP_DigestInit_ex && s_EVP_DigestUpdate && s_EVP_DigestFinal_ex && s_EVP_get_digestbyname) {
        const size_t sha_offset = (random64() & 0x1ff) | 1;
        const size_t sha_arena_size = sha_offset + sizeof(sha_test);
        uint8_t *sha_arena = (uint8_t *) mmap(NULL, sha_arena_size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

        sha_test *sha_test_ptr = (sha_test *)(&sha_arena[sha_offset]);
        test->data = sha_test_ptr;

        sha_test_ptr->arena = sha_arena;
        sha_test_ptr->arena_size = sha_arena_size;

        for (size_t i=0; i<SHA_GOLDEN_ELEMS; i++)
        {
            sha_elem *cursor = &sha_test_ptr->golden_elements[i];
            memset_random(&cursor->plain_text[0], PLAINTEXT_SIZE);

            /* Calculate sha checksums */
            ssl_sha256(cursor);
            ssl_sha384(cursor);
            ssl_sha512(cursor);
        }

        return EXIT_SUCCESS;
    }
    else {
        return EXIT_SKIP;
    }
}

static int ssl_sha_run(struct test* test, int cpu)
{
    sha_test *sha_test_ptr = (sha_test *) test->data;
    sha_elem *golden_elements = &sha_test_ptr->golden_elements[0];

    const size_t our_arena_size = SHA_MAX_OFFSET + sizeof(sha_elem);
    uint8_t *our_arena = (uint8_t *) mmap(NULL, our_arena_size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);


    TEST_LOOP(test, 256) {
        const size_t our_offset = (random64() & 0x1ff) | 1;
        const size_t golden_idx = random64() & (SHA_GOLDEN_ELEMS - 1);
        sha_elem *golden_elem = &golden_elements[golden_idx];

        sha_elem *our_elem = (sha_elem *) (&our_arena[our_offset]);
        memcpy(&our_elem->plain_text, &golden_elem->plain_text[0], PLAINTEXT_SIZE);

        /* Calculate sha checksums */
        ssl_sha256(our_elem);
        ssl_sha384(our_elem);
        ssl_sha512(our_elem);

        /* Check result against golden values */
        memcmp_or_fail(&our_elem->sha256sum[0], &golden_elem->sha256sum[0], SHA256_DIGEST_LENGTH,
                "sha256sum values does not match.");
        memcmp_or_fail(&our_elem->sha384sum[0], &golden_elem->sha384sum[0], SHA256_DIGEST_LENGTH,
                "sha384sum values does not match.");
        memcmp_or_fail(&our_elem->sha512sum[0], &golden_elem->sha512sum[0], SHA256_DIGEST_LENGTH,
                "sha512sum values does not match.");
    }
    return EXIT_SUCCESS;
}

DECLARE_TEST(openssl_sha, "Test calculating differnt sha checksums")
    .test_init = ssl_sha_init,
    .test_run = ssl_sha_run,
    .quality_level = TEST_QUALITY_BETA,
END_DECLARE_TEST
