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

#include <sandstone.h>
#include <test_class_cpu.hpp>

#if SANDSTONE_SSL_BUILD

#include <sandstone_ssl.h>

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/mman.h>

namespace {
class OpensshShaTest : public SandstoneTest::Cpu
{
public:
    static constexpr auto quality_level = TestQuality::Production;
    static constexpr char description[] = "Test calculating different sha checksums";

    int init()
    {
        if (s_EVP_DigestInit_ex && s_EVP_DigestUpdate && s_EVP_DigestFinal_ex && s_EVP_get_digestbyname) {
            const size_t sha_offset = (random64() & 0x1ff) | 1;
            const size_t sha_arena_size = sha_offset + sizeof(sha_test);
            sha_test_ctx.arena = (uint8_t *) mmap(NULL, sha_arena_size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
            sha_test_ctx.arena_size = sha_arena_size;

            for (size_t i=0; i<SHA_GOLDEN_ELEMS; i++) {
                sha_elem *cursor = &sha_test_ctx.golden_elements[i];
                memset_random(&cursor->plain_text[0], PLAINTEXT_SIZE);

                /* Calculate sha checksums */
                ssl_sha256(cursor);
                ssl_sha384(cursor);
                ssl_sha512(cursor);
            }

            return EXIT_SUCCESS;
        }
        else {
            log_skip(TestResourceIssueSkipCategory, "OpenSSL library is not available or the current version is not supported");
            return EXIT_SKIP;
        }
    }

    int run()
    {
        const size_t our_arena_size = SHA_MAX_OFFSET + sizeof(sha_elem);
        uint8_t *our_arena = (uint8_t *) mmap(NULL, our_arena_size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

        test_loop<256>([&] {
            const size_t our_offset = (random64() & 0x1ff) | 1;
            const size_t golden_idx = random64() & (SHA_GOLDEN_ELEMS - 1);
            sha_elem *golden_elem = &sha_test_ctx.golden_elements[golden_idx];

            sha_elem *our_elem = (sha_elem *) (&our_arena[our_offset]);
            memcpy(&our_elem->plain_text, &golden_elem->plain_text[0], PLAINTEXT_SIZE);

            ssl_sha256(our_elem);
            ssl_sha384(our_elem);
            ssl_sha512(our_elem);

            /* Check result against golden values */
            memcmp_or_fail(&our_elem->sha256sum[0], &golden_elem->sha256sum[0], SHA256_DIGEST_LENGTH,
                    "sha256sum values does not match.");
            memcmp_or_fail(&our_elem->sha384sum[0], &golden_elem->sha384sum[0], SHA384_DIGEST_LENGTH,
                    "sha384sum values does not match.");
            memcmp_or_fail(&our_elem->sha512sum[0], &golden_elem->sha512sum[0], SHA512_DIGEST_LENGTH,
                    "sha512sum values does not match.");
        });

        return EXIT_SUCCESS;
    }

private:
    static constexpr auto PLAINTEXT_SIZE = 512UL;
    static constexpr auto SHA_GOLDEN_ELEMS = 1024UL;
    static constexpr auto SHA_MAX_OFFSET = 512UL;

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
    } sha_test_ctx;

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
};
} // end anonymous namespace

#else // !SANDSTONE_SSL_BUILD

namespace {
class OpensshShaTest : public SandstoneTest::Cpu
{
public:
    static constexpr auto quality_level = TestQuality::Production;
    static constexpr char description[] = "Test calculating different sha checksums";

    int init()
    {
        log_skip(OsNotSupportedSkipCategory, "Not supported on this OS");
        return EXIT_SKIP;
    }

    int run()
    {
        __builtin_unreachable();
    }
};
} // end anonymous namespace

#endif

DECLARE_TEST_CLASS(openssh_sha, OpensshShaTest);
