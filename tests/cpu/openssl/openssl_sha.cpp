/**
 *
 * @copyright
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test openssl_sha
 *
 * @parblock
 * The test calculates 3 different checksums (sha256, sha384 and sha512) for a
 * corpus of 1,024 randomly generated 512-byte buffers. Init and workers get
 * the plaintext inputs and submit digest arrays for cross-checking. Later
 * submissions on a CPU must match that CPU's first. Init's results participate in
 * verification, not as trusted references. Each worker completes at least one
 * corpus sweep, using randomized traversal and odd buffer offsets, before
 * checking whether to repeat.
 *
 * @note Cross-owner comparison requires at least two published CPU owners
 * within the same execution slice/pass.
 * Init and a worker on the same CPU provide same-owner checking, not extra votes.
 * @endparblock
 *
 */

#include "sandstone.h"
#include "crosscheck.h"

#if SANDSTONE_SSL_BUILD

#include "sandstone_ssl.h"

#include <array>
#include <string.h>
#include <stdlib.h>
#include <vector>

#define PLAINTEXT_SIZE              (512UL)
#define SHA_GOLDEN_ELEMS            (1024UL)
#define SHA_MAX_OFFSET              (512UL)

namespace {

struct sha_elem
{
    uint8_t plain_text[PLAINTEXT_SIZE];
    uint8_t sha256sum[SHA256_DIGEST_LENGTH];
    uint8_t sha384sum[SHA384_DIGEST_LENGTH];
    uint8_t sha512sum[SHA512_DIGEST_LENGTH];
};

CROSSCHECK_INPUT(sha_plaintexts, uint8_t);
CROSSCHECK_OUTPUT(sha256_digests, uint8_t);
CROSSCHECK_OUTPUT(sha384_digests, uint8_t);
CROSSCHECK_OUTPUT(sha512_digests, uint8_t);

struct sha_digests
{
    std::array<uint8_t, SHA_GOLDEN_ELEMS * SHA256_DIGEST_LENGTH> sha256;
    std::array<uint8_t, SHA_GOLDEN_ELEMS * SHA384_DIGEST_LENGTH> sha384;
    std::array<uint8_t, SHA_GOLDEN_ELEMS * SHA512_DIGEST_LENGTH> sha512;
};

static int calculate_sha(const char *algorithm, const uint8_t *plaintext, uint8_t *digest,
                         unsigned int expected_length, size_t index)
{
    const EVP_MD *md = s_EVP_get_digestbyname(algorithm);
    if (!md) {
        log_skip(TestResourceIssueSkipCategory,
                 "%s EVP_get_digestbyname unavailable at corpus index %zu", algorithm, index);
        return EXIT_SKIP;
    }

    EVP_MD_CTX *mdctx = s_EVP_MD_CTX_new();
    if (!mdctx) {
        log_skip(TestResourceIssueSkipCategory,
                 "%s EVP_MD_CTX_new failed at corpus index %zu", algorithm, index);
        return EXIT_SKIP;
    }

    int result = EXIT_SUCCESS;
    unsigned int md_len = 0;
    if (s_EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        log_skip(TestResourceIssueSkipCategory,
                 "%s EVP_DigestInit_ex failed at corpus index %zu", algorithm, index);
        result = EXIT_SKIP;
    } else if (s_EVP_DigestUpdate(mdctx, plaintext, PLAINTEXT_SIZE) != 1) {
        log_error("%s EVP_DigestUpdate failed at corpus index %zu", algorithm, index);
        result = EXIT_FAILURE;
    } else if (s_EVP_DigestFinal_ex(mdctx, digest, &md_len) != 1) {
        log_error("%s EVP_DigestFinal_ex failed at corpus index %zu", algorithm, index);
        result = EXIT_FAILURE;
    } else if (md_len != expected_length) {
        log_error("%s EVP_DigestFinal_ex wrong length at corpus index %zu: got %u, expected %u",
                  algorithm, index, md_len, expected_length);
        result = EXIT_FAILURE;
    }
    s_EVP_MD_CTX_free(mdctx);
    return result;
}

static int calculate_sha_corpus(sha_digests &digests)
{
    auto plaintexts = get_input(sha_plaintexts);
    uint8_t arena[SHA_MAX_OFFSET + sizeof(sha_elem)];
    size_t index = random64() & (SHA_GOLDEN_ELEMS - 1);
    // An odd stride visits every member of this power-of-two corpus once.
    const size_t stride = (random64() & (SHA_GOLDEN_ELEMS - 1)) | 1;
    for (size_t i = 0; i < SHA_GOLDEN_ELEMS; ++i) {
        const size_t offset = (random64() & 0x1ff) | 1;
        sha_elem *elem = reinterpret_cast<sha_elem *>(&arena[offset]);
        memcpy(elem->plain_text, &plaintexts[index * PLAINTEXT_SIZE], PLAINTEXT_SIZE);
        int result = calculate_sha("sha256", elem->plain_text, elem->sha256sum, SHA256_DIGEST_LENGTH, index);
        if (result != EXIT_SUCCESS)
            return result;
        result = calculate_sha("sha384", elem->plain_text, elem->sha384sum, SHA384_DIGEST_LENGTH, index);
        if (result != EXIT_SUCCESS)
            return result;
        result = calculate_sha("sha512", elem->plain_text, elem->sha512sum, SHA512_DIGEST_LENGTH, index);
        if (result != EXIT_SUCCESS)
            return result;
        memcpy(&digests.sha256[index * SHA256_DIGEST_LENGTH], elem->sha256sum, SHA256_DIGEST_LENGTH);
        memcpy(&digests.sha384[index * SHA384_DIGEST_LENGTH], elem->sha384sum, SHA384_DIGEST_LENGTH);
        memcpy(&digests.sha512[index * SHA512_DIGEST_LENGTH], elem->sha512sum, SHA512_DIGEST_LENGTH);
        index = (index + stride) & (SHA_GOLDEN_ELEMS - 1);
    }
    return EXIT_SUCCESS;
}

static void submit_sha_digests(const sha_digests &digests)
{
    submit_output(sha256_digests, digests.sha256, "SHA-256 corpus digests");
    submit_output(sha384_digests, digests.sha384, "SHA-384 corpus digests");
    submit_output(sha512_digests, digests.sha512, "SHA-512 corpus digests");
}

#pragma GCC diagnostic ignored "-Waddress" // for builds we've linked to OpenSSL
static int ssl_sha_init(struct test* test)
{
    if (s_EVP_MD_CTX_new && s_EVP_MD_CTX_free && s_EVP_DigestInit_ex && s_EVP_DigestUpdate
            && s_EVP_DigestFinal_ex && s_EVP_get_digestbyname) {
        std::vector<uint8_t> plaintexts(SHA_GOLDEN_ELEMS * PLAINTEXT_SIZE);
        memset_random(plaintexts.data(), plaintexts.size());
        set_input(sha_plaintexts, plaintexts, "Plaintext corpus");

        sha_digests digests;
        int result = calculate_sha_corpus(digests);
        if (result != EXIT_SUCCESS)
            return result;
        submit_sha_digests(digests);
        return EXIT_SUCCESS;
    }
    else {
        log_skip(TestResourceIssueSkipCategory, "OpenSSL library is not available or the current version is not supported");
        return EXIT_SKIP;
    }
}

static int ssl_sha_run(struct test* test, int cpu)
{
    sha_digests digests;
    TEST_LOOP(test, 1) {
        int result = calculate_sha_corpus(digests);
        if (result != EXIT_SUCCESS)
            return result;
        submit_sha_digests(digests);
    }
    return EXIT_SUCCESS;
}

} // namespace

#else // !SANDSTONE_SSL_BUILD

static int ssl_sha_init(struct test *test)
{
    log_skip(OsNotSupportedSkipCategory, "Not supported on this OS");
    return EXIT_SKIP;
}

static int ssl_sha_run(struct test *test, int cpu)
{
    __builtin_unreachable();
}

#endif

DECLARE_TEST(openssl_sha, "Test calculating different sha checksums")
    .test_init = ssl_sha_init,
    .test_run = ssl_sha_run,
    .quality_level = TEST_QUALITY_PROD,
END_DECLARE_TEST
