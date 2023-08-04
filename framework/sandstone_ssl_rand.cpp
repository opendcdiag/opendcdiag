/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */


#include "sandstone_ssl.h"
#include "sandstone_ssl_rand.h"

static OSSL_PROVIDER *s_prov;

/* Random context management */
static void *sandstone_rand_newctx(void *provctx, void *parent,
                            const OSSL_DISPATCH *parent_calls)
{}

static void sandstone_rand_freectx(void *ctx)
{}

/* Random number generator functions */
static int sandstone_rand_instantiate(void *ctx, unsigned int strength, int prediction_resistance,
                               const unsigned char *pstr, size_t pstr_len,
                               const OSSL_PARAM params[])
{
    return 1;
}

static int sandstone_rand_uninstantiate(void *ctx)
{
    return 1;
}

static int sandstone_rand_generate(void *ctx, unsigned char *out, size_t outlen,
                            unsigned int strength, int prediction_resistance,
                            const unsigned char *addin, size_t addin_len)
{
    return 1;
}


/* Random functions
 * https://www.openssl.org/docs/man3.0/man7/provider-rand.html
 */
static const OSSL_DISPATCH sandstone_rand_functions[] = {
    {OSSL_FUNC_RAND_NEWCTX, (void (*)(void))sandstone_rand_newctx},
    {OSSL_FUNC_RAND_FREECTX, (void (*)(void))sandstone_rand_freectx},
    {OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))sandstone_rand_instantiate},
    {OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))sandstone_rand_uninstantiate},
    {OSSL_FUNC_RAND_GENERATE, (void (*)(void))sandstone_rand_generate},
    //{OSSL_FUNC_RAND_, (void (*)(void))sandstone_rand_},
    //{OSSL_FUNC_RAND_, (void (*)(void))sandstone_rand_},
    {0, NULL}
};

static const OSSL_ALGORITHM sandstone_rand_op[] = {
    {"sand-rand", "provider=sandstone-rand", sandstone_rand_functions},
    {NULL, NULL, NULL}
};

static const OSSL_ALGORITHM *sandstone_rand_query(const OSSL_PROVIDER *prov,
    int operation_id, int *no_cache)
{
    // Provider will only offer random
    switch (operation_id) {
        case OSSL_OP_RAND:
            return sandstone_rand_op;
    }
    return NULL;
}

/* Base functions offered by the provider */
static const OSSL_DISPATCH sandstone_rand_method[] = {
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))OSSL_LIB_CTX_free},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))sandstone_rand_query},
    {0, NULL }
};

/* Provider's initialization */
static int sandstone_ssl_rand_provider_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
    void **provctx)
{
    // Create provider context
    *provctx = s_OSSL_LIB_CTX_new();
    if (*provctx == NULL)
         return 0;

    *out = sandstone_rand_method;
    return 1;
}

void sandstone_ssl_rand_init()
{
    if (s_OSSL_PROVIDER_add_builtin(NULL, "sandstone-rand", sandstone_ssl_rand_provider_init) != 1)
        fprintf(stderr, "%s WARNING: Cannot load sandstone random provider", program_invocation_name);
}
