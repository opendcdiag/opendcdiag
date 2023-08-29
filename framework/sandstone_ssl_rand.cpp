/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */


#include "sandstone_ssl.h"
#include "sandstone_ssl_rand.h"

static OSSL_PROVIDER *s_prov;

/* Random context management */
static void *sandstone_rand_newctx(void *ctx, void *parent,
                            const OSSL_DISPATCH *parent_calls)
{
    // Allocate context
    int *rand_st = reinterpret_cast<int*>(malloc(sizeof(*rand_st)));
    if (rand_st != NULL)
        *rand_st = EVP_RAND_STATE_UNINITIALISED;

    return rand_st;
}

static void sandstone_rand_freectx(void *ctx)
{
     free(ctx);
}

/* Random number generator functions */
static int sandstone_rand_instantiate(void *ctx, unsigned int strength, int prediction_resistance,
                               const unsigned char *pstr, size_t pstr_len,
                               const OSSL_PARAM params[])
{
    ctx = reinterpret_cast<void *>(EVP_RAND_STATE_READY);
    return 1;
}

static int sandstone_rand_uninstantiate(void *ctx)
{
    ctx = reinterpret_cast<void *>(EVP_RAND_STATE_UNINITIALISED);
    return 1;
}

static int sandstone_rand_generate(void *ctx, unsigned char *out, size_t outlen,
                            unsigned int strength, int prediction_resistance,
                            const unsigned char *addin, size_t addin_len)
{
    memset_random(out, outlen);
    return 1;
}

/* Infra for future thread-safe support */
static int sandstone_rand_enable_locking(ossl_unused void *ctx)
{
    return 1;
}

static const OSSL_PARAM *sandstone_rand_gettable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        s_OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
        s_OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        s_OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

/* Get details of currently set parameter values associated with the given provider
 * https://www.openssl.org/docs/man3.0/man7/EVP_RAND-CTR-DRBG.html
 */
static int sandstone_rand_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = s_OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p != NULL && !s_OSSL_PARAM_set_int(p, *(int *)ctx))
        return 0;

    p = s_OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !s_OSSL_PARAM_set_int(p, 500))
        return 0;

    p = s_OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !s_OSSL_PARAM_set_size_t(p, INT_MAX))
        return 0;

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
    {OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))sandstone_rand_enable_locking},
    {OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void(*)(void))sandstone_rand_gettable_ctx_params },
    {OSSL_FUNC_RAND_GET_CTX_PARAMS, (void(*)(void))sandstone_rand_get_ctx_params },
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
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))s_OSSL_LIB_CTX_free},
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
    // Check OpenSSL is working before loading the random provider.
    if (!OpenSSLWorking)
        return;

    if (s_OSSL_PROVIDER_add_builtin(NULL, "sandstone-rand", sandstone_ssl_rand_provider_init) != 1
            || s_RAND_set_DRBG_type(NULL, "sand-rand", NULL, NULL, NULL) != 1
            || (s_prov = s_OSSL_PROVIDER_try_load(NULL, "sandstone-rand", 1)) == NULL )
        fprintf(stderr, "%s WARNING: Cannot load sandstone random provider", program_invocation_name);
}

void sandstone_ssl_rand_unload()
{
    s_OSSL_PROVIDER_unload(s_prov);
}
