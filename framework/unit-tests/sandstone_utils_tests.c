/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sandstone.h>
#include "fp_vectors/Floats.h"

#define ASSERT_EQ(exp, act) do { if ((exp) != (act)) { return __LINE__; }} while (0)

// NAN is a predefined __builtin, undefine it to properly handle IS_NAN
#undef NAN

#define IS0()
#define IS1(o)       OVERLOAD(IS_, o)(f)
#define IS2(o, ...)  IS1(o); IS1(__VA_ARGS__)
#define IS3(o, ...)  IS1(o); IS2(__VA_ARGS__)
#define IS4(o, ...)  IS1(o); IS3(__VA_ARGS__)
#define IS5(o, ...)  IS1(o); IS4(__VA_ARGS__)
#define IS6(o, ...)  IS1(o); IS5(__VA_ARGS__)
#define IS7(o, ...)  IS1(o); IS6(__VA_ARGS__)
#define IS8(o, ...)  IS1(o); IS7(__VA_ARGS__)
#define IS9(o, ...)  IS1(o); IS8(__VA_ARGS__)
#define IS10(o, ...) IS1(o); IS9(__VA_ARGS__)
#define IS(...)      OVERLOAD(IS, NARGS(__VA_ARGS__))(__VA_ARGS__)

#define CHECK(F, ...) do {\
        F f = NEW_RANDOM(F);\
        IS(__VA_ARGS__); \
        TO_FLOAT(f);\
    } while (0)

int test_new_random_float_prototypes_c(void) {
    new_random_hfloat8();
    new_random_bfloat8();
    new_random_float16();
    new_random_bfloat16();
    new_random_float32();
    new_random_float();
    new_random_float64();
    new_random_double();
    new_random_float80();

    new_random_hfloat8(PATTERNED);
    new_random_bfloat8(PATTERNED);
    new_random_float16(PATTERNED);
    new_random_bfloat16(PATTERNED);
    new_random_float32(PATTERNED);
    new_random_float(PATTERNED);
    new_random_float64(PATTERNED);
    new_random_double(PATTERNED);
    new_random_float80(PATTERNED);

    new_random_hfloat8(FAST_MEMSET);
    new_random_bfloat8(FAST_MEMSET);
    new_random_float16(FAST_MEMSET);
    new_random_bfloat16(FAST_MEMSET);
    new_random_float32(FAST_MEMSET);
    new_random_float(FAST_MEMSET);
    new_random_float64(FAST_MEMSET);
    new_random_double(FAST_MEMSET);
    new_random_float80(FAST_MEMSET);


    CHECK(HFloat8, NEGATIVE, ZERO, DENORMAL, VALID, INF_NAN, OVERFLOW);
    CHECK(BFloat8, NEGATIVE, ZERO, DENORMAL, VALID, INF, NAN, SNAN, QNAN, OVERFLOW);
    CHECK(Float16, NEGATIVE, ZERO, DENORMAL, VALID, INF, NAN, SNAN, QNAN);
    CHECK(BFloat16, NEGATIVE, ZERO, DENORMAL, VALID, INF, NAN, SNAN, QNAN);
    CHECK(Float32, NEGATIVE, ZERO, DENORMAL, VALID, INF, NAN, SNAN, QNAN);
    CHECK(Float64, NEGATIVE, ZERO, DENORMAL, VALID, INF, NAN, SNAN, QNAN);
    CHECK(Float80);

    return 0;
}
