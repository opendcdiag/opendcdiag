/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sandstone.h>
#include "fp_vectors/Floats.h"

int test_floats_prototypes_c(void)
{
    HFloat8 hfloat8 = new_hfloat8(0, 0, 0);
    BFloat8 bfloat8 = new_bfloat8(0, 0, 0);
    Float16 float16 = new_float16(0, 0, 0);
    BFloat16 bfloat16 = new_bfloat16(0, 0, 0);
    Float32 float32 = new_float32(0, 0, 0);
    float f = 0.0f;
    Float64 float64 = new_float64(0, 0, 0);
    double d = 0.0;
    Float80 float80 = new_float80(0, 0, 0, 0);

    if (IS_NEGATIVE(hfloat8)) return __LINE__;
    if (IS_NEGATIVE(bfloat8)) return __LINE__;
    if (IS_NEGATIVE(float16)) return __LINE__;
    if (IS_NEGATIVE(bfloat16)) return __LINE__;
    if (IS_NEGATIVE(float32)) return __LINE__;
    if (IS_NEGATIVE(f)) return __LINE__;
    if (IS_NEGATIVE(float64)) return __LINE__;
    if (IS_NEGATIVE(d)) return __LINE__;
    if (IS_NEGATIVE(float80)) return __LINE__;

    if (!IS_ZERO(hfloat8)) return __LINE__;
    if (!IS_ZERO(bfloat8)) return __LINE__;
    if (!IS_ZERO(float16)) return __LINE__;
    if (!IS_ZERO(bfloat16)) return __LINE__;
    if (!IS_ZERO(float32)) return __LINE__;
    if (!IS_ZERO(f)) return __LINE__;
    if (!IS_ZERO(float64)) return __LINE__;
    if (!IS_ZERO(d)) return __LINE__;
    if (!IS_ZERO(float80)) return __LINE__;

    if (IS_DENORMAL(hfloat8)) return __LINE__;
    if (IS_DENORMAL(bfloat8)) return __LINE__;
    if (IS_DENORMAL(float16)) return __LINE__;
    if (IS_DENORMAL(bfloat16)) return __LINE__;
    if (IS_DENORMAL(float32)) return __LINE__;
    if (IS_DENORMAL(f)) return __LINE__;
    if (IS_DENORMAL(float64)) return __LINE__;
    if (IS_DENORMAL(d)) return __LINE__;
    if (IS_DENORMAL(float80)) return __LINE__;

    if (!IS_FINITE(hfloat8)) return __LINE__;
    if (!IS_FINITE(bfloat8)) return __LINE__;
    if (!IS_FINITE(float16)) return __LINE__;
    if (!IS_FINITE(bfloat16)) return __LINE__;
    if (!IS_FINITE(float32)) return __LINE__;
    if (!IS_FINITE(f)) return __LINE__;
    if (!IS_FINITE(float64)) return __LINE__;
    if (!IS_FINITE(d)) return __LINE__;
    if (!IS_FINITE(float80)) return __LINE__;

    if (IS_INF_NAN(hfloat8)) return __LINE__;
    if (IS_OVERFLOW(hfloat8)) return __LINE__;
    if (IS_OVERFLOW(bfloat8)) return __LINE__;

    if (IS_INF(bfloat8)) return __LINE__;
    if (IS_INF(float16)) return __LINE__;
    if (IS_INF(bfloat16)) return __LINE__;
    if (IS_INF(float32)) return __LINE__;
    if (IS_INF(f)) return __LINE__;
    if (IS_INF(float64)) return __LINE__;
    if (IS_INF(d)) return __LINE__;
    if (IS_INF(float80)) return __LINE__;

    if (IS_NAN(bfloat8)) return __LINE__;
    if (IS_NAN(float16)) return __LINE__;
    if (IS_NAN(bfloat16)) return __LINE__;
    if (IS_NAN(float32)) return __LINE__;
    if (IS_NAN(f)) return __LINE__;
    if (IS_NAN(float64)) return __LINE__;
    if (IS_NAN(d)) return __LINE__;
    if (IS_NAN(float80)) return __LINE__;

    if (IS_SNAN(bfloat8)) return __LINE__;
    if (IS_SNAN(float16)) return __LINE__;
    if (IS_SNAN(bfloat16)) return __LINE__;
    if (IS_SNAN(float32)) return __LINE__;
    if (IS_SNAN(f)) return __LINE__;
    if (IS_SNAN(float64)) return __LINE__;
    if (IS_SNAN(d)) return __LINE__;
    if (IS_SNAN(float80)) return __LINE__;

    if (IS_QNAN(bfloat8)) return __LINE__;
    if (IS_QNAN(float16)) return __LINE__;
    if (IS_QNAN(bfloat16)) return __LINE__;
    if (IS_QNAN(float32)) return __LINE__;
    if (IS_QNAN(f)) return __LINE__;
    if (IS_QNAN(float64)) return __LINE__;
    if (IS_QNAN(d)) return __LINE__;
    if (IS_QNAN(float80)) return __LINE__;

    if (GET_NAN_PAYLOAD(float16) != 0) return __LINE__;
    if (GET_NAN_PAYLOAD(bfloat16) != 0) return __LINE__;
    if (GET_NAN_PAYLOAD(float32) != 0) return __LINE__;
    if (GET_NAN_PAYLOAD(f) != 0) return __LINE__;
    if (GET_NAN_PAYLOAD(float64) != 0) return __LINE__;
    if (GET_NAN_PAYLOAD(d) != 0) return __LINE__;
    if (GET_NAN_PAYLOAD(float80) != 0) return __LINE__;

    if (AS_FP(hfloat8) != 0.0) return __LINE__;
    if (AS_FP(bfloat8) != 0.0) return __LINE__;
    if (AS_FP(float16) != 0.0) return __LINE__;
    if (AS_FP(bfloat16) != 0.0) return __LINE__;
    if (AS_FP(float32) != 0.0) return __LINE__;
    if (AS_FP(f) != 0.0) return __LINE__;
    if (AS_FP(float64) != 0.0) return __LINE__;
    if (AS_FP(d) != 0.0) return __LINE__;
    if (AS_FP(float80) != 0.0) return __LINE__;

    new_random_hfloat8();
    new_random_bfloat8();
    new_random_float16();
    new_random_bfloat16();
    new_random_float32();
    new_random_float();
    new_random_float64();
    new_random_double();
    new_random_float80();

    SET_RANDOM(hfloat8);
    SET_RANDOM(bfloat8);
    SET_RANDOM(float16);
    SET_RANDOM(bfloat16);
    SET_RANDOM(float32);
    SET_RANDOM(f);
    SET_RANDOM(float64);
    SET_RANDOM(d);
    SET_RANDOM(float80);

    bfloat8 = new_random(BFloat8);
    hfloat8 = new_random(HFloat8);
    bfloat16 = new_random(BFloat16);
    float16 = new_random(Float16);
    float32 = new_random(Float32);
    f = new_random(float);
    float64 = new_random(Float64);
    d = new_random(double);
    float80 = new_random(Float80);

    return 0;
}

#define ASSERT_EQ(exp, act) do { if ((exp) != (act)) { return __LINE__; }} while (0)

// NAN is a predefined __builtin, undefine it to properly handle local IS_NAN
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
        F f = new_random(F);\
        IS(__VA_ARGS__); \
        AS_FP(f);\
    } while (0)

int test_new_random_float_prototypes_c(void) {
    new_random_hfloat8(FP_PATTERNED);
    new_random_bfloat8(FP_PATTERNED);
    new_random_float16(FP_PATTERNED);
    new_random_bfloat16(FP_PATTERNED);
    new_random_float32(FP_PATTERNED);
    new_random_float(FP_PATTERNED);
    new_random_float64(FP_PATTERNED);
    new_random_double(FP_PATTERNED);
    new_random_float80(FP_PATTERNED);

    new_random_hfloat8(FP_FAST_MEMSET);
    new_random_bfloat8(FP_FAST_MEMSET);
    new_random_float16(FP_FAST_MEMSET);
    new_random_bfloat16(FP_FAST_MEMSET);
    new_random_float32(FP_FAST_MEMSET);
    new_random_float(FP_FAST_MEMSET);
    new_random_float64(FP_FAST_MEMSET);
    new_random_double(FP_FAST_MEMSET);
    new_random_float80(FP_FAST_MEMSET);


    CHECK(HFloat8, NEGATIVE, ZERO, DENORMAL, FINITE, INF_NAN, OVERFLOW);
    CHECK(BFloat8, NEGATIVE, ZERO, DENORMAL, FINITE, INF, NAN, SNAN, QNAN, OVERFLOW);
    CHECK(Float16, NEGATIVE, ZERO, DENORMAL, FINITE, INF, NAN, SNAN, QNAN);
    CHECK(BFloat16, NEGATIVE, ZERO, DENORMAL, FINITE, INF, NAN, SNAN, QNAN);
    CHECK(Float32, NEGATIVE, ZERO, DENORMAL, FINITE, INF, NAN, SNAN, QNAN);
    CHECK(Float64, NEGATIVE, ZERO, DENORMAL, FINITE, INF, NAN, SNAN, QNAN);
    CHECK(Float80);

    // default generator with a range
    new_random_hfloat8(12.0, 13.0);
    new_random_bfloat8(12.0, 13.0);
    new_random_float16(12.0, 13.0);
    new_random_bfloat16(12.0, 13.0);
    new_random_float32(12.0, 13.0);
    new_random_float(12.0, 13.0);
    new_random_float64(12.0, 13.0);
    new_random_double(12.0, 13.0);
    new_random_float80(12.0, 13.0);

    // generator with a range
    const float MAX_FLOAT = 3.4028235e38f;
    new_random_hfloat8(0, MAX_FLOAT);
    new_random_bfloat8(0, MAX_FLOAT);
    new_random_float16(0, MAX_FLOAT);
    new_random_bfloat16(0, MAX_FLOAT);
    new_random_float32(0, MAX_FLOAT);
    new_random_float(0, MAX_FLOAT);
    new_random_float64(0, MAX_FLOAT);
    new_random_double(0, MAX_FLOAT);
    new_random_float80(0, MAX_FLOAT);

    return 0;
}
