/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sandstone.h>
#include <fp_vectors/Floats.h>

#define CHECK_PROP_NEGATIVE CHECK_PREDICATES1
#define CHECK_PROP_ZERO CHECK_PREDICATES1
#define CHECK_PROP_DENORMAL CHECK_PREDICATES1
#define CHECK_PROP_FINITE CHECK_PREDICATES1
#define CHECK_PROP_INF_NAN CHECK_PREDICATES1
#define CHECK_PROP_INF CHECK_PREDICATES1
#define CHECK_PROP_NAN CHECK_PREDICATES1
#define CHECK_PROP_SNAN CHECK_PREDICATES1
#define CHECK_PROP_QNAN CHECK_PREDICATES1
#define CHECK_PROP_OVERFLOW CHECK_PREDICATES1
#define CHECK_PROP(o) OVERLOAD(CHECK_PROP_, o)()

#define CHECK_PREDICATES1(f)
#define CHECK_PREDICATES2(f, o, ...)  OVERLOAD(IS_, o)(f)
#define CHECK_PREDICATES3(f, o, ...)  CHECK_PREDICATES2(f, o); CHECK_PREDICATES2(f, __VA_ARGS__)
#define CHECK_PREDICATES4(f, o, ...)  CHECK_PREDICATES2(f, o); CHECK_PREDICATES3(f, __VA_ARGS__)
#define CHECK_PREDICATES5(f, o, ...)  CHECK_PREDICATES2(f, o); CHECK_PREDICATES4(f, __VA_ARGS__)
#define CHECK_PREDICATES6(f, o, ...)  CHECK_PREDICATES2(f, o); CHECK_PREDICATES5(f, __VA_ARGS__)
#define CHECK_PREDICATES7(f, o, ...)  CHECK_PREDICATES2(f, o); CHECK_PREDICATES6(f, __VA_ARGS__)
#define CHECK_PREDICATES8(f, o, ...)  CHECK_PREDICATES2(f, o); CHECK_PREDICATES7(f, __VA_ARGS__)
#define CHECK_PREDICATES9(f, o, ...)  CHECK_PREDICATES2(f, o); CHECK_PREDICATES8(f, __VA_ARGS__)
#define CHECK_PREDICATES10(f, o, ...) CHECK_PREDICATES2(f, o); CHECK_PREDICATES9(f, __VA_ARGS__)
#define CHECK_PREDICATES11(f, o, ...) CHECK_PREDICATES2(f, o); CHECK_PREDICATES10(f, __VA_ARGS__)
#define CHECK_PREDICATES(...)         OVERLOAD(CHECK_PREDICATES, NARGS(__VA_ARGS__))(__VA_ARGS__)

#define CHECK_FLOAT_PREDICATES(F, ...) do {\
        F f = {};\
        CHECK_PREDICATES(f, ##__VA_ARGS__);\
        AS_FP(f);\
    } while (0)

// some predicates are predefined __builtins, undefine to check unary predicates
// properly (without preprocessor expansion)
#ifdef NAN
#undef NAN
#endif

#ifdef SNAN
#undef SNAN
#endif

int test_floats_prototypes_c(void)
{
    // verify the unary predicates if not overloaded by "other" macros.
    // No code is generated from these
    CHECK_PROP(NEGATIVE);
    CHECK_PROP(ZERO);
    CHECK_PROP(DENORMAL);
    CHECK_PROP(FINITE);
    CHECK_PROP(INF_NAN);
    CHECK_PROP(INF);
    CHECK_PROP(NAN);
    CHECK_PROP(SNAN);
    CHECK_PROP(QNAN);
    CHECK_PROP(OVERFLOW);

    CHECK_FLOAT_PREDICATES(HFloat8, NEGATIVE, ZERO, DENORMAL, FINITE, INF_NAN, OVERFLOW);
    CHECK_FLOAT_PREDICATES(BFloat8, NEGATIVE, ZERO, DENORMAL, FINITE, INF, NAN, SNAN, QNAN, OVERFLOW);
    CHECK_FLOAT_PREDICATES(Float16, NEGATIVE, ZERO, DENORMAL, FINITE, INF, NAN, SNAN, QNAN);
    CHECK_FLOAT_PREDICATES(BFloat16, NEGATIVE, ZERO, DENORMAL, FINITE, INF, NAN, SNAN, QNAN);
    CHECK_FLOAT_PREDICATES(Float32, NEGATIVE, ZERO, DENORMAL, FINITE, INF, NAN, SNAN, QNAN);
    CHECK_FLOAT_PREDICATES(float, NEGATIVE, ZERO, DENORMAL, FINITE, INF, NAN, SNAN, QNAN);
    CHECK_FLOAT_PREDICATES(Float64, NEGATIVE, ZERO, DENORMAL, FINITE, INF, NAN, SNAN, QNAN);
    CHECK_FLOAT_PREDICATES(double, NEGATIVE, ZERO, DENORMAL, FINITE, INF, NAN, SNAN, QNAN);
    CHECK_FLOAT_PREDICATES(Float80);

    // old sign/exp/mantissa builder
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


    bfloat8 = new_random_bfloat8();
    hfloat8 = new_random_hfloat8();
    bfloat16 = new_random_bfloat16();
    float16 = new_random_float16();
    float32 = new_random_float32();
    f = new_random_float();
    float64 = new_random_float64();
    d = new_random_double();
    float80 = new_random_float80();

    bfloat8 = new_random(BFloat8);
    hfloat8 = new_random(HFloat8);
    bfloat16 = new_random(BFloat16);
    float16 = new_random(Float16);
    float32 = new_random(Float32);
    f = new_random(float);
    float64 = new_random(Float64);
    d = new_random(double);
    float80 = new_random(Float80);

    set_random(&bfloat8, 1);
    set_random(&hfloat8, 1);
    set_random(&bfloat16, 1);
    set_random(&float16, 1);
    set_random(&float32, 1);
    set_random(&f, 1);
    set_random(&float64, 1);
    set_random(&d, 1);
    set_random(&float80, 1);

    return 0;
}

#ifndef ASSERT_EQ
#define ASSERT_EQ(exp, act) do { if ((exp) != (act)) { return __LINE__; }} while (0)
#endif

int test_new_random_float_prototypes_c(void) {
    // compatibility with existing code: implicit compatibility random generator
    new_random_hfloat8();
    new_random_bfloat8();
    new_random_float16();
    new_random_bfloat16();
    new_random_float32();
    new_random_float();
    new_random_float64();
    new_random_double();
    new_random_float80();

    // obsolete random generation, fast path without bitfields
    // (explicit compatibility random generator)
    new_random_hfloat8(FP_GEN_COMPATIBILITY_GENERATOR);
    new_random_bfloat8(FP_GEN_COMPATIBILITY_GENERATOR);
    new_random_float16(FP_GEN_COMPATIBILITY_GENERATOR);
    new_random_bfloat16(FP_GEN_COMPATIBILITY_GENERATOR);
    new_random_float32(FP_GEN_COMPATIBILITY_GENERATOR);
    new_random_float(FP_GEN_COMPATIBILITY_GENERATOR);
    new_random_float64(FP_GEN_COMPATIBILITY_GENERATOR);
    new_random_double(FP_GEN_COMPATIBILITY_GENERATOR);
    new_random_float80(FP_GEN_COMPATIBILITY_GENERATOR);

    new_random_hfloat8(FP_GEN_FAST_MEMSET_RANDOM);
    new_random_bfloat8(FP_GEN_FAST_MEMSET_RANDOM);
    new_random_float16(FP_GEN_FAST_MEMSET_RANDOM);
    new_random_bfloat16(FP_GEN_FAST_MEMSET_RANDOM);
    new_random_float32(FP_GEN_FAST_MEMSET_RANDOM);
    new_random_float(FP_GEN_FAST_MEMSET_RANDOM);
    new_random_float64(FP_GEN_FAST_MEMSET_RANDOM);
    new_random_double(FP_GEN_FAST_MEMSET_RANDOM);
    new_random_float80(FP_GEN_FAST_MEMSET_RANDOM);

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

    static_assert(FP_GEN_RANDOM == 0, "FP_GEN_RANDOM must be zero");
    new_random_hfloat8(FP_GEN_RANDOM);
    new_random_bfloat8(FP_GEN_RANDOM);
    new_random_float16(FP_GEN_RANDOM);
    new_random_bfloat16(FP_GEN_RANDOM);
    new_random_float32(FP_GEN_RANDOM);
    new_random_float(FP_GEN_RANDOM);
    new_random_float64(FP_GEN_RANDOM);
    new_random_double(FP_GEN_RANDOM);
    new_random_float80(FP_GEN_RANDOM);

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

    #ifdef __cplusplus
    #define NUM_SAMPLES 11
    #else
    #define NUM_SAMPLES 33
    #endif

    HFloat8 hfloat8;
    HFloat8 hfloat8_arr[NUM_SAMPLES];
    HFloat8* hfloat8_ptr = &hfloat8_arr[0];

    // single value
    SET_RANDOM(hfloat8);
    SET_RANDOM(hfloat8, FP_GEN_POSITIVE);
    SET_RANDOM(hfloat8, 1.0, 4.0);
    SET_RANDOM(hfloat8, FP_GEN_FINITE, 1.0, 4.0);

    // pointer version: variable
    SET_RANDOM_PTR(hfloat8_ptr, NUM_SAMPLES);
    SET_RANDOM_PTR(hfloat8_ptr, 1, FP_GEN_POSITIVE);
    SET_RANDOM_PTR(hfloat8_ptr, 2, 1.0, 4.0);
    SET_RANDOM_PTR(hfloat8_ptr, 3, FP_GEN_FINITE, 1.0, 4.0);
    SET_RANDOM_PTR(hfloat8_ptr, NUM_SAMPLES, FP_GEN_FAST_ZERO);

    // pointer version: rvalue
    SET_RANDOM_PTR(&hfloat8, 1);
    SET_RANDOM_PTR(&hfloat8, 1, FP_GEN_POSITIVE);
    SET_RANDOM_PTR(&hfloat8, 1, 1.0, 4.0);
    SET_RANDOM_PTR(&hfloat8, 1, FP_GEN_FINITE, 1.0, 4.0);
    SET_RANDOM_PTR(&hfloat8, 1, FP_GEN_FAST_ZERO);

    // array version: variable only
    SET_RANDOM_ARR(hfloat8_arr);
    SET_RANDOM_ARR(hfloat8_arr, FP_GEN_POSITIVE);
    SET_RANDOM_ARR(hfloat8_arr, 1.0, 4.0);
    SET_RANDOM_ARR(hfloat8_arr, FP_GEN_FINITE, 1.0, 4.0);
    SET_RANDOM_ARR(hfloat8_arr, FP_GEN_FAST_ZERO);

    // array as a pointer (with nelems)
    SET_RANDOM_PTR(hfloat8_arr, NUM_SAMPLES - 1);
    SET_RANDOM_PTR(hfloat8_arr, 1, FP_GEN_POSITIVE);
    SET_RANDOM_PTR(hfloat8_arr, 2, 1.0, 4.0);
    SET_RANDOM_PTR(hfloat8_arr, 3, FP_GEN_FINITE, 1.0, 4.0);
    SET_RANDOM_PTR(hfloat8_arr, NUM_SAMPLES, FP_GEN_FAST_ZERO);

    return 0;
}
