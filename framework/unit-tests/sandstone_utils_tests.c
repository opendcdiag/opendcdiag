/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sandstone.h>
#include "fp_vectors/Floats.h"
#include "sandstone_data.h"

// Direct DATATYPEFORTYPE coverage.
int test_datatypefortype_c(void)
{
    _Bool b = 0;
    char c = 0;
    uint8_t u8 = 0;
    uint16_t u16 = 0;
    uint32_t u32 = 0;
    unsigned long ul = 0;
    unsigned long long ull = 0;
    __uint128_t u128 = 0;
    int8_t i8 = 0;
    int16_t i16 = 0;
    int32_t i32 = 0;
    long l = 0;
    long long ll = 0;
    __int128_t i128 = 0;
    HFloat8 hf8 = new_hfloat8(0, 0, 0);
    BFloat8 bf8 = new_bfloat8(0, 0, 0);
    BFloat16 bf16 = new_bfloat16(0, 0, 0);
    Float16 f16 = new_float16(0, 0, 0);
    float f32 = 0.0f;
    double f64 = 0.0;
    long double f80 = 0.0L;

    if (DATATYPEFORTYPE(b) != UInt8Data) return __LINE__;
    if (DATATYPEFORTYPE(c) != UInt8Data) return __LINE__;
    if (DATATYPEFORTYPE(u8) != UInt8Data) return __LINE__;
    if (DATATYPEFORTYPE(u16) != UInt16Data) return __LINE__;
    if (DATATYPEFORTYPE(u32) != UInt32Data) return __LINE__;
    if (DATATYPEFORTYPE(ul) != (sizeof(unsigned long) == sizeof(unsigned long long) ? UInt64Data : UInt32Data)) return __LINE__;
    if (DATATYPEFORTYPE(ull) != UInt64Data) return __LINE__;
    if (DATATYPEFORTYPE(u128) != UInt128Data) return __LINE__;
    if (DATATYPEFORTYPE(i8) != Int8Data) return __LINE__;
    if (DATATYPEFORTYPE(i16) != Int16Data) return __LINE__;
    if (DATATYPEFORTYPE(i32) != Int32Data) return __LINE__;
    if (DATATYPEFORTYPE(l) != (sizeof(long) == sizeof(long long) ? Int64Data : Int32Data)) return __LINE__;
    if (DATATYPEFORTYPE(ll) != Int64Data) return __LINE__;
    if (DATATYPEFORTYPE(i128) != Int128Data) return __LINE__;
    if (DATATYPEFORTYPE(hf8) != HFloat8Data) return __LINE__;
    if (DATATYPEFORTYPE(bf8) != BFloat8Data) return __LINE__;
    if (DATATYPEFORTYPE(bf16) != BFloat16Data) return __LINE__;
    if (DATATYPEFORTYPE(f16) != Float16Data) return __LINE__;
    if (DATATYPEFORTYPE(f32) != Float32Data) return __LINE__;
    if (DATATYPEFORTYPE(f64) != Float64Data) return __LINE__;
    if (DATATYPEFORTYPE(f80) != (sizeof(long double) == sizeof(double) ? Float64Data : Float80Data)) return __LINE__;

    return 0;
}

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
