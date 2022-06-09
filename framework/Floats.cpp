/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <unistd.h>
#include <sandstone_data.h>
#include <sandstone.h>

/**
 * @brief C++ assertion validators
 *
 * Static assertions here only. No code generated from this file.
 */

static constexpr Float16 Float16_all_ones = new_float16(~0, ~0, ~0);
static_assert(Float16_all_ones.sign == 1, "Float16: Incorrect sign");
static_assert(Float16_all_ones.exponent == FLOAT16_NAN_EXPONENT, "Float16: Incorrect exponent");
static_assert(Float16_all_ones.mantissa == FLOAT16_MANTISSA_MASK, "Float16: Incorrect mantissa");

static constexpr Float16 Float16_qnan = new_float16(0, FLOAT16_NAN_EXPONENT, FLOAT16_MANTISSA_QUIET_NAN_MASK);
static_assert(Float16_qnan.is_qnan(), "Float16: qNaN expected");
static_assert(Float16_qnan.get_nan_payload() == 0, "Float16: Incorrect NaN payload");

static constexpr Float16 Float16_11_22 = new_float16(0, 11, 22);
static_assert(Float16_11_22.sign == 0, "Float16: positive expected");
static_assert(Float16_11_22.exponent == 11, "Float16: Incorrect exponent");
static_assert(Float16_11_22.mantissa == 22, "Float16: Incorrect mantissa");


static constexpr BFloat16 BFloat16_all_ones = new_bfloat16(~0, ~0, ~0);
static_assert(BFloat16_all_ones.sign == 1, "BFloat16: Incorrect sign");
static_assert(BFloat16_all_ones.exponent == BFLOAT16_NAN_EXPONENT, "BFloat16: Incorrect exponent");
static_assert(BFloat16_all_ones.mantissa == BFLOAT16_MANTISSA_MASK, "BFloat16: Incorrect mantissa");

static constexpr BFloat16 BFloat16_qnan = new_bfloat16(0, BFLOAT16_NAN_EXPONENT, BFLOAT16_MANTISSA_QUIET_NAN_MASK);
static_assert(BFloat16_qnan.is_qnan(), "BFloat16: qNaN expected");
static_assert(BFloat16_qnan.get_nan_payload() == 0, "BFloat16: Incorrect NaN payload");

static constexpr BFloat16 BFloat16_11_22 = new_bfloat16(0, 11, 22);
static_assert(BFloat16_11_22.sign == 0, "BFloat16: positive expected");
static_assert(BFloat16_11_22.exponent == 11, "BFloat16: Incorrect exponent");
static_assert(BFloat16_11_22.mantissa == 22, "BFloat16: Incorrect mantissa");


static constexpr Float32 Float32_all_ones = new_float32(~0, ~0, ~0);
static_assert(Float32_all_ones.sign == 1, "Float32: Incorrect sign");
static_assert(Float32_all_ones.exponent == FLOAT32_NAN_EXPONENT, "Float32: Incorrect exponent");
static_assert(Float32_all_ones.mantissa == FLOAT32_MANTISSA_MASK, "Float32: Incorrect mantissa");

static constexpr Float32 Float32_11_22 = new_float32(0, 11, 22);
static_assert(Float32_11_22.sign == 0, "Float32: positive expected");
static_assert(Float32_11_22.exponent == 11, "Float32: Incorrect exponent");
static_assert(Float32_11_22.mantissa == 22, "Float32: Incorrect mantissa");


static constexpr Float64 Float64_all_ones = new_float64(~0, ~0, ~0);
static_assert(Float64_all_ones.sign == 1, "Float64: Incorrect sign");
static_assert(Float64_all_ones.exponent == FLOAT64_NAN_EXPONENT, "Float64: Incorrect exponent");
static_assert(Float64_all_ones.mantissa == FLOAT64_MANTISSA_MASK, "Float64: Incorrect mantissa");

static constexpr Float64 Float64_11_22 = new_float64(0, 11, 22);
static_assert(Float64_11_22.sign == 0, "Float64: positive expected");
static_assert(Float64_11_22.exponent == 11, "Float64: Incorrect exponent");
static_assert(Float64_11_22.mantissa == 22, "Float64: Incorrect mantissa");


static constexpr Float80 Float80_all_ones = new_float80(~0, ~0, ~0, ~0);
static_assert(Float80_all_ones.sign == 1, "Float80: Incorrect sign");
static_assert(Float80_all_ones.exponent == FLOAT80_NAN_EXPONENT, "Float80: Incorrect exponent");
static_assert(Float80_all_ones.jbit == 1, "Float80: Incorrect j-bit");
static_assert(Float80_all_ones.mantissa == FLOAT80_MANTISSA_MASK, "Float80: Incorrect mantissa");

static constexpr Float80 Float80_11_22 = new_float80(0, 11, 33, 22);
static_assert(Float80_11_22.sign == 0, "Float80: positive expected");
static_assert(Float80_11_22.exponent == 11, "Float80: Incorrect exponent");
static_assert(Float80_11_22.jbit == 1, "Float80: Incorrect j-bit");
static_assert(Float80_11_22.mantissa == 22, "Float80: Incorrect mantissa");

/**
 * @brief Sanity checks
 *
 * Corresponding fields sizes should match masks/etc
 *
 * @{
 */
#define MASK(n)  (((n) == 64) ? 0xffffffffffffffffuLL : ((1uLL << (n)) - 1))
#define QUIET(t)  ((1uLL << (t ## _MANTISSA_BITS - 1)))

static_assert(BFLOAT16_EXPONENT_MASK == FLOAT32_EXPONENT_MASK, "BFloat16 is truncated Float32 (MSB only)");
static_assert(BFLOAT16_MANTISSA_MASK == (FLOAT32_MANTISSA_MASK >> 16), "BFloat16 is truncated Float32 (MSB only)");

static_assert(sizeof(Float16) == 2, "Float16 structure is not of the correct size");
static_assert(FLOAT16_NAN_EXPONENT == FLOAT16_EXPONENT_MASK, "Float16::NaNs have all exponent bits set");
static_assert(FLOAT16_INFINITY_EXPONENT == FLOAT16_EXPONENT_MASK, "Float16::Inf has all exponent bits set");
static_assert(MASK(FP16_EXPONENT_BITS) == FLOAT16_EXPONENT_MASK, "Float16 exponent mask has different size than the field");
static_assert(MASK(FP16_MANTISSA_BITS) == FLOAT16_MANTISSA_MASK, "Float16 mantissa mask has different size than the field");
static_assert(QUIET(FP16) == FLOAT16_MANTISSA_QUIET_NAN_MASK, "Quiet bit is MSB of the mantissa");
static_assert(FP16_SIGN_BITS + FP16_EXPONENT_BITS + FP16_MANTISSA_BITS == 16, "Bitfields sums to type size");

static_assert(sizeof(BFloat16) == 2, "BFloat16 structure is not of the correct size");
static_assert(BFLOAT16_NAN_EXPONENT == BFLOAT16_EXPONENT_MASK, "BFloat16::NaNs have all exponent bits set");
static_assert(BFLOAT16_INFINITY_EXPONENT == BFLOAT16_EXPONENT_MASK, "BFloat16::Inf has all exponent bits set");
static_assert(MASK(BFLT16_EXPONENT_BITS) == BFLOAT16_EXPONENT_MASK, "BFloat16 exponent mask has different size than the field");
static_assert(MASK(BFLT16_MANTISSA_BITS) == BFLOAT16_MANTISSA_MASK, "BFloat16 mantissa mask has different size than the field");
static_assert(QUIET(BFLT16) == BFLOAT16_MANTISSA_QUIET_NAN_MASK, "Quiet bit is MSB of the mantissa");
static_assert(BFLT16_SIGN_BITS + BFLT16_EXPONENT_BITS + BFLT16_MANTISSA_BITS == 16, "Bitfields sums to type size");

static_assert(sizeof(Float32) == sizeof(float), "Float32 structure is not of the correct size");
static_assert(FLOAT32_NAN_EXPONENT == FLOAT32_EXPONENT_MASK, "Float32::NaNs have all exponent bits set");
static_assert(FLOAT32_INFINITY_EXPONENT == FLOAT32_EXPONENT_MASK, "Float32::Inf has all exponent bits set");
static_assert(MASK(FLOAT32_EXPONENT_BITS) == FLOAT32_EXPONENT_MASK, "Float32 exponent mask has different size than the field");
static_assert(MASK(FLOAT32_MANTISSA_BITS) == FLOAT32_MANTISSA_MASK, "Float32 mantissa mask has different size than the field");
static_assert(QUIET(FLOAT32) == FLOAT32_MANTISSA_QUIET_NAN_MASK, "Quiet bit is MSB of the mantissa");
static_assert(FLOAT32_SIGN_BITS + FLOAT32_EXPONENT_BITS + FLOAT32_MANTISSA_BITS == 32, "Bitfields sums to type size");

static_assert(sizeof(Float64) == sizeof(double), "Float64 structure is not of the correct size");
static_assert(FLOAT64_NAN_EXPONENT == FLOAT64_EXPONENT_MASK, "Float64::NaNs have all exponent bits set");
static_assert(FLOAT64_INFINITY_EXPONENT == FLOAT64_EXPONENT_MASK, "Float64::Inf has all exponent bits set");
static_assert(MASK(FLOAT64_EXPONENT_BITS) == FLOAT64_EXPONENT_MASK, "Float64 exponent mask has different size than the field");
static_assert(MASK(FLOAT64_MANTISSA_BITS) == FLOAT64_MANTISSA_MASK, "Float64 mantissa mask has different size than the field");
static_assert(QUIET(FLOAT64) == FLOAT64_MANTISSA_QUIET_NAN_MASK, "Quiet bit is MSB of the mantissa");
static_assert(FLOAT64_SIGN_BITS + FLOAT64_EXPONENT_BITS + FLOAT64_MANTISSA_BITS == 64, "Bitfields sums to type size");

static_assert(sizeof(double) < sizeof(long double), "Compiler does not support long double");
static_assert(sizeof(Float80) == sizeof(long double), "Float80 structure is not of the correct size");
static_assert(FLOAT80_NAN_EXPONENT == FLOAT80_EXPONENT_MASK, "All Float80::NaNs have all exponent bits set");
static_assert(FLOAT80_INFINITY_EXPONENT == FLOAT80_EXPONENT_MASK, "Float80::Inf has all exponent bits set");
static_assert(MASK(FLOAT80_EXPONENT_BITS) == FLOAT80_EXPONENT_MASK, "Float80 exponent mask has different size than the field");
static_assert(MASK(FLOAT80_MANTISSA_BITS) == FLOAT80_MANTISSA_MASK, "Float80 mask has different size than mantissa+jbit");
static_assert(QUIET(FLOAT80) == FLOAT80_MANTISSA_QUIET_NAN_MASK, "Quiet bit is MSB of the mantissa");
static_assert(FLOAT80_SIGN_BITS + FLOAT80_EXPONENT_BITS + FLOAT80_JBIT_BITS + FLOAT80_MANTISSA_BITS == 80, "Bitfields sums to type size");

/** @} */

/**
 * @brief C function definitions
 * @{
 */
extern "C" {

Float16 new_random_float16()
{
    Float16 f;
    f.sign = random32();
    f.exponent = random32();
    f.mantissa = set_random_bits(random32() % (FP16_MANTISSA_BITS + 1), FP16_MANTISSA_BITS);

    return f;
}

BFloat16 new_random_bfloat16()
{
    BFloat16 f;
    f.sign = random32();
    f.exponent = random32();
    f.mantissa = set_random_bits(random32() % (BFLT16_MANTISSA_BITS + 1), BFLT16_MANTISSA_BITS);

    return f;
}

Float32 new_random_float32()
{
    Float32 f;
    f.sign = random32();
    f.exponent = random32();
    f.mantissa = set_random_bits(random32() % (FLOAT32_MANTISSA_BITS + 1), FLOAT32_MANTISSA_BITS);

    return f;
}

Float64 new_random_float64()
{
    Float64 f;
    f.sign = random32();
    f.exponent = random32();
    f.mantissa = set_random_bits(random32() % (FLOAT64_MANTISSA_BITS + 1), FLOAT64_MANTISSA_BITS);

    return f;
}

Float80 new_random_float80()
{
    Float80 f;
    f.sign = random32();
    f.exponent = random32();
    f.jbit = 1;
    f.mantissa = set_random_bits(random32() % (FLOAT80_MANTISSA_BITS + 1), FLOAT80_MANTISSA_BITS);

    return f;
}

}
/** @} */
