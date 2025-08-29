/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <unistd.h>
#include <sandstone_data.h>
#include <sandstone_p.h>

/**
 * @brief C++ assertion validators
 */

static constexpr BFloat8 BFloat8_all_ones = new_bfloat8(~0, ~0, ~0);
static_assert(BFloat8_all_ones.sign == 1, "BFloat8: Incorrect sign");
static_assert(BFloat8_all_ones.exponent == BFLOAT8_NAN_EXPONENT, "BFloat8: Incorrect exponent");
static_assert(BFloat8_all_ones.mantissa == BFLOAT8_MANTISSA_MASK, "BFloat8: Incorrect mantissa");

static constexpr BFloat8 BFloat8_11_2 = new_bfloat8(0, 11, 2);
static_assert(BFloat8_11_2.sign == 0, "BFloat8: positive expected");
static_assert(BFloat8_11_2.exponent == 11, "BFloat8: Incorrect exponent");
static_assert(BFloat8_11_2.mantissa == 2, "BFloat8: Incorrect mantissa");

static constexpr BFloat8 BFloat8_qnan = new_bfloat8(0, BFLOAT8_NAN_EXPONENT, BFLOAT8_QNAN_AT_INPUT_MANTISSA);
static_assert(BFloat8_qnan.is_qnan(), "BFloat8: qNaN expected");

static constexpr BFloat8 BFloat8_snan = new_bfloat8(0, BFLOAT8_NAN_EXPONENT, BFLOAT8_SNAN_AT_INPUT_MANTISSA);
static_assert(BFloat8_snan.is_snan(), "BFloat8: sNaN expected");

static constexpr HFloat8 HFloat8_all_ones = new_hfloat8(~0, ~0, ~0);
static_assert(HFloat8_all_ones.sign == 1, "HFloat8: Incorrect sign");
static_assert(HFloat8_all_ones.exponent == HFLOAT8_INF_NAN_EXPONENT, "HFloat8: Incorrect exponent");
static_assert(HFloat8_all_ones.mantissa == HFLOAT8_MANTISSA_MASK, "HFloat8: Incorrect mantissa");
// cannot check the value in constexpr, the union is not initialized is constexpr context

static constexpr HFloat8 HFloat8_11_2 = new_hfloat8(0, 11, 2);
static_assert(HFloat8_11_2.sign == 0, "HFloat8: positive expected");
static_assert(HFloat8_11_2.exponent == 11, "HFloat8: Incorrect exponent");
static_assert(HFloat8_11_2.mantissa == 2, "HFloat8: Incorrect mantissa");

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
#define QUIET(t)  ((1uLL << (t ## _MANTISSA_BITS - 1)))

static_assert(sizeof(BFloat8) == 1, "BFloat8 structure is not of the correct size");
static_assert(BFLOAT8_NAN_EXPONENT == BFLOAT8_EXPONENT_MASK, "BFloat8::NaNs have all exponent bits set");
static_assert(BFLOAT8_INFINITY_EXPONENT == BFLOAT8_EXPONENT_MASK, "BFloat8::Inf has all exponent bits set");
static_assert(MASK(BFLOAT8_EXPONENT_BITS) == BFLOAT8_EXPONENT_MASK, "BFloat8 exponent mask has different size than the field");
static_assert(MASK(BFLOAT8_MANTISSA_BITS) == BFLOAT8_MANTISSA_MASK, "BFloat8 mantissa mask has different size than the field");
static_assert(BFLOAT8_SIGN_BITS + BFLOAT8_EXPONENT_BITS + BFLOAT8_MANTISSA_BITS == 8, "Bitfields sums to type size");

static_assert(sizeof(HFloat8) == 1, "HFloat8 structure is not of the correct size");
static_assert(HFLOAT8_INF_NAN_EXPONENT == HFLOAT8_EXPONENT_MASK, "HFloat8::NaNs have all exponent bits set");
static_assert(MASK(HFLOAT8_EXPONENT_BITS) == HFLOAT8_EXPONENT_MASK, "HFloat8 exponent mask has different size than the field");
static_assert(MASK(HFLOAT8_MANTISSA_BITS) == HFLOAT8_MANTISSA_MASK, "HFloat8 mantissa mask has different size than the field");
static_assert(HFLOAT8_SIGN_BITS + HFLOAT8_EXPONENT_BITS + HFLOAT8_MANTISSA_BITS == 8, "Bitfields sums to type size");

static_assert(sizeof(Float16) == 2, "Float16 structure is not of the correct size");
static_assert(FLOAT16_NAN_EXPONENT == FLOAT16_EXPONENT_MASK, "Float16::NaNs have all exponent bits set");
static_assert(FLOAT16_INFINITY_EXPONENT == FLOAT16_EXPONENT_MASK, "Float16::Inf has all exponent bits set");
static_assert(MASK(FLOAT16_EXPONENT_BITS) == FLOAT16_EXPONENT_MASK, "Float16 exponent mask has different size than the field");
static_assert(MASK(FLOAT16_MANTISSA_BITS) == FLOAT16_MANTISSA_MASK, "Float16 mantissa mask has different size than the field");
static_assert(QUIET(FLOAT16) == FLOAT16_MANTISSA_QUIET_NAN_MASK, "Quiet bit is MSB of the mantissa");
static_assert(FLOAT16_SIGN_BITS + FLOAT16_EXPONENT_BITS + FLOAT16_MANTISSA_BITS == 16, "Bitfields sums to type size");

static_assert(sizeof(BFloat16) == 2, "BFloat16 structure is not of the correct size");
static_assert(BFLOAT16_EXPONENT_MASK == FLOAT32_EXPONENT_MASK, "BFloat16 is truncated Float32 (MSB only)");
static_assert(BFLOAT16_MANTISSA_MASK == (FLOAT32_MANTISSA_MASK >> 16), "BFloat16 is truncated Float32 (MSB only)");
static_assert(BFLOAT16_NAN_EXPONENT == BFLOAT16_EXPONENT_MASK, "BFloat16::NaNs have all exponent bits set");
static_assert(BFLOAT16_INFINITY_EXPONENT == BFLOAT16_EXPONENT_MASK, "BFloat16::Inf has all exponent bits set");
static_assert(MASK(BFLOAT16_EXPONENT_BITS) == BFLOAT16_EXPONENT_MASK, "BFloat16 exponent mask has different size than the field");
static_assert(MASK(BFLOAT16_MANTISSA_BITS) == BFLOAT16_MANTISSA_MASK, "BFloat16 mantissa mask has different size than the field");
static_assert(QUIET(BFLOAT16) == BFLOAT16_MANTISSA_QUIET_NAN_MASK, "Quiet bit is MSB of the mantissa");
static_assert(BFLOAT16_SIGN_BITS + BFLOAT16_EXPONENT_BITS + BFLOAT16_MANTISSA_BITS == 16, "Bitfields sums to type size");

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

BFloat8 to_bfloat8_emulated(float f) {
    Float32 f32{ f };
    // "copy" NaNs (quiet and silent) and Inf to the output
    if (f32.exponent == FLOAT32_INFINITY_EXPONENT) {
        uint8_t m =
            f32.mantissa == 0 ? BFLOAT8_INF_AT_INPUT_MANTISSA :
            ((f32.mantissa & FLOAT32_MANTISSA_QUIET_NAN_MASK) == 0) ? BFLOAT8_SNAN_AT_INPUT_MANTISSA :
            BFLOAT8_QNAN_AT_INPUT_MANTISSA;
        return { (uint8_t) f32.sign, BFLOAT8_NAN_EXPONENT, m };
    }
    // big values are immediately reported as SATURATE/OVERFLOW, rounding is not checked
    int exp = ((int) f32.exponent) - FLOAT32_EXPONENT_BIAS + BFLOAT8_EXPONENT_BIAS;
    if (exp >= (int) BFLOAT8_NAN_EXPONENT) {
        return { (uint8_t) f32.sign, BFLOAT8_NAN_EXPONENT, BFLOAT8_OVERFLOW_MANTISSA };
    }
    // denormals and small values are unconditionally flushed to 0
    if (exp < -((int) BFLOAT8_MANTISSA_BITS)) {
        return { (uint8_t) f32.sign, BFLOAT8_DENORM_EXPONENT, 0 };
    }

    // "always normal" value is caught here, just restore "hidden" bit
    uint32_t mant = ((1u << FLOAT32_MANTISSA_BITS) | f32.mantissa);

    // "denormalize" very small values
    if (exp <= 0) {
        mant >>= (1 + (-exp));
        exp = BFLOAT8_DENORM_EXPONENT;
    }
    // do the rounding, just by adding half of last significant bit
    mant += (1u << (FLOAT32_MANTISSA_BITS - BFLOAT8_MANTISSA_BITS - 1));

    mant >>= (FLOAT32_MANTISSA_BITS - BFLOAT8_MANTISSA_BITS);
    // handle mantissa saturation
    if (mant == (1 << (BFLOAT8_MANTISSA_BITS + 1))) {
        mant >>= 1;
        exp++;
    }

    // discard hidden bit, it is not set for denormalized value. Rounding can
    // be a reason of exponent change in denormals!
    if (exp != 0) {
        mant ^= (1 << BFLOAT8_MANTISSA_BITS);
    } else if (mant >= (1 << BFLOAT8_MANTISSA_BITS)) {
        mant ^= (1 << BFLOAT8_MANTISSA_BITS);
        exp++;
    }
    assert(mant < (1 << BFLOAT8_MANTISSA_BITS));

    assert(exp >= 0);
    if (exp >= BFLOAT8_NAN_EXPONENT) {
        return { (uint8_t) f32.sign, BFLOAT8_NAN_EXPONENT, BFLOAT8_OVERFLOW_MANTISSA }; // overflow
    }
    return { (uint8_t) f32.sign, (uint8_t) exp, (uint8_t) mant };
}

float from_bfloat8_emulated(BFloat8 f) {
    Float32 f32 =
        f.is_zero() ? Float32{ f.sign, FLOAT32_DENORM_EXPONENT, 0 } :
        f.is_denormal() ?
            f.mantissa >= 2 ? Float32{ (uint8_t)f.sign, FLOAT32_EXPONENT_BIAS - BFLOAT8_EXPONENT_BIAS - BFLOAT8_MANTISSA_BITS + 2, ((uint32_t) f.mantissa) << (FLOAT32_MANTISSA_BITS - BFLOAT8_MANTISSA_BITS + 1)} :
            Float32{ f.sign, FLOAT32_EXPONENT_BIAS - BFLOAT8_EXPONENT_BIAS - BFLOAT8_MANTISSA_BITS + 1, ((uint32_t) f.mantissa) << (FLOAT32_MANTISSA_BITS - BFLOAT8_MANTISSA_BITS + 2) } :
        f.is_valid() ? Float32{ f.sign, f.exponent + FLOAT32_EXPONENT_BIAS - BFLOAT8_EXPONENT_BIAS, (uint32_t) f.mantissa << (FLOAT32_MANTISSA_BITS - BFLOAT8_MANTISSA_BITS) } :
        f.is_inf() || f.is_overflow() ? Float32{ f.sign, FLOAT32_INFINITY_EXPONENT, 0 } :
        f.is_qnan() ? Float32{ f.sign, FLOAT32_NAN_EXPONENT, FLOAT32_MANTISSA_QUIET_NAN_MASK | 1 } :
        Float32{ f.sign, FLOAT32_NAN_EXPONENT, 1 };
    return f32.as_float;
}

HFloat8 to_hfloat8_emulated(float f) {
    Float32 f32{ f };
    // NaN/Inf always reported as NAN_INF
    if (f32.exponent == FLOAT32_INFINITY_EXPONENT) {
        return { (uint8_t) f32.sign, HFLOAT8_NAN_INF_VALUE };
    }
    // big values are immediately reported as SATURATE/OVERFLOW
    int exp = ((int) f32.exponent) - FLOAT32_EXPONENT_BIAS + HFLOAT8_EXPONENT_BIAS;
    if (exp > ((int) HFLOAT8_INF_NAN_EXPONENT)) {
        return { (uint8_t) f32.sign, HFLOAT8_SATURATED_OVERFLOW_VALUE };
    }
    // denormals and small values are unconditionally flushed to 0
    if (exp < -((int) HFLOAT8_MANTISSA_BITS)) {
        return { (uint8_t) f32.sign, HFLOAT8_DENORM_EXPONENT, 0 };
    }

    // "always normal" value is caught here, just restore "hidden" bit
    uint32_t mant = ((1u << FLOAT32_MANTISSA_BITS) | f32.mantissa);

    // "denormalize" very small values
    if (exp <= 0) {
        mant >>= (1 + (-exp));
        exp = HFLOAT8_DENORM_EXPONENT;
    }
    // do the rounding, just by adding half of last significant bit
    mant += (1u << (FLOAT32_MANTISSA_BITS - HFLOAT8_MANTISSA_BITS - 1));

    mant >>= (FLOAT32_MANTISSA_BITS - HFLOAT8_MANTISSA_BITS);
    // handle mantissa saturation
    if (mant == (1 << (HFLOAT8_MANTISSA_BITS + 1))) {
        mant >>= 1;
        exp++;
    }

    // discard hidden bit, it is not set for denormalized value. Rounding can
    // be a reason of exponent change in denormals!
    if (exp != 0) {
        mant ^= (1 << HFLOAT8_MANTISSA_BITS);
    } else if (mant >= (1 << HFLOAT8_MANTISSA_BITS)) {
        mant ^= (1 << HFLOAT8_MANTISSA_BITS);
        exp++;
    }
    assert(mant < (1 << HFLOAT8_MANTISSA_BITS));

    assert(exp >= 0);
    if ((exp > HFLOAT8_INF_NAN_EXPONENT) || ((exp == HFLOAT8_INF_NAN_EXPONENT) && (mant >= 0b110))) {
        return { (uint8_t) f32.sign, HFLOAT8_SATURATED_OVERFLOW_VALUE }; // overflow
    }
    return { (uint8_t) f32.sign, (uint8_t) exp, (uint8_t) mant };
}

float from_hfloat8_emulated(HFloat8 f) {
    Float32 f32 =
        f.is_zero() ? Float32{ f.sign, FLOAT32_DENORM_EXPONENT, 0 } :
        f.is_denormal() ?
            f.mantissa >= 4 ? Float32{ f.sign, FLOAT32_EXPONENT_BIAS - HFLOAT8_EXPONENT_BIAS - HFLOAT8_MANTISSA_BITS + 3, ((uint32_t) f.mantissa) << (FLOAT32_MANTISSA_BITS - HFLOAT8_MANTISSA_BITS + 1) } :
            f.mantissa >= 2 ? Float32{ f.sign, FLOAT32_EXPONENT_BIAS - HFLOAT8_EXPONENT_BIAS - HFLOAT8_MANTISSA_BITS + 2, ((uint32_t) f.mantissa) << (FLOAT32_MANTISSA_BITS - HFLOAT8_MANTISSA_BITS + 2)} :
            Float32{ f.sign, FLOAT32_EXPONENT_BIAS - HFLOAT8_EXPONENT_BIAS - HFLOAT8_MANTISSA_BITS + 1, ((uint32_t) f.mantissa) << (FLOAT32_MANTISSA_BITS - HFLOAT8_MANTISSA_BITS + 3) } :
        f.is_valid() ? Float32{ f.sign, f.exponent + FLOAT32_EXPONENT_BIAS - HFLOAT8_EXPONENT_BIAS, (uint32_t) f.mantissa << (FLOAT32_MANTISSA_BITS - HFLOAT8_MANTISSA_BITS) } :
        Float32{ f.sign, FLOAT32_INFINITY_EXPONENT, 0 };
    return f32.as_float;
}

Float16 new_random_float16()
{
    Float16 f;

    f.sign = random32();
    f.exponent = random32();
    f.mantissa = set_random_bits(random32() % (FLOAT16_MANTISSA_BITS + 1), FLOAT16_MANTISSA_BITS);
    return f;
}

BFloat16 new_random_bfloat16()
{
    BFloat16 f;

    f.sign = random32();
    f.exponent = random32();
    f.mantissa = set_random_bits(random32() % (BFLOAT16_MANTISSA_BITS + 1), BFLOAT16_MANTISSA_BITS);
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
