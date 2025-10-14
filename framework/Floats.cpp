/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sandstone_data.h>
#include <sandstone_p.h>

#include <fp_vectors/static_vectors.h>

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
 * @brief C conversion definitions
 * @{
 */
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
        f.is_finite() ? Float32{ f.sign, f.exponent + FLOAT32_EXPONENT_BIAS - BFLOAT8_EXPONENT_BIAS, (uint32_t) f.mantissa << (FLOAT32_MANTISSA_BITS - BFLOAT8_MANTISSA_BITS) } :
        f.is_inf() || f.is_overflow() ? Float32{ f.sign, FLOAT32_INFINITY_EXPONENT, 0 } :
        f.is_qnan() ? Float32{ f.sign, FLOAT32_NAN_EXPONENT, FLOAT32_MANTISSA_QUIET_NAN_MASK | 1 } :
        Float32{ f.sign, FLOAT32_NAN_EXPONENT, 1 };
    return f32.as_float;
}

HFloat8 to_hfloat8_emulated(float f) {
    Float32 f32{ f };
    // Inf/NaN always reported as INF_NAN
    if (f32.exponent == FLOAT32_INFINITY_EXPONENT) {
        return { (uint8_t) f32.sign, HFLOAT8_INF_NAN_VALUE };
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
        f.is_finite() ? Float32{ f.sign, f.exponent + FLOAT32_EXPONENT_BIAS - HFLOAT8_EXPONENT_BIAS, (uint32_t) f.mantissa << (FLOAT32_MANTISSA_BITS - HFLOAT8_MANTISSA_BITS) } :
        Float32{ f.sign, FLOAT32_INFINITY_EXPONENT, 0 };
    return f32.as_float;
}

/** @} */

#if defined(OBSOLETE_RANDOM_GENERATORS)
// TODO remove when new approach is accepted
/**
 * @brief C dummy random float generators
 * @{
 */
HFloat8 new_random_hfloat8()
{
    HFloat8 f;

    // keep the pattern of random bits from other new_random_xxx() functions
    f.sign = random32();
    f.exponent = random32();
    f.mantissa = set_random_bits(random32() % (HFLOAT8_MANTISSA_BITS + 1), HFLOAT8_MANTISSA_BITS);
    return f;
}

BFloat8 new_random_bfloat8()
{
    BFloat8 f;

    // keep the pattern of random bits from other new_random_xxx() functions
    f.sign = random32();
    f.exponent = random32();
    f.mantissa = set_random_bits(random32() % (BFLOAT8_MANTISSA_BITS + 1), BFLOAT8_MANTISSA_BITS);
    return f;
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

/** @} */

#elif !defined(OBSOLETE_RANDOM_GENERATORS)

namespace {

static constexpr int BITS_FROM_RANDOM = 31;

template<typename I>
constexpr I get_mask(int bits) {
    if (bits <= 0) {
        return I(0);
    }
    if (bits >= sizeof(I) * 8) {
        return I(~0);
    }
    return (static_cast<I>(1) << bits) - 1;
}

template<typename I>
I get_random_bits(int bits) {
    static std::mutex mutex{};
    static uint32_t random_bits_value = 0;
    static int random_bits_available = 0;


    if ((bits <= 0) || (bits > sizeof(I) * 8)){
        assert((bits > 0) && "Requested number of bits must be positive");
        assert((bits <= sizeof(I) * 8) && "Requested number of bits must fit the type");
        return I{ 0 };
    }

    std::lock_guard<std::mutex> lock(mutex);
    I val = 0;
    while (bits != 0) {
        if ((random_bits_available == 0) || (random_bits_available >= BITS_FROM_RANDOM)) {
            random_bits_value = random();
            random_bits_available = BITS_FROM_RANDOM;
        }
        int b = bits;
        if (b > random_bits_available) {
            b = random_bits_available;
        }
        // shift by 8*sizeof(T) is undefined behavior! Number of available bits
        // might apply to all bits, while very first shift is never required
        if (val) {
            val <<= b;
        }
        val |= I(random_bits_value & get_mask<uint32_t>(b));
        random_bits_available -= b;
        random_bits_value >>= b;
        bits -= b;
    }
    return val;
}

template<typename I>
I get_random_value(I range) {
    static_assert(NotImplementedFor<I>::value, "get_random_value not implemented for this type");
    return I{0};
}

template<> uint32_t get_random_value(uint32_t range) {
    static std::mutex mutex{};
    static uint32_t random_val_value = 0;
    static uint32_t random_val_available = 0;

    if (range <= 1) {
        return 0;
    }
    assert((range < (1ULL << BITS_FROM_RANDOM)) && "Large values are not supported");

    std::lock_guard<std::mutex> lock(mutex);
    if (random_val_available <= range) {
        random_val_value = random32();
        random_val_available = (1ULL << BITS_FROM_RANDOM);
    }
    uint32_t val = random_val_value % range;
    random_val_available /= range;
    random_val_value /= range;
    return val;
}

template<typename F>
F get_predefined_float(int& selected_predefined) {
    assert(false && "Predefined values not available for the type");
    return {};
}
template<> Float16 get_predefined_float(int& selected_predefined) {
    if (selected_predefined < 0) {
        selected_predefined = get_random_value<uint32_t>(num_float16_vectors());
    }
    return get_float16_vector(selected_predefined);
}
template<> Float32 get_predefined_float(int& selected_predefined) {
    if (selected_predefined < 0) {
        selected_predefined = get_random_value<uint32_t>(num_float32_vectors());
    }
    return get_float32_vector(selected_predefined);
}
template<> Float64 get_predefined_float(int& selected_predefined) {
    if (selected_predefined < 0) {
        selected_predefined = get_random_value<uint32_t>(num_float64_vectors());
    }
    return get_float64_vector(selected_predefined);
}
template<> Float80 get_predefined_float(int& selected_predefined) {
    if (selected_predefined < 0) {
        selected_predefined = get_random_value<uint32_t>(num_float80_vectors());
    }
    return get_float80_vector(selected_predefined);
}

static_assert(HFLOAT8_DENORM_EXPONENT == 0, "Denormal exponent must be zero");
static_assert(BFLOAT8_DENORM_EXPONENT == 0, "Denormal exponent must be zero");
static_assert(FLOAT16_DENORM_EXPONENT == 0, "Denormal exponent must be zero");
static_assert(BFLOAT16_DENORM_EXPONENT == 0, "Denormal exponent must be zero");
static_assert(FLOAT32_DENORM_EXPONENT == 0, "Denormal exponent must be zero");
static_assert(FLOAT64_DENORM_EXPONENT == 0, "Denormal exponent must be zero");
static_assert(FLOAT80_DENORM_EXPONENT == 0, "Denormal exponent must be zero");

template<typename F>
F force_denormal(F& f) {
    f.exponent = 0;
    // prevent against 0 by setting any bit
    if (f.mantissa == 0) {
        f.mantissa |= static_cast<typename F::base_type>(1ULL << get_random_value<uint32_t>(F::mantissa_bits()));
    }
    return f;
}
template<>
Float80 force_denormal(Float80& f) {
    f.exponent = FLOAT80_DENORM_EXPONENT;
    f.jbit = 0;
    // prevent against 0 by setting any bit
    if (f.mantissa == 0) {
        f.mantissa |= static_cast<typename Float80::base_type>(1ULL << get_random_value<uint32_t>(Float80::mantissa_bits()));
    }
    return f;
}

static_assert(get_mask<typename BFloat8::base_type>(BFloat8::exponent_bits())   == BFLOAT8_INFINITY_EXPONENT);
static_assert(get_mask<typename Float16::base_type>(Float16::exponent_bits())   == FLOAT16_INFINITY_EXPONENT);
static_assert(get_mask<typename BFloat16::base_type>(BFloat16::exponent_bits()) == BFLOAT16_INFINITY_EXPONENT);
static_assert(get_mask<typename Float32::base_type>(Float32::exponent_bits())   == FLOAT32_INFINITY_EXPONENT);
static_assert(get_mask<typename Float64::base_type>(Float64::exponent_bits())   == FLOAT64_INFINITY_EXPONENT);
static_assert(get_mask<typename Float80::base_type>(Float80::exponent_bits())   == FLOAT80_INFINITY_EXPONENT);

template<typename F>
F force_infinity(F& f) {
    f.exponent = get_mask<typename F::base_type>(F::exponent_bits());
    f.mantissa = 0;
    return f;
}
template<>
HFloat8 force_infinity(HFloat8& f) {
    f.value = HFLOAT8_INF_NAN_VALUE;
    return f;
}

static_assert(get_mask<typename HFloat8::base_type>(HFloat8::exponent_bits())   == HFLOAT8_INF_NAN_EXPONENT);
static_assert(get_mask<typename BFloat8::base_type>(BFloat8::exponent_bits())   == BFLOAT8_NAN_EXPONENT);
static_assert(get_mask<typename Float16::base_type>(Float16::exponent_bits())   == FLOAT16_NAN_EXPONENT);
static_assert(get_mask<typename BFloat16::base_type>(BFloat16::exponent_bits()) == BFLOAT16_NAN_EXPONENT);
static_assert(get_mask<typename Float32::base_type>(Float32::exponent_bits())   == FLOAT32_NAN_EXPONENT);
static_assert(get_mask<typename Float64::base_type>(Float64::exponent_bits())   == FLOAT64_NAN_EXPONENT);
static_assert(get_mask<typename Float80::base_type>(Float80::exponent_bits())   == FLOAT80_NAN_EXPONENT);

static_assert(1ULL << (Float16::mantissa_bits() - 1)  == FLOAT16_MANTISSA_QUIET_NAN_MASK);
static_assert(1ULL << (BFloat16::mantissa_bits() - 1) == BFLOAT16_MANTISSA_QUIET_NAN_MASK);
static_assert(1ULL << (Float32::mantissa_bits() - 1)  == FLOAT32_MANTISSA_QUIET_NAN_MASK);
static_assert(1ULL << (Float64::mantissa_bits() - 1)  == FLOAT64_MANTISSA_QUIET_NAN_MASK);
static_assert(1ULL << (Float80::mantissa_bits() - 1)  == FLOAT80_MANTISSA_QUIET_NAN_MASK);

template<typename F>
F force_nan(F& f) {
    f.exponent = get_mask<typename F::base_type>(F::exponent_bits());
    if (f.mantissa == 0) {
        // prevent against 0 by setting any bit, including most significant one (quiet)
        uint32_t bit = get_random_value<uint32_t>(F::mantissa_bits());
        f.mantissa = static_cast<F::base_type>(1ULL << bit);
    }
    return f;
}
template<typename F>
F force_nan(F& f, bool quiet) {
    f.exponent = get_mask<typename F::base_type>(F::exponent_bits());
    if (quiet) {
        f.mantissa |= static_cast<F::base_type>(1ULL << (F::mantissa_bits() - 1));
    } else if (f.mantissa == 0) {
        // prevent against 0 by setting any bit, excluding most significant one (quiet bit)
        uint32_t bit = get_random_value<uint32_t>(F::mantissa_bits() - 1);
        f.mantissa = static_cast<F::base_type>(1ULL << bit);
    } else {
        // make sure quiet bit is cleared
        f.mantissa &= static_cast<F::base_type>(~(1ULL << (F::mantissa_bits() - 1)));
    }
    return f;
}
template<>
HFloat8 force_nan(HFloat8& f, bool quiet) {
    // HFloat8 has only Inf
    assert(false && "HFloat8 with S/Q NaN values");
    return f;
}
template<>
HFloat8 force_nan(HFloat8& f) {
    assert(false && "HFloat8 with NaN values");
    return f;
}
template<>
BFloat8 force_nan(BFloat8& f, bool quiet) {
    f.exponent = BFLOAT8_NAN_EXPONENT;
    f.mantissa = quiet ? BFLOAT8_QNAN_AT_INPUT_MANTISSA : BFLOAT8_SNAN_AT_INPUT_MANTISSA;
    return f;
}
template<>
BFloat8 force_nan(BFloat8& f) {
    // either sNaN or qNaN, separate non-zero payloads
    return force_nan(f, static_cast<bool>(get_random_bits<uint32_t>(1)));
}

template<typename F>
F force_overflow(F& f) {
    assert(false && "Specific overflow value for the type");
    return f;
}
template<>
HFloat8 force_overflow(HFloat8& f) {
    f.value = HFLOAT8_SATURATED_OVERFLOW_VALUE;
    return f;
}
template<>
BFloat8 force_overflow(BFloat8& f) {
    f.exponent = BFLOAT8_NAN_EXPONENT;
    f.mantissa = BFLOAT8_OVERFLOW_MANTISSA;
    return f;
}

template<typename F>
constexpr uint32_t get_exponent_bias() {
    return get_mask<typename F::base_type>(F::exponent_bits() - 1);
}

static_assert(get_exponent_bias<HFloat8>()  == HFLOAT8_EXPONENT_BIAS);
static_assert(get_exponent_bias<BFloat8>()  == BFLOAT8_EXPONENT_BIAS);
static_assert(get_exponent_bias<Float16>()  == FLOAT16_EXPONENT_BIAS);
static_assert(get_exponent_bias<BFloat16>() == BFLOAT16_EXPONENT_BIAS);
static_assert(get_exponent_bias<Float32>()  == FLOAT32_EXPONENT_BIAS);
static_assert(get_exponent_bias<Float64>()  == FLOAT64_EXPONENT_BIAS);
static_assert(get_exponent_bias<Float80>()  == FLOAT80_EXPONENT_BIAS);

template<typename F>
void fix_bits(F&) {
}
template<>
void fix_bits(Float80& f) {
    f.jbit = (f.exponent == 0) ? 0 : 1;
}

// verify that the default flags are zero: RNG optimized random values in all fields
static_assert(FP_GEN_RANDOM == 0, "FP_GEN_RANDOM is expected to be a default and equal 0");

template<typename F>
inline F single_random(uint32_t flags) {
    // special cases: compatibility generator and static vector with percentage selector
    using BaseType = F::base_type;
    switch (flags) {
        case FP_GEN_FAST_ZERO:
            return F{
                /* .sign */     static_cast<BaseType>(0),
                /* .exponent */ static_cast<BaseType>(0),
                /* .mantissa */ static_cast<BaseType>(0)
            };
        case FP_GEN_COMPATIBILITY_GENERATOR:
            return F{
                /* .sign */     static_cast<BaseType>(random32()),
                /* .exponent */ static_cast<BaseType>(random32()),
                /* .mantissa */ static_cast<BaseType>(set_random_bits(random32() % (F::mantissa_bits() + 1), F::mantissa_bits()))
            };
    }

    int selected_predefined = -1;
    if (flags & FP_GEN_PCT_VEC_SELECTOR) {
        // make sure if low-significance bits are used for percentage
        static constexpr uint32_t ANY_PCT1 = 90;
        static_assert((ANY_PCT1 & FP_GEN_PCT_VEC_SELECTOR_VAL_MASK) == ANY_PCT1, "Invalid percentage mask");
        static constexpr uint32_t ANY_PCT2 = 45;
        static_assert((ANY_PCT2 & FP_GEN_PCT_VEC_SELECTOR_VAL_MASK) == ANY_PCT2, "Invalid percentage mask");

        // percentage must be in the range 1..100 to have effect
        assert(((flags & FP_GEN_PCT_VEC_SELECTOR_VAL_MASK) <= 100) && "Invalid percentage for static_vector selector");
        if (((flags & FP_GEN_PCT_VEC_SELECTOR_VAL_MASK) != 0) &&
            (get_random_value<uint32_t>(100) < (flags & FP_GEN_PCT_VEC_SELECTOR_VAL_MASK)))
        {
            return get_predefined_float<F>(selected_predefined);
        }
    }

    // validate generation flags, do not check PCT selector bits
    assert(({
            constexpr uint32_t handled =
                FP_GEN_RANDOM_FLAGS_MANTISSA_MASK | FP_GEN_RANDOM_FLAGS_EXPONENT_MASK | FP_GEN_RANDOM_FLAGS_SIGN_MASK |
                FP_GEN_RANDOM_FLAGS_FORCE_FINITE | FP_GEN_RANDOM_FLAGS_NO_SUBNORMALS;
            static_assert((handled & (FP_GEN_PCT_VEC_SELECTOR | FP_GEN_PCT_VEC_SELECTOR_VAL_MASK)) == 0,
                "PCT shares the same bits as other flags");
            uint32_t ff = flags;
            if (ff & FP_GEN_PCT_VEC_SELECTOR) {
                ff = ff & (~(FP_GEN_PCT_VEC_SELECTOR | FP_GEN_PCT_VEC_SELECTOR_VAL_MASK));
            }
            ((ff & (~handled)) == 0);
        }) && "Unknown flags in random float generator");

    F f;
    switch (flags & FP_GEN_RANDOM_FLAGS_SIGN_MASK) {
        case FP_GEN_RANDOM_FLAGS_SIGN_RANDOM:
            f.sign = random();
            break;
        case FP_GEN_RANDOM_FLAGS_SIGN_BITS:
            static_assert(FP_GEN_RANDOM_FLAGS_SIGN_BITS == 0, "RNG optimized random sign is expected to be the default");
            f.sign = get_random_bits<BaseType>(1);
            break;
        case FP_GEN_RANDOM_FLAGS_SIGN_POSITIVE:
            f.sign = 0;
            break;
        case FP_GEN_RANDOM_FLAGS_SIGN_NEGATIVE:
            f.sign = 1;
            break;
        default:
            assert(false && "Unhandled sign generator");
            __builtin_unreachable();
    }

    switch (flags & FP_GEN_RANDOM_FLAGS_EXPONENT_MASK) {
        case FP_GEN_RANDOM_FLAGS_EXPONENT_RANDOM:
            static_assert(F::exponent_bits() <= BITS_FROM_RANDOM, "RNG result is not sufficient for exponent");
            f.exponent = random();
            break;
        case FP_GEN_RANDOM_FLAGS_EXPONENT_BITS:
            static_assert(FP_GEN_RANDOM_FLAGS_EXPONENT_BITS == 0, "RNG optimized random exponent is expected to be the default");
            f.exponent = get_random_bits<BaseType>(F::exponent_bits());
            break;
        case FP_GEN_RANDOM_FLAGS_EXPONENT_GAUSSIAN2:
            static_assert(F::exponent_bits() > 1, "Type is not capable of Gaussian 2 distribution");
            f.exponent = get_random_bits<BaseType>(F::exponent_bits() - 1) +
                            get_random_bits<BaseType>(F::exponent_bits() - 1);
            break;
        case FP_GEN_RANDOM_FLAGS_EXPONENT_GAUSSIAN4:
            static_assert(F::exponent_bits() > 2, "Type is not capable of Gaussian 4 distribution");
            f.exponent = get_random_bits<BaseType>(F::exponent_bits() - 1) +
                            get_random_bits<BaseType>(F::exponent_bits() - 2) +
                            get_random_bits<BaseType>(F::exponent_bits() - 2);
            break;
        case FP_GEN_RANDOM_FLAGS_EXPONENT_GAUSSIAN8:
            static_assert(F::exponent_bits() > 3, "Type is not capable of Gaussian 8 distribution");
            f.exponent = get_random_bits<BaseType>(F::exponent_bits() - 1) +
                            get_random_bits<BaseType>(F::exponent_bits() - 2) +
                            get_random_bits<BaseType>(F::exponent_bits() - 3) +
                            get_random_bits<BaseType>(F::exponent_bits() - 3);
            break;
        case FP_GEN_RANDOM_FLAGS_EXPONENT_VECTOR:
            f.exponent = get_predefined_float<F>(selected_predefined).exponent;
            break;

        case FP_GEN_RANDOM_FLAGS_EXPONENT_MAX:
            // in most cases (except BFloat8/HFloat8) infinity or NaNs
            f.exponent = get_mask<BaseType>(F::exponent_bits());
            break;
        case FP_GEN_RANDOM_FLAGS_EXPONENT_BIAS:
            // range [1..2)
            f.exponent = get_exponent_bias<F>();
            break;
        case FP_GEN_RANDOM_FLAGS_EXPONENT_ZERO:
        case FP_GEN_RANDOM_FLAGS_VALUE_DENORMAL:
            // zero or denormal
            f.exponent = 0;
            break;
        case FP_GEN_RANDOM_FLAGS_VALUE_ZERO:
            // fast path: both exponent and mantissa are zeros
            f.exponent = 0;
            flags = (flags & (~FP_GEN_RANDOM_FLAGS_MANTISSA_MASK)) | FP_GEN_RANDOM_FLAGS_MANTISSA_ZERO;
            break;
        case FP_GEN_RANDOM_FLAGS_VALUE_INF:
        case FP_GEN_RANDOM_FLAGS_VALUE_OVERFLOW:
            // exp will be enforced, do not randomize the mantissa
            flags = (flags & (~FP_GEN_RANDOM_FLAGS_MANTISSA_MASK)) | FP_GEN_RANDOM_FLAGS_MANTISSA_ZERO;
            break;
        case FP_GEN_RANDOM_FLAGS_VALUE_NAN:
        case FP_GEN_RANDOM_FLAGS_VALUE_SNAN:
        case FP_GEN_RANDOM_FLAGS_VALUE_QNAN:
            // exp enforced later
            break;

        default:
            assert(false && "Unhandled exponent generator");
            __builtin_unreachable();
    }

    switch (flags & FP_GEN_RANDOM_FLAGS_MANTISSA_MASK) {
        case FP_GEN_RANDOM_FLAGS_MANTISSA_RANDOM:
            if constexpr (F::mantissa_bits() > 64) {
                f.mantissa = random128();
            } else if constexpr (F::mantissa_bits() > 32) {
                f.mantissa = random64();
            } else if constexpr (F::mantissa_bits() > BITS_FROM_RANDOM) {
                f.mantissa = random32();
            } else {
                f.mantissa = random();
            }
            break;
        case FP_GEN_RANDOM_FLAGS_MANTISSA_BITS:
            static_assert(FP_GEN_RANDOM_FLAGS_MANTISSA_BITS == 0, "RNG optimized random mantissa is expected to be the default");
            f.mantissa = get_random_bits<BaseType>(F::mantissa_bits());
            break;
        case FP_GEN_RANDOM_FLAGS_MANTISSA_PATTERNED:
            // existing pattern to generate "chains" of 1s and 0s, RNG optimized
            f.mantissa = set_random_bits(get_random_value<uint32_t>(F::mantissa_bits() + 1), F::mantissa_bits());
            break;
        case FP_GEN_RANDOM_FLAGS_MANTISSA_VECTOR:
            f.mantissa = get_predefined_float<F>(selected_predefined).mantissa;
            break;
        case FP_GEN_RANDOM_FLAGS_MANTISSA_ZERO:
            f.mantissa = 0;
            break;
        default:
            assert(false && "Unhandled mantissa generator");
            __builtin_unreachable();
    }

    // enforce specific exponent/mantissa combinations. Mantissa must be ready as some force() require it
    switch (flags & FP_GEN_RANDOM_FLAGS_EXPONENT_MASK) {
        // VALUE_ZERO already handled
        case FP_GEN_RANDOM_FLAGS_VALUE_INF:
            force_infinity(f);
            break;
        case FP_GEN_RANDOM_FLAGS_VALUE_OVERFLOW:
            force_overflow(f);
            break;
        case FP_GEN_RANDOM_FLAGS_VALUE_DENORMAL:
            force_denormal(f);
            break;
        case FP_GEN_RANDOM_FLAGS_VALUE_NAN:
            force_nan(f);
            break;
        case FP_GEN_RANDOM_FLAGS_VALUE_QNAN:
            force_nan(f, true);
            break;
        case FP_GEN_RANDOM_FLAGS_VALUE_SNAN:
            force_nan(f, false);
            break;
    }

    if (flags & FP_GEN_RANDOM_FLAGS_FORCE_FINITE) {
        assert(({
                bool compatible;
                switch (flags & FP_GEN_RANDOM_FLAGS_EXPONENT_MASK) {
                    case FP_GEN_RANDOM_FLAGS_VALUE_INF:
                    case FP_GEN_RANDOM_FLAGS_VALUE_OVERFLOW:
                    case FP_GEN_RANDOM_FLAGS_VALUE_NAN:
                    case FP_GEN_RANDOM_FLAGS_VALUE_SNAN:
                    case FP_GEN_RANDOM_FLAGS_VALUE_QNAN:
                        compatible = false;
                        break;
                    default:
                        compatible = true;
                        break;
                }
                compatible;
            }) && "Cannot request finite value when Inf/NaN/overflow is forced");
        if (!f.is_finite()) {
            f.exponent = get_exponent_bias<F>();
        }
    }
    if (flags & FP_GEN_RANDOM_FLAGS_NO_SUBNORMALS) {
        assert(({
                bool compatible;
                switch (flags & FP_GEN_RANDOM_FLAGS_EXPONENT_MASK) {
                    case FP_GEN_RANDOM_FLAGS_VALUE_ZERO:
                    case FP_GEN_RANDOM_FLAGS_VALUE_DENORMAL:
                        compatible = false;
                        break;
                    default:
                        compatible = true;
                        break;
                }
                compatible;
            }) && "Cannot request normal value if zero/denormal/Inf/NaN/overflow is forced");
        if (f.is_zero() || f.is_denormal()) {
            f.exponent = get_exponent_bias<F>();
        }
    }
    fix_bits(f);
    return f;
}

template<typename F>
inline F normalize(F f, float v1, float v2, uint32_t flags) {
    // return the value normalized to the full/half-axis ranges if +-maximum float values were given.
    // Force negative/positive values if the range covers only half-axis range.
    // (appropriate sign is expected in the result, exponent/mantissa are not changed!)
    constexpr uint32_t U = 0;
    constexpr uint32_t Z = 1;
    constexpr uint32_t P = 2;
    constexpr uint32_t N = 3;
    auto props = [](F f) -> uint32_t {
        if (f.is_zero()) {
            return Z;
        } else if ((!f.is_finite()) || f.is_max()) {
            return f.is_negative() ? N : P;
        }
        return U;
    };
    F f1{v1};
    F f2{v2};
    uint32_t s1 = props(f1);
    uint32_t s2 = props(f2);

    // do the sanity checks
    assert(!(((s1 == Z) || (f1.is_negative())) && ((s2 == Z) || f2.is_negative()) &&
             ((flags & FP_GEN_RANDOM_FLAGS_SIGN_MASK) == FP_GEN_RANDOM_FLAGS_SIGN_POSITIVE) && "Negative range for positive value"));
    assert(!(((s1 == Z) || (!f1.is_negative())) && ((s2 == Z) || (!f2.is_negative())) &&
             ((flags & FP_GEN_RANDOM_FLAGS_SIGN_MASK) == FP_GEN_RANDOM_FLAGS_SIGN_NEGATIVE) && "Positive range for negative value"));
    assert(!(((s1 == P) && (s2 == P)) || ((s1 == N) && (s2 == N))) && "Requested +-Inf");
    if ((s1 == Z) && (s2 == Z) && (!f.is_finite())) {
        // no normalization, zero range requested
        assert(false && "Requested zero range for invalid value");
        return f1;
    }

    // Normalization does nothing for Inf/NaN/overflow values except the sign
    if (!f.is_finite()) {
        if (f1.is_negative() && f2.is_negative()) {
            f.sign = 1;
        } else if ((!f1.is_negative()) && (!f2.is_negative())) {
            f.sign = 0;
        }
        return f;
    }

    // half axis ranges
    if (((s1 == Z) && (s2 == P)) || ((s1 == P) && (s2 == Z))) {
        f.sign = 0;
        return f;
    }
    if (((s1 == N) && (s2 == Z)) || ((s1 == Z) && (s2 == N))) {
        f.sign = 1;
        return f;
    }
    // no normalization, axis-crossing range requested
    if (((s1 == N) && (s2 == P)) || ((s1 == P) && (s2 == N))) {
        return f;
    }

    // normalize input value to the range, just by normalizing it to 1..2 (with flat distribution)
    // and then forcing requested range. It will report very few values (esp. for 8bit types),
    // so it would be needed to normalize e.g. float and downconvert it to appropriate type if
    // more values is expected, e.g: BFloat8(gen_random_float(10, 20))
    f.sign = 0;
    f.exponent = get_exponent_bias<F>();
    auto v = f.as_fp();
    return F((v - (decltype(v)) 1.0) * ((decltype(v)) v2 - (decltype(v)) v1) + (decltype(v)) v1);
}

#undef set_random
template<typename F>
inline void set_random(F* ptr, size_t num, uint32_t flags, float v1, float v2) {
    // extra scenarios, fast paths (all values at once)
    switch (flags) {
        case FP_GEN_FAST_MEMSET_ZERO:
            memset((void*) ptr, 0, sizeof(F) * num);
            return;
        case FP_GEN_FAST_MEMSET_RANDOM:
            memset_random((void*) ptr, sizeof(F) * num);
            return;
    }

    for (size_t i = 0; i < num; i++) {
        if (flags & FP_GEN_NORMALIZE) {
            // normalize<F>(single_random<Float32>())?
            ptr[i] = normalize(single_random<F>(flags & (~FP_GEN_NORMALIZE)), v1, v2, flags);
        } else {
            ptr[i] = single_random<F>(flags);
        }
    }
}

} // anonymous namespace

void set_random_hfloat8(HFloat8* ptr, size_t num, uint32_t flags, float v1, float v2) {
    set_random<HFloat8>(ptr, num, flags, v1, v2);
}
void set_random_bfloat8(BFloat8* ptr, size_t num, uint32_t flags, float v1, float v2) {
    set_random<BFloat8>(ptr, num, flags, v1, v2);
}
void set_random_float16(Float16* ptr, size_t num, uint32_t flags, float v1, float v2) {
    set_random<Float16>(ptr, num, flags, v1, v2);
}
void set_random_bfloat16(BFloat16* ptr, size_t num, uint32_t flags, float v1, float v2) {
    set_random<BFloat16>(ptr, num, flags, v1, v2);
}
void set_random_float32(Float32* ptr, size_t num, uint32_t flags, float v1, float v2) {
    set_random<Float32>(ptr, num, flags, v1, v2);
}
void set_random_float(float* ptr, size_t num, uint32_t flags, float v1, float v2) {
    set_random<Float32>(reinterpret_cast<Float32*>(ptr), num, flags, v1, v2);
}
void set_random_float64(Float64* ptr, size_t num, uint32_t flags, float v1, float v2) {
    set_random<Float64>(ptr, num, flags, v1, v2);
}
void set_random_double(double* ptr, size_t num, uint32_t flags, float v1, float v2) {
    set_random<Float64>(reinterpret_cast<Float64*>(ptr), num, flags, v1, v2);
}
void set_random_float80(Float80* ptr, size_t num, uint32_t flags, float v1, float v2) {
    set_random<Float80>(ptr, num, flags, v1, v2);
}

#endif // !OBSOLETE_RANDOM_GENERATORS
