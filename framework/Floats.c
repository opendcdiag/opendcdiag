/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <unistd.h>
#include <stdint.h>
#include <zconf.h>
#include "fp_vectors/Floats.h"
#include <sandstone.h>

Float32 new_float32(unsigned sign, unsigned exponent, unsigned mantissa)
{
    Float32 f;
    f.sign = sign & 1u;
    f.exponent = exponent & FLOAT32_EXPONENT_MASK;
    f.mantissa = mantissa & FLOAT32_MANTISSA_MASK;
    return f;
}

Float64 new_float64(unsigned sign, uint32_t exponent, uint64_t mantissa)
{
    Float64 f;
    f.sign = sign & 1u;
    f.exponent = exponent & FLOAT64_EXPONENT_MASK;
    f.mantissa = mantissa & FLOAT64_MANTISSA_MASK;
    return f;
}

Float80 new_float80(unsigned sign, uint32_t exponent, unsigned jbit, uint64_t mantissa)
{
    Float80 f;
    f.sign = sign & 1u;
    f.jbit = jbit & 1u;
    f.exponent = exponent & FLOAT80_EXPONENT_MASK;
    f.mantissa = mantissa & FLOAT80_MANTISSA_MASK;
    return f;
}

Float32 new_random_float32(){
    Float32  f;
    f.sign = random32() % 2;
    f.exponent = random32() & FLOAT32_EXPONENT_MASK;
    f.mantissa = set_random_bits((random32() % 22) + 1, 23); // set between 1 and 22 bits of the mantissa

    return f;
}

Float64 new_random_float64(){
    Float64  f;
    f.sign = random32() % 2;
    f.exponent = random32() & FLOAT64_EXPONENT_MASK;
    f.mantissa = set_random_bits((random32() % 52) + 1, 53); // set between 1 and 52 bits of the mantissa

    return f;
}

Float80 new_random_float80(){
    Float80  f;
    f.sign = random32() % 2;
    f.exponent = random32() & FLOAT80_EXPONENT_MASK;
    f.jbit = 1;
    f.mantissa = set_random_bits((random32() % 63) + 1, 64); // set between 1 and 63 bits of the mantissa

    return f;
}

