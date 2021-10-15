/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __FP_VECTORS_H
#define __FP_VECTORS_H

#include <assert.h>
#include <stdint.h>

#define FLOAT32_EXPONENT_MASK  0xffu
#define FLOAT64_EXPONENT_MASK  0x7ffu
#define FLOAT80_EXPONENT_MASK  0x7fffu

#define FLOAT32_INFINITY_EXPONENT  0xffu
#define FLOAT64_INFINITY_EXPONENT  0x7ffu
#define FLOAT80_INFINITY_EXPONENT  0x7fffu

#define FLOAT32_NAN_EXPONENT  0xffu
#define FLOAT64_NAN_EXPONENT  0x7ffu
#define FLOAT80_NAN_EXPONENT  0x7fffu

#define FLOAT32_EXPONENT_BIAS  0x7fu
#define FLOAT64_EXPONENT_BIAS  0x3ffu
#define FLOAT80_EXPONENT_BIAS  0x3fffu

#define FLOAT32_MANTISSA_MASK  0x7fffffu
#define FLOAT64_MANTISSA_MASK  0xfffffffffffffu
#define FLOAT80_MANTISSA_MASK  0xffffffffffffffffu

#define FLOAT32_MANTISSA_QUIET_NAN_MASK  0x400000u
#define FLOAT64_MANTISSA_QUIET_NAN_MASK  0x8000000000000u
#define FLOAT80_MANTISSA_QUIET_NAN_MASK  0x8000000000000000u

#ifdef __cplusplus
extern "C" {
#endif

typedef union {
    float as_float;
    uint32_t as_hex;
    struct {
        unsigned mantissa : 23;
        unsigned exponent : 8;
        unsigned sign : 1;
    };
} Float32;
static_assert(sizeof(Float32) == sizeof(float), "Float32 structure is not of the correct size");

typedef union {
    double as_float;
    uint64_t as_hex;
    struct {
        unsigned long long mantissa : 52;
        unsigned long long exponent : 11;
        unsigned long long sign : 1;
    };
} Float64;
static_assert(sizeof(Float64) == sizeof(double), "Float64 structure is not of the correct size");

typedef union {
    struct {
        long double as_float;
    };
    struct {
        unsigned long long mantissa : 63;
        unsigned long jbit : 1;
        unsigned exponent : 15;
        unsigned sign : 1;
    };
    struct {
        uint64_t low64;
        uint16_t high16;
    } as_hex;
} Float80;
static_assert(sizeof(double) < sizeof(long double), "Compiler does not support long double");
static_assert(sizeof(Float80) == sizeof(long double), "Float80 structure is not of the correct size");

Float32 new_float32(uint32_t sign, uint32_t exponent, uint32_t mantissa);
Float64 new_float64(uint32_t sign, uint32_t exponent, uint64_t mantissa);
Float80 new_float80(uint32_t sign, uint32_t exponent, uint32_t jbit, uint64_t mantissa);

Float32 new_random_float32();
Float64 new_random_float64();
Float80 new_random_float80();

#ifdef __cplusplus
} // extern "C"
#endif

#endif //PROJECT_FP_VECTORS_H
