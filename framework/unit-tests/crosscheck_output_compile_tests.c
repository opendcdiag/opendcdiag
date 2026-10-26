/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

// Compile each case separately, without warning promotion; only case 0 compiles.
#include "crosscheck.h"

#include <stddef.h>
#include <stdint.h>

#ifndef CROSSCHECK_COMPILE_CASE
#  define CROSSCHECK_COMPILE_CASE 0
#endif

#if CROSSCHECK_COMPILE_CASE == 0
#define DECLARE_CONTROL(ctype, tag, suffix) DECLARE_CROSS_CHECK_OUTPUT(control_##suffix, ctype);
DECLARE_CONTROL(_Bool, UInt8Data, bool)
DECLARE_CONTROL(char, UInt8Data, char)
DECLARE_CONTROL(uint8_t, UInt8Data, uint8)
DECLARE_CONTROL(uint16_t, UInt16Data, uint16)
DECLARE_CONTROL(uint32_t, UInt32Data, uint32)
DECLARE_CONTROL(unsigned long, SANDSTONE_ULONG_TYPE, ulong)
DECLARE_CONTROL(unsigned long long, UInt64Data, ullong)
DECLARE_CONTROL(__uint128_t, UInt128Data, uint128)
DECLARE_CONTROL(int8_t, Int8Data, int8)
DECLARE_CONTROL(int16_t, Int16Data, int16)
DECLARE_CONTROL(int32_t, Int32Data, int32)
DECLARE_CONTROL(long, SANDSTONE_LONG_TYPE, long)
DECLARE_CONTROL(long long, Int64Data, llong)
DECLARE_CONTROL(__int128_t, Int128Data, int128)
DECLARE_CONTROL(HFloat8, HFloat8Data, hfloat8)
DECLARE_CONTROL(BFloat8, BFloat8Data, bfloat8)
DECLARE_CONTROL(BFloat16, BFloat16Data, bfloat16)
DECLARE_CONTROL(Float16, Float16Data, float16)
DECLARE_CONTROL(float, Float32Data, float)
DECLARE_CONTROL(double, Float64Data, double)
DECLARE_CONTROL(long double, SANDSTONE_LONG_DOUBLE_TYPE, long_double)
#undef DECLARE_CONTROL
#define CHECK_CONTROL(ctype, tag, suffix) \
    void crosscheck_output_control_##suffix(ctype *data, const ctype *constant, size_t count) \
    { \
        capture_output(control_##suffix, data, count, "mutable"); \
        capture_output(control_##suffix, constant, count, NULL); \
        capture_output(control_##suffix, (const ctype *)NULL, 0, NULL); \
    }
SANDSTONE_SCALAR_TYPES(CHECK_CONTROL)
#undef CHECK_CONTROL

#elif CROSSCHECK_COMPILE_CASE == 1
DECLARE_CROSS_CHECK_OUTPUT(output, uint32_t);
void crosscheck_output_case(uint16_t *data)
{
    capture_output(output, data, 1, NULL);
}

#elif CROSSCHECK_COMPILE_CASE == 2
DECLARE_CROSS_CHECK_OUTPUT(output, uint8_t);
void crosscheck_output_case(_Bool *data)
{
    capture_output(output, data, 1, NULL);
}

#elif CROSSCHECK_COMPILE_CASE == 3
DECLARE_CROSS_CHECK_OUTPUT(output, _Bool);
void crosscheck_output_case(uint8_t *data)
{
    capture_output(output, data, 1, NULL);
}

#elif CROSSCHECK_COMPILE_CASE == 4
DECLARE_CROSS_CHECK_OUTPUT(output, uint32_t);
void crosscheck_output_case(int32_t *data)
{
    capture_output(output, data, 1, NULL);
}

#elif CROSSCHECK_COMPILE_CASE == 5
DECLARE_CROSS_CHECK_OUTPUT(output, uint32_t);
void crosscheck_output_case(void *data)
{
    capture_output(output, data, 1, NULL);
}

#elif CROSSCHECK_COMPILE_CASE == 6
DECLARE_CROSS_CHECK_OUTPUT(output, uint32_t);
void crosscheck_output_case(volatile uint32_t *data)
{
    capture_output(output, data, 1, NULL);
}

#elif CROSSCHECK_COMPILE_CASE == 7
#ifdef __cplusplus
namespace { struct Opaque { uint32_t value; }; }
DECLARE_CROSS_CHECK_OUTPUT(output, Opaque);
#else
struct crosscheck_output_opaque { uint32_t value; };
DECLARE_CROSS_CHECK_OUTPUT(output, struct crosscheck_output_opaque);
#endif

#elif CROSSCHECK_COMPILE_CASE == 8
DECLARE_CROSS_CHECK_OUTPUT(output, void);

#elif CROSSCHECK_COMPILE_CASE == 9
DECLARE_CROSS_CHECK_OUTPUT(output, const uint32_t);

#elif CROSSCHECK_COMPILE_CASE == 10
DECLARE_CROSS_CHECK_OUTPUT(output, volatile uint32_t);

#elif CROSSCHECK_COMPILE_CASE == 11
DECLARE_CROSS_CHECK_OUTPUT(output, uint32_t);
void crosscheck_output_case(uint32_t (*data)[2])
{
    capture_output(output, data, 1, NULL);
}

#elif CROSSCHECK_COMPILE_CASE == 12
DECLARE_CROSS_CHECK_OUTPUT(output, uint32_t);
void crosscheck_output_case(uint32_t *data)
{
    capture_input(output, data, 1, NULL);
}

#elif CROSSCHECK_COMPILE_CASE == 13
DECLARE_CROSS_CHECK_OUTPUT(output, uint32_t);
void crosscheck_output_case(void)
{
    (void)get_input(output);
}

#elif CROSSCHECK_COMPILE_CASE == 14
DECLARE_CROSS_CHECK_INPUT(input, uint32_t);
void crosscheck_output_case(uint32_t *data)
{
    capture_output(input, data, 1, NULL);
}

#elif CROSSCHECK_COMPILE_CASE == 15
DECLARE_CROSS_CHECK_OUTPUT(output, uint32_t);
void crosscheck_output_case(uint32_t *data)
{
    capture_output(output, data, 1);
}

#else
#  error "Unknown CROSSCHECK_COMPILE_CASE"
#endif
