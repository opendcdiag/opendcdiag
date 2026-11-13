/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

// Compile each case separately; only case 0 must compile. Do not link this file.
#include "crosscheck.h"

#include <stddef.h>
#include <stdint.h>

#ifndef CROSSCHECK_COMPILE_CASE
#  define CROSSCHECK_COMPILE_CASE 0
#endif

#if CROSSCHECK_COMPILE_CASE == 0

#define DECLARE_CONTROL_INPUT(ctype, tag, suffix) \
    CROSSCHECK_INPUT(control_##suffix, ctype);
// These declarations must not nest SANDSTONE_SCALAR_TYPES expansions.
DECLARE_CONTROL_INPUT(_Bool, UInt8Data, bool)
DECLARE_CONTROL_INPUT(char, UInt8Data, char)
DECLARE_CONTROL_INPUT(uint8_t, UInt8Data, uint8)
DECLARE_CONTROL_INPUT(uint16_t, UInt16Data, uint16)
DECLARE_CONTROL_INPUT(uint32_t, UInt32Data, uint32)
DECLARE_CONTROL_INPUT(unsigned long, SANDSTONE_ULONG_TYPE, ulong)
DECLARE_CONTROL_INPUT(unsigned long long, UInt64Data, ullong)
DECLARE_CONTROL_INPUT(__uint128_t, UInt128Data, uint128)
DECLARE_CONTROL_INPUT(int8_t, Int8Data, int8)
DECLARE_CONTROL_INPUT(int16_t, Int16Data, int16)
DECLARE_CONTROL_INPUT(int32_t, Int32Data, int32)
DECLARE_CONTROL_INPUT(long, SANDSTONE_LONG_TYPE, long)
DECLARE_CONTROL_INPUT(long long, Int64Data, llong)
DECLARE_CONTROL_INPUT(__int128_t, Int128Data, int128)
DECLARE_CONTROL_INPUT(HFloat8, HFloat8Data, hfloat8)
DECLARE_CONTROL_INPUT(BFloat8, BFloat8Data, bfloat8)
DECLARE_CONTROL_INPUT(BFloat16, BFloat16Data, bfloat16)
DECLARE_CONTROL_INPUT(Float16, Float16Data, float16)
DECLARE_CONTROL_INPUT(float, Float32Data, float)
DECLARE_CONTROL_INPUT(double, Float64Data, double)
DECLARE_CONTROL_INPUT(long double, SANDSTONE_LONG_DOUBLE_TYPE, long_double)
#undef DECLARE_CONTROL_INPUT

#define CHECK_CONTROL_INPUT(ctype, tag, suffix) \
    void crosscheck_compile_control_##suffix(ctype *data, const ctype *constant, size_t count) \
    { \
        set_input(control_##suffix, data, count, "mutable pointer"); \
        set_input(control_##suffix, constant, count, NULL); \
        __auto_type view = get_input(control_##suffix); \
        _Static_assert(_Generic(view.data, const ctype *: 1, default: 0), \
                       "get_input must return a pointer to const elements"); \
        const ctype *read_data = view.data; \
        size_t read_count = view.count; \
        (void)read_data; \
        (void)read_count; \
    }
SANDSTONE_SCALAR_TYPES(CHECK_CONTROL_INPUT)
#undef CHECK_CONTROL_INPUT

#elif CROSSCHECK_COMPILE_CASE == 1
// Wrong scalar width.
CROSSCHECK_INPUT(input, uint32_t);
void crosscheck_compile_case(uint16_t *data)
{
    set_input(input, data, 1, NULL);
}

#elif CROSSCHECK_COMPILE_CASE == 2
// Same DataType, different element type: bool is not uint8_t.
CROSSCHECK_INPUT(input, uint8_t);
void crosscheck_compile_case(_Bool *data)
{
    set_input(input, data, 1, NULL);
}

#elif CROSSCHECK_COMPILE_CASE == 3
// Check the reverse direction of the same-DataType mismatch too.
CROSSCHECK_INPUT(input, _Bool);
void crosscheck_compile_case(uint8_t *data)
{
    set_input(input, data, 1, NULL);
}

#elif CROSSCHECK_COMPILE_CASE == 4
// Wrong signedness.
CROSSCHECK_INPUT(input, uint32_t);
void crosscheck_compile_case(int32_t *data)
{
    set_input(input, data, 1, NULL);
}

#elif CROSSCHECK_COMPILE_CASE == 5
CROSSCHECK_INPUT(input, uint32_t);
void crosscheck_compile_case(void *data)
{
    set_input(input, data, 1, NULL);
}

#elif CROSSCHECK_COMPILE_CASE == 6
CROSSCHECK_INPUT(input, uint32_t);
void crosscheck_compile_case(volatile uint32_t *data)
{
    set_input(input, data, 1, NULL);
}

#elif CROSSCHECK_COMPILE_CASE == 7
struct crosscheck_compile_opaque { uint32_t value; };
CROSSCHECK_INPUT(input, struct crosscheck_compile_opaque);

#elif CROSSCHECK_COMPILE_CASE == 8
CROSSCHECK_INPUT(input, void);

#elif CROSSCHECK_COMPILE_CASE == 9
CROSSCHECK_INPUT(input, const uint32_t);

#elif CROSSCHECK_COMPILE_CASE == 10
CROSSCHECK_INPUT(input, volatile uint32_t);

#elif CROSSCHECK_COMPILE_CASE == 11
CROSSCHECK_INPUT(input, uint32_t);
void crosscheck_compile_case(uint32_t (*data)[2])
{
    set_input(input, data, 1, NULL);
}

#elif CROSSCHECK_COMPILE_CASE == 12
CROSSCHECK_INPUT(input, uint32_t);
void crosscheck_compile_case(void)
{
    __auto_type view = get_input(input);
    view.data = NULL;
}

#elif CROSSCHECK_COMPILE_CASE == 13
CROSSCHECK_INPUT(input, uint32_t);
void crosscheck_compile_case(void)
{
    __auto_type view = get_input(input);
    view.count = 0;
}

#else
#  error "Unknown CROSSCHECK_COMPILE_CASE"
#endif
