/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck.h"

#include <stddef.h>
#include <stdint.h>

// All API expressions are unevaluated: this translation unit must not require
// crosscheck.cpp's set/get entry points in the unit-test executable.
#define CHECK_INPUT_TYPE(ctype, tag, suffix) \
    CROSSCHECK_INPUT(crosscheck_c_##suffix, ctype); \
    _Static_assert(__builtin_types_compatible_p( \
            __typeof__(get_input(crosscheck_c_##suffix).data), const ctype *), \
            "typed const input pointer"); \
    _Static_assert(__builtin_types_compatible_p( \
            __typeof__(get_input(crosscheck_c_##suffix).count), size_t), \
            "element count is size_t"); \
    _Static_assert(__builtin_types_compatible_p( \
            __typeof__(set_input(crosscheck_c_##suffix, (ctype *)0, 0, NULL)), void), \
            "mutable input pointer accepted"); \
    _Static_assert(__builtin_types_compatible_p( \
            __typeof__(set_input(crosscheck_c_##suffix, (const ctype *)0, 0, "input")), void), \
            "const input pointer accepted");

// Expand independently: CROSSCHECK_INPUT itself uses SANDSTONE_SCALAR_TYPES.
CHECK_INPUT_TYPE(_Bool, UInt8Data, bool)
CHECK_INPUT_TYPE(char, UInt8Data, char)
CHECK_INPUT_TYPE(uint8_t, UInt8Data, uint8)
CHECK_INPUT_TYPE(uint16_t, UInt16Data, uint16)
CHECK_INPUT_TYPE(uint32_t, UInt32Data, uint32)
CHECK_INPUT_TYPE(unsigned long, SANDSTONE_ULONG_TYPE, ulong)
CHECK_INPUT_TYPE(unsigned long long, UInt64Data, ullong)
CHECK_INPUT_TYPE(__uint128_t, UInt128Data, uint128)
CHECK_INPUT_TYPE(int8_t, Int8Data, int8)
CHECK_INPUT_TYPE(int16_t, Int16Data, int16)
CHECK_INPUT_TYPE(int32_t, Int32Data, int32)
CHECK_INPUT_TYPE(long, SANDSTONE_LONG_TYPE, long)
CHECK_INPUT_TYPE(long long, Int64Data, llong)
CHECK_INPUT_TYPE(__int128_t, Int128Data, int128)
CHECK_INPUT_TYPE(HFloat8, HFloat8Data, hfloat8)
CHECK_INPUT_TYPE(BFloat8, BFloat8Data, bfloat8)
CHECK_INPUT_TYPE(BFloat16, BFloat16Data, bfloat16)
CHECK_INPUT_TYPE(Float16, Float16Data, float16)
CHECK_INPUT_TYPE(float, Float32Data, float)
CHECK_INPUT_TYPE(double, Float64Data, double)
CHECK_INPUT_TYPE(long double, SANDSTONE_LONG_DOUBLE_TYPE, long_double)
#undef CHECK_INPUT_TYPE

static __attribute__((unused)) uint32_t crosscheck_c_array[3];
static __attribute__((unused)) const uint32_t crosscheck_c_const_array[3];
_Static_assert(__builtin_types_compatible_p(
        __typeof__(set_input(crosscheck_c_uint32, crosscheck_c_array, 3, NULL)), void),
        "array decays to the exact mutable element pointer");
_Static_assert(__builtin_types_compatible_p(
        __typeof__(set_input(crosscheck_c_uint32, crosscheck_c_const_array, 3, NULL)), void),
        "const array decays to the exact const element pointer");

_Static_assert(DATATYPEFORTYPE((_Bool)0) == DATATYPEFORTYPE((uint8_t)0), "shared DataType");

_Static_assert(_Generic(&CROSSCHECK_INPUT_SET_FN((_Bool *)0),
        void (*)(const char *, const _Bool *, size_t, const char *): 1, default: 0),
        "bool dispatch preserves exact type");
_Static_assert(_Generic(&CROSSCHECK_INPUT_SET_FN((const uint8_t *)0),
        void (*)(const char *, const uint8_t *, size_t, const char *): 1, default: 0),
        "const byte dispatch preserves exact type");
