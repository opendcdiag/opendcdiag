/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck.h"

#include <stddef.h>
#include <stdint.h>

// All API expressions are unevaluated: this translation unit must not require
// crosscheck.cpp's set/get/submit entry points in the unit-test executable.
#define CHECK_CROSSCHECK_TYPE(ctype, suffix) \
    CROSSCHECK_INPUT(crosscheck_c_##suffix, ctype); \
    CROSSCHECK_OUTPUT(crosscheck_c_output_##suffix, ctype); \
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
            "const input pointer accepted"); \
    _Static_assert(__builtin_types_compatible_p( \
            __typeof__(submit_output(crosscheck_c_output_##suffix, (ctype *)0, 0, NULL)), void), \
            "mutable output pointer accepted"); \
    _Static_assert(__builtin_types_compatible_p( \
            __typeof__(submit_output(crosscheck_c_output_##suffix, (const ctype *)0, 0, "output")), void), \
            "const output pointer accepted"); \
    _Static_assert(_Generic(&CROSSCHECK_INPUT_SET_FN((ctype *)0), \
            void (*)(const char *, const ctype *, size_t, const char *): 1, default: 0), \
            "input dispatch preserves exact type"); \
    _Static_assert(_Generic(&CROSSCHECK_OUTPUT_SUBMIT_FN((const ctype *)0), \
            void (*)(const char *, const ctype *, size_t, const char *): 1, default: 0), \
            "output dispatch preserves exact type");

// Expand independently: CROSSCHECK_INPUT itself uses SANDSTONE_SCALAR_TYPES.
CHECK_CROSSCHECK_TYPE(_Bool, bool)
CHECK_CROSSCHECK_TYPE(char, char)
CHECK_CROSSCHECK_TYPE(uint8_t, uint8)
CHECK_CROSSCHECK_TYPE(uint16_t, uint16)
CHECK_CROSSCHECK_TYPE(uint32_t, uint32)
CHECK_CROSSCHECK_TYPE(unsigned long, ulong)
CHECK_CROSSCHECK_TYPE(unsigned long long, ullong)
CHECK_CROSSCHECK_TYPE(__uint128_t, uint128)
CHECK_CROSSCHECK_TYPE(int8_t, int8)
CHECK_CROSSCHECK_TYPE(int16_t, int16)
CHECK_CROSSCHECK_TYPE(int32_t, int32)
CHECK_CROSSCHECK_TYPE(long, long)
CHECK_CROSSCHECK_TYPE(long long, llong)
CHECK_CROSSCHECK_TYPE(__int128_t, int128)
CHECK_CROSSCHECK_TYPE(HFloat8, hfloat8)
CHECK_CROSSCHECK_TYPE(BFloat8, bfloat8)
CHECK_CROSSCHECK_TYPE(BFloat16, bfloat16)
CHECK_CROSSCHECK_TYPE(Float16, float16)
CHECK_CROSSCHECK_TYPE(float, float)
CHECK_CROSSCHECK_TYPE(double, double)
CHECK_CROSSCHECK_TYPE(long double, long_double)
#undef CHECK_CROSSCHECK_TYPE

static __attribute__((unused)) uint32_t crosscheck_c_array[3];
static __attribute__((unused)) const uint32_t crosscheck_c_const_array[3];
_Static_assert(__builtin_types_compatible_p(
        __typeof__(set_input(crosscheck_c_uint32, crosscheck_c_array, 3, NULL)), void),
        "array decays to the exact mutable element pointer");
_Static_assert(__builtin_types_compatible_p(
        __typeof__(set_input(crosscheck_c_uint32, crosscheck_c_const_array, 3, NULL)), void),
        "const array decays to the exact const element pointer");
_Static_assert(__builtin_types_compatible_p(
        __typeof__(submit_output(crosscheck_c_output_uint32, crosscheck_c_array, 3, NULL)), void),
        "output array decays to the exact mutable element pointer");
_Static_assert(__builtin_types_compatible_p(
        __typeof__(submit_output(crosscheck_c_output_uint32, crosscheck_c_const_array, 3, NULL)), void),
        "const output array decays to the exact const element pointer");

_Static_assert(DATATYPEFORTYPE((_Bool)0) == DATATYPEFORTYPE((uint8_t)0), "shared DataType");
