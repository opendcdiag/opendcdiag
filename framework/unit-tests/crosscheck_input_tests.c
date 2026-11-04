/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck.h"

#include <stddef.h>
#include <stdint.h>

// All API expressions are unevaluated: this translation unit must not require
// crosscheck.cpp's capture/get entry points in the unit-test executable.
#define CHECK_INPUT_TYPE(ctype, tag, suffix) \
    DECLARE_CROSS_CHECK_INPUT(crosscheck_c_##suffix, ctype); \
    _Static_assert(_Generic(get_input(crosscheck_c_##suffix).data, \
                            const ctype *: 1, default: 0), "typed const input pointer"); \
    _Static_assert(_Generic(get_input(crosscheck_c_##suffix).count, \
                            size_t: 1, default: 0), "element count is size_t"); \
    _Static_assert(__builtin_types_compatible_p( \
            __typeof__(capture_input(crosscheck_c_##suffix, (ctype *)0, 0, NULL)), void), \
            "mutable input pointer accepted"); \
    _Static_assert(__builtin_types_compatible_p( \
            __typeof__(capture_input(crosscheck_c_##suffix, (const ctype *)0, 0, "input")), void), \
            "const input pointer accepted");

// Expand independently: DECLARE_CROSS_CHECK_INPUT itself uses SANDSTONE_SCALAR_TYPES.
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
        __typeof__(capture_input(crosscheck_c_uint32, crosscheck_c_array, 3, NULL)), void),
        "array decays to the exact mutable element pointer");
_Static_assert(__builtin_types_compatible_p(
        __typeof__(capture_input(crosscheck_c_uint32, crosscheck_c_const_array, 3, NULL)), void),
        "const array decays to the exact const element pointer");

// A default association lets us probe rejection independently, without turning
// this positive compilation test into an intentionally failing translation unit.
// These are the exact associations used by capture_input's tag validation.
#define KEY_ACCEPTS(name, pointer) \
    _Generic((pointer), crosscheck_input_type_##name *: 1, \
             const crosscheck_input_type_##name *: 1, default: 0)

struct crosscheck_c_opaque { uint32_t value; };
_Static_assert(KEY_ACCEPTS(crosscheck_c_uint32, crosscheck_c_array), "exact array accepted");
_Static_assert(KEY_ACCEPTS(crosscheck_c_uint32, crosscheck_c_const_array), "const array accepted");
_Static_assert(!KEY_ACCEPTS(crosscheck_c_uint32, (uint16_t *)0), "wrong width rejected");
_Static_assert(!KEY_ACCEPTS(crosscheck_c_uint32, (int32_t *)0), "wrong signedness rejected");
_Static_assert(!KEY_ACCEPTS(crosscheck_c_uint32, (void *)0), "void pointer rejected");
_Static_assert(!KEY_ACCEPTS(crosscheck_c_uint32, (const void *)0), "const void pointer rejected");
_Static_assert(!KEY_ACCEPTS(crosscheck_c_uint32, (volatile uint32_t *)0), "volatile rejected");
_Static_assert(!KEY_ACCEPTS(crosscheck_c_uint32, (struct crosscheck_c_opaque *)0), "opaque rejected");
_Static_assert(DATATYPEFORTYPE((_Bool)0) == DATATYPEFORTYPE((uint8_t)0), "shared DataType");
_Static_assert(KEY_ACCEPTS(crosscheck_c_bool, (_Bool *)0), "bool accepted");
_Static_assert(!KEY_ACCEPTS(crosscheck_c_bool, (uint8_t *)0), "byte is not bool");
_Static_assert(!KEY_ACCEPTS(crosscheck_c_uint8, (_Bool *)0), "bool is not byte");
_Static_assert(!KEY_ACCEPTS(crosscheck_c_uint8, (char *)0), "char is not uint8_t");
#undef KEY_ACCEPTS

_Static_assert(_Generic(&CROSSCHECK_INPUT_CAPTURE_FN((_Bool *)0),
        void (*)(const char *, const _Bool *, size_t, const char *): 1, default: 0),
        "bool dispatch preserves exact type");
_Static_assert(_Generic(&CROSSCHECK_INPUT_CAPTURE_FN((const uint8_t *)0),
        void (*)(const char *, const uint8_t *, size_t, const char *): 1, default: 0),
        "const byte dispatch preserves exact type");
