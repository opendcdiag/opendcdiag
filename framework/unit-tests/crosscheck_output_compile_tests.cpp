/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <list>
#include <span>
#include <string>
#include <vector>

#ifndef CROSSCHECK_COMPILE_CASE
#  define CROSSCHECK_COMPILE_CASE 0
#endif

#if CROSSCHECK_COMPILE_CASE == 0
#define DECLARE_CONTROL(ctype, tag, suffix) CROSSCHECK_OUTPUT(control_##suffix, ctype);
SANDSTONE_SCALAR_TYPES(DECLARE_CONTROL)
#undef DECLARE_CONTROL
#define CHECK_CONTROL(ctype, tag, suffix) \
    void crosscheck_output_control_##suffix(ctype *data, const ctype *constant, size_t count) \
    { \
        submit_output(control_##suffix, data, count, "mutable"); \
        submit_output(control_##suffix, data, count, NULL); \
        submit_output(control_##suffix, constant, count, nullptr); \
        submit_output(control_##suffix, static_cast<const ctype *>(nullptr), 0, nullptr); \
    }
SANDSTONE_SCALAR_TYPES(CHECK_CONTROL)
#undef CHECK_CONTROL
CROSSCHECK_OUTPUT(output, uint32_t);
CROSSCHECK_OUTPUT(text, char);
CROSSCHECK_OUTPUT(flags, bool);
CROSSCHECK_OUTPUT(wrapper32, Float32);
CROSSCHECK_OUTPUT(wrapper64, Float64);
#ifdef SANDSTONE_FP16_TYPE
CROSSCHECK_OUTPUT(native16, fp16_t);
#endif
#ifdef __SIZEOF_FLOAT128__
CROSSCHECK_OUTPUT(wrapper128, Float128);
CROSSCHECK_OUTPUT(native128, __float128);
#endif
void crosscheck_output_ranges()
{
    uint32_t raw[] = {1, 2};
    const std::array<uint32_t, 2> array = {1, 2};
    const std::vector<uint32_t> vector = {1, 2};
    submit_output(output, raw, 0, nullptr);
    submit_output(output, raw, 0, NULL);
    submit_output(output, raw, 2, "pointer");
    submit_output(output, raw, nullptr);
    submit_output(output, raw, NULL);
    submit_output(output, raw, 0); // Explicit null description for the range.
    submit_output(output, array, nullptr);
    submit_output(output, array, NULL);
    submit_output(output, vector, "vector");
    submit_output(output, vector, nullptr);
    submit_output(output, vector, NULL);
    submit_output(output, std::span<uint32_t>(raw), nullptr);
    submit_output(output, std::span<const uint32_t>(raw), nullptr);
    submit_output(output, std::span<const uint32_t>(raw), NULL);
    submit_output(text, std::string("text"), nullptr);
    const bool values[] = {true, false};
    submit_output(flags, values, nullptr);
    const std::array<Float32, 1> single = {};
    const std::array<Float64, 1> wide = {};
    submit_output(wrapper32, single, nullptr);
    submit_output(wrapper64, wide, nullptr);
#ifdef SANDSTONE_FP16_TYPE
    submit_output(native16, static_cast<const fp16_t *>(nullptr), 0, nullptr);
#endif
#ifdef __SIZEOF_FLOAT128__
    submit_output(wrapper128, static_cast<const Float128 *>(nullptr), 0, nullptr);
    submit_output(native128, static_cast<const __float128 *>(nullptr), 0, nullptr);
#endif
}

#elif CROSSCHECK_COMPILE_CASE <= 15
// Shared C controls exercise the same pointer/declaration constraints in C++.
#include "unit-tests/crosscheck_output_compile_tests.c"

#elif CROSSCHECK_COMPILE_CASE == 16
CROSSCHECK_OUTPUT(output, bool);
void crosscheck_output_case(const std::vector<bool> &data)
{
    submit_output(output, data, nullptr);
}

#elif CROSSCHECK_COMPILE_CASE == 17
CROSSCHECK_OUTPUT(output, uint32_t);
void crosscheck_output_case(const std::list<uint32_t> &data)
{
    submit_output(output, data, nullptr);
}

#elif CROSSCHECK_COMPILE_CASE == 18
CROSSCHECK_OUTPUT(output, uint32_t);
void crosscheck_output_case(std::span<volatile uint32_t> data)
{
    submit_output(output, data, nullptr);
}

#elif CROSSCHECK_COMPILE_CASE == 19
CROSSCHECK_OUTPUT(output, uint32_t);
void crosscheck_output_case(const std::vector<uint16_t> &data)
{
    submit_output(output, data, nullptr);
}

#elif CROSSCHECK_COMPILE_CASE == 20
CROSSCHECK_OUTPUT(output, Float32);
void crosscheck_output_case(float *data)
{
    submit_output(output, data, 1, nullptr);
}

#elif CROSSCHECK_COMPILE_CASE == 21
CROSSCHECK_OUTPUT(output, float);
void crosscheck_output_case(Float32 *data)
{
    submit_output(output, data, 1, nullptr);
}

#elif CROSSCHECK_COMPILE_CASE == 22
CROSSCHECK_OUTPUT(output, Float64);
void crosscheck_output_case(double *data)
{
    submit_output(output, data, 1, nullptr);
}

#elif CROSSCHECK_COMPILE_CASE == 23
CROSSCHECK_OUTPUT(output, double);
void crosscheck_output_case(Float64 *data)
{
    submit_output(output, data, 1, nullptr);
}

#elif CROSSCHECK_COMPILE_CASE == 24
CROSSCHECK_OUTPUT(output, uint32_t);
void crosscheck_output_case(const std::vector<uint32_t> &data)
{
    submit_output(output, data);
}

#elif CROSSCHECK_COMPILE_CASE == 25
CROSSCHECK_OUTPUT(output, uint32_t);
void crosscheck_output_case(uint32_t *data)
{
    // A pointer/count submission still requires a fourth description argument.
    submit_output(output, data, 0);
}

#elif CROSSCHECK_COMPILE_CASE == 26
namespace { struct Opaque { uint32_t value; }; }
CROSSCHECK_OUTPUT(output, uint32_t);
void crosscheck_output_case(const std::vector<Opaque> &data)
{
    submit_output(output, data, nullptr);
}

#elif CROSSCHECK_COMPILE_CASE == 27
CROSSCHECK_OUTPUT(output, uint32_t);
void crosscheck_output_case(const std::vector<std::vector<uint32_t>> &data)
{
    submit_output(output, data, nullptr);
}

#elif CROSSCHECK_COMPILE_CASE == 28 || CROSSCHECK_COMPILE_CASE == 29
#ifdef __SIZEOF_FLOAT128__
#  define CROSSCHECK_NATIVE __float128
#  define CROSSCHECK_WRAPPER Float128
#else
#  define CROSSCHECK_NATIVE float
#  define CROSSCHECK_WRAPPER Float32
#endif
#if CROSSCHECK_COMPILE_CASE == 28
CROSSCHECK_OUTPUT(output, CROSSCHECK_WRAPPER);
void crosscheck_output_case(CROSSCHECK_NATIVE *data)
{
    submit_output(output, data, 1, nullptr);
}
#else
CROSSCHECK_OUTPUT(output, CROSSCHECK_NATIVE);
void crosscheck_output_case(CROSSCHECK_WRAPPER *data)
{
    submit_output(output, data, 1, nullptr);
}
#endif

#elif CROSSCHECK_COMPILE_CASE == 30 || CROSSCHECK_COMPILE_CASE == 31
#ifdef SANDSTONE_FP16_TYPE
#  define CROSSCHECK_NATIVE fp16_t
#  define CROSSCHECK_WRAPPER Float16
#else
#  define CROSSCHECK_NATIVE float
#  define CROSSCHECK_WRAPPER Float32
#endif
#if CROSSCHECK_COMPILE_CASE == 30
CROSSCHECK_OUTPUT(output, CROSSCHECK_WRAPPER);
void crosscheck_output_case(CROSSCHECK_NATIVE *data)
{
    submit_output(output, data, 1, nullptr);
}
#else
CROSSCHECK_OUTPUT(output, CROSSCHECK_NATIVE);
void crosscheck_output_case(CROSSCHECK_WRAPPER *data)
{
    submit_output(output, data, 1, nullptr);
}
#endif

#else
#  error "Unknown CROSSCHECK_COMPILE_CASE"
#endif
