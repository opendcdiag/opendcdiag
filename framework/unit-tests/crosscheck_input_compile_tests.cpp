/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

// Compile each case separately; only case 0 must compile. Do not link this file.
#include "crosscheck.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <list>
#include <span>
#include <type_traits>
#include <vector>

#ifndef CROSSCHECK_COMPILE_CASE
#  define CROSSCHECK_COMPILE_CASE 0
#endif

#if CROSSCHECK_COMPILE_CASE == 0

#define DECLARE_CONTROL_INPUT(ctype, tag, suffix) \
    CROSSCHECK_INPUT(control_##suffix, ctype);
SANDSTONE_SCALAR_TYPES(DECLARE_CONTROL_INPUT)
#undef DECLARE_CONTROL_INPUT

#define CHECK_CONTROL_INPUT(ctype, tag, suffix) \
    void crosscheck_compile_control_##suffix(ctype *data, const ctype *constant, size_t count) \
    { \
        set_input(control_##suffix, data, count, "mutable pointer"); \
        set_input(control_##suffix, constant, count); \
        const auto view = get_input(control_##suffix); \
        static_assert(std::is_same_v<decltype(view), const std::span<const ctype>>); \
        const ctype *read_data = view.data(); \
        size_t read_count = view.size(); \
        (void)read_data; \
        (void)read_count; \
    }
SANDSTONE_SCALAR_TYPES(CHECK_CONTROL_INPUT)
#undef CHECK_CONTROL_INPUT

CROSSCHECK_INPUT(wrapper_float32, Float32);
CROSSCHECK_INPUT(wrapper_float64, Float64);
void crosscheck_compile_wrappers(const Float32 *single, const Float64 *wide)
{
    set_input(wrapper_float32, single, 1);
    set_input(wrapper_float64, wide, 1);
}

CROSSCHECK_INPUT(range_input, uint32_t);
void crosscheck_compile_ranges()
{
    uint32_t raw[] = {1, 2};
    const std::array<uint32_t, 2> array = {1, 2};
    const std::vector<uint32_t> vector = {1, 2};
    std::span<uint32_t> mutable_span(raw);
    std::span<const uint32_t> constant_span(raw);
    set_input(range_input, raw);
    set_input(range_input, raw, 0);
    set_input(range_input, raw, 2);
    set_input(range_input, raw, nullptr);
    set_input(range_input, array, "array");
    set_input(range_input, vector);
    set_input(range_input, mutable_span);
    set_input(range_input, constant_span);
    auto view = get_input(range_input);
    static_assert(std::is_same_v<decltype(view), std::span<const uint32_t>>);
    (void)view;
}

#elif CROSSCHECK_COMPILE_CASE == 1
// Wrong scalar width.
CROSSCHECK_INPUT(input, uint32_t);
void crosscheck_compile_case(uint16_t *data)
{
    set_input(input, data, 1, nullptr);
}

#elif CROSSCHECK_COMPILE_CASE == 2
// Same DataType, different element type: bool is not uint8_t.
CROSSCHECK_INPUT(input, uint8_t);
void crosscheck_compile_case(bool *data)
{
    set_input(input, data, 1, nullptr);
}

#elif CROSSCHECK_COMPILE_CASE == 3
// Check the reverse direction of the same-DataType mismatch too.
CROSSCHECK_INPUT(input, bool);
void crosscheck_compile_case(uint8_t *data)
{
    set_input(input, data, 1, nullptr);
}

#elif CROSSCHECK_COMPILE_CASE == 4
// Wrong signedness.
CROSSCHECK_INPUT(input, uint32_t);
void crosscheck_compile_case(int32_t *data)
{
    set_input(input, data, 1, nullptr);
}

#elif CROSSCHECK_COMPILE_CASE == 5
CROSSCHECK_INPUT(input, uint32_t);
void crosscheck_compile_case(void *data)
{
    set_input(input, data, 1, nullptr);
}

#elif CROSSCHECK_COMPILE_CASE == 6
CROSSCHECK_INPUT(input, uint32_t);
void crosscheck_compile_case(volatile uint32_t *data)
{
    set_input(input, data, 1, nullptr);
}

#elif CROSSCHECK_COMPILE_CASE == 7
namespace { struct Opaque { uint32_t value; }; }
CROSSCHECK_INPUT(input, Opaque);

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
    set_input(input, data, 1, nullptr);
}

#elif CROSSCHECK_COMPILE_CASE == 12
CROSSCHECK_INPUT(input, bool);
void crosscheck_compile_case(const std::vector<bool> &data)
{
    set_input(input, data);
}

#elif CROSSCHECK_COMPILE_CASE == 13
CROSSCHECK_INPUT(input, uint32_t);
void crosscheck_compile_case(const std::list<uint32_t> &data)
{
    set_input(input, data);
}

#elif CROSSCHECK_COMPILE_CASE == 14
CROSSCHECK_INPUT(input, uint32_t);
void crosscheck_compile_case(std::span<volatile uint32_t> data)
{
    set_input(input, data);
}

#elif CROSSCHECK_COMPILE_CASE == 15
// A valid contiguous range, but its elements do not match the tag.
CROSSCHECK_INPUT(input, uint32_t);
void crosscheck_compile_case(const std::vector<uint16_t> &data)
{
    set_input(input, data);
}

#else
#  error "Unknown CROSSCHECK_COMPILE_CASE"
#endif
