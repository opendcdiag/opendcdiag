/*
 * Copyright 2022-2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"
#include <bit>

namespace {

static constexpr uint32_t BITS_FROM_RANDOM = 31;

template<typename T>
constexpr T get_mask(uint32_t bits) {
    if (bits >= sizeof(T) * 8) {
        return T(~0);
    }
    return (static_cast<T>(1) << bits) - 1;
}

template<typename T, auto G, uint32_t B>
T get_random_bits(uint32_t bits) {
    static thread_local decltype(G()) random_bits_value = 0;
    static thread_local uint32_t random_bits_available = 0;

    static_assert(B <= 8 * sizeof(random_bits_value),
        "Generator cannot provide more bits than the generated type can hold");
    assert((bits <= sizeof(T) * 8) && "Number of bits requested must not be greater than in the type");

    T val = 0;
    uint32_t appended = 0;
    while (bits != 0) {
        if (random_bits_available == 0) {
            random_bits_available = B;
            random_bits_value = G();
        }
        uint32_t b = (bits <= random_bits_available) ? bits : random_bits_available;
        val |= (T(random_bits_value) & get_mask<T>(b)) << appended;
        random_bits_available -= b;
        random_bits_value >>= b;
        appended += b;
        bits -= b;
    }
    return val;
}

template<typename T, auto G, uint32_t B>
T get_random_value(T range) {
    assert((range > 0) && "Range must be a positive non-zero value");

    // do not even fetch anything for ranges less than 1 (negative ranges of signed types are not handled too)
    if (range <= 1) {
        return 0;
    }

    decltype(G()) random_bits_value = G();
    static_assert(B <= 8 * sizeof(random_bits_value),
        "Generator cannot provide more bits than the generated type can hold");
    assert((range <= get_mask<T>(B)) && "Range must be less than the number of possible values from the generator");

    // the simplest way to get a random value.. to be replaced with algo with rejections and optimized RNG usage
    return random_bits_value % range;
}

} // anonymous namespace

extern "C" {

uint64_t get_random_bits(uint32_t num_bits) {
    return get_random_bits<uint64_t, random, BITS_FROM_RANDOM>(num_bits);
}

uint32_t get_random_value(uint32_t range) {
    return get_random_value<uint32_t, random, BITS_FROM_RANDOM>(range);
}

} // extern "C"
