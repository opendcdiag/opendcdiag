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

template<typename T, auto G, uint32_t B, int MAX_REJECTION_LOOPS = 7>
T get_random_value(T range) {
    assert((range > 0) && "Range must be a positive non-zero value");

    // do not even fetch anything for ranges less than 1 (negative ranges of signed types are not handled too)
    if (range <= 1) {
        return 0;
    }

    // Compute the number of bits needed to represent values in [0, range - 1].
    uint32_t bits = sizeof(T) * 8 - std::countl_zero(range - 1);
    // to avoid biased results, try a few times with value rejection to get value in range
    // if not caught any "successful" value, just do biased modulo operation to avoid infinite loops
    // (especially with scenarios where RNG provides all-1s all the time, e.g. Constant:ffffffff)
    // it will be always hit for ranges of power of two, but a bit more than 50% for worst cases
    // (e.g. range=65). Having 7 tries should result in uniformity better than 1%
    for (int loop = 0; loop < MAX_REJECTION_LOOPS; loop++) {
        T val = get_random_bits<T, G, B>(bits);
        if (val < range) {
            return val;
        }
    }
    return get_random_bits<T, G, B>(bits) % range;
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
