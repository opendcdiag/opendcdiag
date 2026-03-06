/*
 * Copyright 2022-2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"
#include <bit>

// TODO move it to random.cpp

namespace {

template<typename T, typename R, int MAX_REJECTION_LOOPS>
T get_random_value(R range) {
    assert((range > 0) && "Range must be a positive non-zero value");

    // do not even fetch anything for ranges less than 1 (negative ranges of signed types are not handled too)
    if (range <= 1) {
        return 0;
    }

    // Compute the number of bits needed to represent values in [0, range - 1].
    uint32_t bits = sizeof(R) * 8 - std::countl_zero(range - 1);
    if constexpr (MAX_REJECTION_LOOPS > 0) {
        for (int loop = 0; loop < MAX_REJECTION_LOOPS; loop++) {
            T val = get_random_bits(bits);
            if (val < range) {
                return val;
            }
        }
    }
    return get_random_bits(bits) % range;
}

} // anonymous namespace

extern "C" {

uint32_t get_random_value(uint32_t range) {
    // to avoid biased results, try a few times with value rejection to get value in range
    // if not caught any "successful" value, just do biased modulo operation to avoid infinite loops
    // (especially with scenarios where RNG provides all-1s all the time, e.g. Constant:ffffffff)
    // it will be always hit for ranges of power of two, but a bit more than 50% for worst cases
    // (e.g. range=65). Having 7 tries should result in uniformity better than 1%
    return get_random_value<uint32_t, uint32_t, 7>(range);
}

} // extern "C"
