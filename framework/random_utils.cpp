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
    decltype(G()) random_bits_value = 0;
    uint32_t random_bits_available = 0;

    static_assert(B <= 8 * sizeof(random_bits_value),
        "Generator cannot provide more bits than the generated type can hold");

    T val = 0;
    while (bits != 0) {
        if (random_bits_available == 0) {
            random_bits_value = G();
            random_bits_available = B;
        }
        uint32_t b = (bits <= random_bits_available) ? bits : random_bits_available;
        // shift by 8*sizeof(T) or more is undefined behavior! Number of available bits
        // might apply to all bits, while very first shift is never required.
        // Lets address "undefined behaviour" if wrong number of bits is requested
        // (either way, such cases should be prevented by assertions outside)
        // 1-step operations (e.g. 64b for uint64_t with 128b generator) works correctly.
        if (b < sizeof(T) * 8) {
            val <<= b;
        }

        // as random data is random.. no need to keep endianness in mind, we can just
        // store bits in any particular order
        val ^= T(random_bits_value & get_mask<T>(b));
        random_bits_available -= b;
        if (random_bits_available != 0) {
            random_bits_value >>= b;
        }
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

    // Compute the number of bits needed to represent values in [0, range - 1].
    uint32_t bits = sizeof(T) * 8 - std::countl_zero(range - 1);
    // to avoid biased results, try a few times with value rejection to get value in range
    // if not caught any "successful" value, just do biased modulo operation to avoid infinite loops
    // (especially with scenarios where RNG provides all-1s all the time, e.g. Constant:ffffffff)
    // it will be always hit for ranges of power of two, but a bit more than 50% for worst cases
    // (e.g. range=65). Having 7 tries should give uniformity better than 1%
    static constexpr int MAX_REJECTION_LOOPS = 7;
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

uint64_t get_random_bits31(uint32_t num_bits) {
    return get_random_bits<uint64_t, random, BITS_FROM_RANDOM>(num_bits);
}
uint64_t get_random_bits128(uint32_t num_bits) {
    return get_random_bits<uint64_t, random128, 128>(num_bits);
}

uint32_t get_random_value31(uint32_t range) {
    return get_random_value<uint32_t, random, BITS_FROM_RANDOM>(range);
}

void *memset_random(void *buf, size_t n)
{
    if (n <= sizeof(uint64_t)) {
        if (n > sizeof(uint32_t)) {
            uint64_t v = random64();
            return memcpy(buf, &v, n);
        }

        uint32_t v = random32();
        return memcpy(buf, &v, n);
    }

    __uint128_t v = random128();
    if (n < sizeof(v))
        return memcpy(buf, &v, n);

    uint8_t *ptr = static_cast<uint8_t *>(buf);
    uint8_t *end = ptr + n;
    while (end - ptr > sizeof(v)) {
        memcpy(ptr, &v, sizeof(v));
        v = random128();
        ptr += sizeof(v);
    }

    if (end - ptr)
        memcpy(end - sizeof(v), &v, sizeof(v));

    return buf;
}

uint64_t set_random_bits(unsigned num_bits_to_set, uint32_t bitwidth) {
    if (num_bits_to_set >= 64 && bitwidth >= 64)
        return 0xFFFFFFFFFFFFFFFF;  // can't be handled by shifting and subtracting :-(
    else if (num_bits_to_set >= bitwidth || num_bits_to_set >= 64)
        return (1ul << bitwidth) - 1ul;

    // Create a list of all possible bits we could set (basically 1 .. bitwidth)
    uint32_t bit_positions[64];
    for(unsigned i=0; i < bitwidth; i++) {
        bit_positions[i] = i;
    }


    uint64_t value = 0;
    uint32_t num_unset_bits = bitwidth;
    while (num_bits_to_set > 0) {

        // pick a bit position from the bit_positions array for what
        // we have left in the list to select as indicated by num_unset_bits
        int idx_of_bit_to_set = random32() % num_unset_bits;
        uint32_t bitpos_to_set = bit_positions[idx_of_bit_to_set];

        // set the bit
        value |= UINT64_C(1) << bitpos_to_set; // set the bit

        // remove the selected bit from the list and shorten the list by 1
        // If we remove the last entry, shortening the list is removing it
        // otherwise we swap the last entry in bit_positions with the one
        // we just selected, the shorten the list
        if (idx_of_bit_to_set < num_unset_bits - 1)
            bit_positions[idx_of_bit_to_set] = bit_positions[num_unset_bits - 1];

        num_unset_bits -= 1;  // shortens the list by 1
        num_bits_to_set--;    // loop count
    }
    return value;
}

#ifdef SANDSTONE_UNITTESTS
// Random.cpp patterns for unit tests, identical with LCG engine.
// Do not allow to reimplement these for unit tests.
__attribute__((weak)) __uint128_t random128() {
    union {
        struct {
            __uint128_t b1 : 24;
            __uint128_t b2 : 24;
            __uint128_t b3 : 16;
            __uint128_t b4 : 24;
            __uint128_t b5 : 24;
            __uint128_t b6 : 16;
        };
        __uint128_t v;
    } f;
    static_assert(sizeof(f) == sizeof(__uint128_t), "Wrong size of the uint128_t union");
    f.b1 = random();
    f.b2 = random();
    f.b3 = random();
    f.b4 = random();
    f.b5 = random();
    f.b6 = random();
    return f.v;
}

__attribute__((weak)) uint64_t random64() {
    union {
        struct {
            uint64_t b1 : 24;
            uint64_t b2 : 24;
            uint64_t b3 : 16;
        };
        uint64_t v;
    } f;
    static_assert(sizeof(f) == sizeof(uint64_t), "Wrong size of the uint64_t union");
    f.b1 = random();
    f.b2 = random();
    f.b3 = random();
    return f.v;
}

__attribute__((weak)) uint32_t random32() {
    union {
        struct {
            uint32_t b1 : 16;
            uint32_t b2 : 16;
        };
        uint32_t v;
    } f;
    static_assert(sizeof(f) == sizeof(uint32_t), "Wrong size of the uint32_t union");
    f.b1 = random();
    f.b2 = random();
    return f.v;
}
#endif // SANDSTONE_UNITTESTS

} // extern "C"
