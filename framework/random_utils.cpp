/*
 * Copyright 2022-2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"

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
    static std::mutex mutex{};
    static decltype(G()) random_bits_value = 0;
    static uint32_t random_bits_available = 0;
    static_assert(B <= 8 * sizeof(random_bits_value), "Generator is not able to provide B bits");

    std::lock_guard<std::mutex> lock(mutex);
    T val = 0;
    while (bits != 0) {
        if ((random_bits_available == 0) || (random_bits_available >= B)) {
            random_bits_value = G();
            random_bits_available = B;
        }
        int b = (bits <= random_bits_available) ? bits : random_bits_available;
        // shift by 8*sizeof(T) is undefined behavior! Number of available bits
        // might apply to all bits, while very first shift is never required
        if (val) {
            val <<= b;
        }
        val |= T(random_bits_value & get_mask<T>(b));
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
    static std::mutex mutex{};
    static T random_val_value = 0;
    static T random_val_available = 0;

    if (range <= 1) {
        return 0;
    }
    if constexpr (B < sizeof(T) * 8) {
        // if the generator provides less bits than the type size,
        // we cannot handle the full range
        assert((range <= get_mask<T>(B)) && "Large values are not supported");
    }

    std::lock_guard<std::mutex> lock(mutex);
    // with out-of-available-range values rejection
    if (random_val_available <= range) {
        random_val_value = G();
        random_val_available = get_mask<T>(B);
    }
    T val = random_val_value % range;
    random_val_available /= range;
    random_val_value /= range;
    return val;
}

} // anonymous namespace

extern "C" {

uint64_t get_random_bits31(uint32_t num_bits) {
    return get_random_bits<uint64_t, random, BITS_FROM_RANDOM>(num_bits);
}
uint64_t get_random_bits128(uint32_t num_bits) {
    // for AES it is far more efficient to use random128() instead of random()
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

} // extern "C"
