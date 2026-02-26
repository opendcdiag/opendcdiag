/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sandstone.h>

/**
 * "Override" random functions to use in unit tests
 */

#include <unit-tests/random_mocker.hpp>

// random() replacement to mock with <int>
extern "C" {
int random_lib() {
    return random();
}

#define random random_mocked
int random_mocked() {
    if (RandomMocker::Mock<int>::get_instance()) {
        return RandomMocker::Mock<int>::get_instance()->get_value();
    }
    return random_lib();
}
} // extern "C"

#include "random_utils.cpp"

extern "C" {
// Random.cpp patterns for unit tests, identical with LCG engine.
// Do not allow to reimplement these for unit tests.
__uint128_t random128() {
    if (RandomMocker::Mock<__uint128_t>::get_instance()) {
        return RandomMocker::Mock<__uint128_t>::get_instance()->get_value();
    }

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

uint64_t random64() {
    if (RandomMocker::Mock<uint64_t>::get_instance()) {
        return RandomMocker::Mock<uint64_t>::get_instance()->get_value();
    }

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

uint32_t random32() {
    if (RandomMocker::Mock<uint32_t>::get_instance()) {
        return RandomMocker::Mock<uint32_t>::get_instance()->get_value();
    }

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

} // extern "C"

namespace RandomMocker {

template<>
Mock<__uint128_t>* Mock<__uint128_t>::instance = nullptr;
template<>
Mock<uint64_t>* Mock<uint64_t>::instance = nullptr;
template<>
Mock<uint32_t>* Mock<uint32_t>::instance = nullptr;
template<>
Mock<int>* Mock<int>::instance = nullptr;

} // RandomMocker

/** @} */
