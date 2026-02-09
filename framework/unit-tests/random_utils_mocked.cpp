/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sandstone.h>

#ifndef SANDSTONE_UNITTESTS
#error This file is only for unit tests. Do not use it with the framework or tests.
#endif

/**
 * "Override" random functions to use in unit tests
 */
#include "random.cpp"
#include "random_utils.cpp"

#include <unit-tests/random_mocker.hpp>
#include <chrono>

namespace {

struct RandomEngineWithMock : public EngineWrapper<std::minstd_rand> {
    RandomEngineWithMock():
        EngineWrapper<std::minstd_rand>(LCG, 0)
    {
        // initialize the engine with time-based seed. The object is not fully constructed yet
        // "magic singleton" pattern will not work if any non-static method is called!
        uint64_t t = std::chrono::system_clock::now().time_since_epoch().count();
        SeedSequence sseq{
            static_cast<uint32_t>(t) ^ static_cast<uint32_t>(t >> 32),
            static_cast<uint32_t>(t >> 32),
            static_cast<uint32_t>(t),
            0x55aa55aa,
        };
        seedGlobalEngine(sseq);
    }

    long int generateInt(thread_rng* rng) override {
        if (RandomMocker::Mock<int>::get_instance()) {
            int val = RandomMocker::Mock<int>::get_instance()->get_value();
            if (val >= 0) {
                return val;
            }
        }
        int val = EngineWrapper<std::minstd_rand>::generateInt(rng);
        return val;
    }
    uint32_t generate32(thread_rng* rng) override {
        if (RandomMocker::Mock<uint32_t>::get_instance()) {
            return RandomMocker::Mock<uint32_t>::get_instance()->get_value();
        }
        return EngineWrapper<std::minstd_rand>::generate32(rng);
    }
    uint64_t generate64(thread_rng* rng) override {
        if (RandomMocker::Mock<uint64_t>::get_instance()) {
            return RandomMocker::Mock<uint64_t>::get_instance()->get_value();
        }
        return EngineWrapper<std::minstd_rand>::generate64(rng);
    }
    __uint128_t generate128(thread_rng* rng) override {
        if (RandomMocker::Mock<__uint128_t>::get_instance()) {
            return RandomMocker::Mock<__uint128_t>::get_instance()->get_value();
        }
        return EngineWrapper<std::minstd_rand>::generate128(rng);
    }

    // not very useful, just to verify get_random_bits<>
    uint64_t get_random_bits_8(thread_rng* rng, uint32_t bits);
    uint64_t get_random_bits_32(thread_rng* rng, uint32_t bits);
    uint64_t get_random_bits_128(thread_rng* rng, uint32_t bits);
};

static RandomEngineWrapper* random_engine(RandomEngineWrapper* e) {
    if (e != nullptr) {
        fprintf(stderr, "Unit tests are not intended to change the engine instance\n");
    }
    static RandomEngineWithMock engine{};
    return &engine;
}
static thread_rng* rng_for_thread(int) {
    static thread_rng rng{};
    return &rng;
}

uint64_t RandomEngineWithMock::get_random_bits_8(thread_rng* rng, uint32_t bits) {
    // let discard 24 bits from each mocked/fetched value, generate32/mock<uint32_t> is used.
    // The cache is 32 bits, so we can fetch up to 4 random values (8bit)
    return get_random_bits<uint64_t, &RandomEngineWrapper::generate32, 8, uint32_t>(rng, bits);
}
uint64_t get_random_bits_8(uint32_t bits) {
    return reinterpret_cast<RandomEngineWithMock*>(random_engine())->RandomEngineWithMock::get_random_bits_8(rng_for_thread(0), bits);
}
uint64_t RandomEngineWithMock::get_random_bits_32(thread_rng* rng, uint32_t bits) {
    return get_random_bits<uint64_t, &RandomEngineWrapper::generate32, 32, uint32_t>(rng, bits);
}
uint64_t get_random_bits_32(uint32_t bits) {
    return reinterpret_cast<RandomEngineWithMock*>(random_engine())->RandomEngineWithMock::get_random_bits_32(rng_for_thread(0), bits);
}
uint64_t RandomEngineWithMock::get_random_bits_128(thread_rng* rng, uint32_t bits) {
    return get_random_bits<uint64_t, &RandomEngineWrapper::generate128, 128, __uint128_t>(rng, bits);
}
uint64_t get_random_bits_128(uint32_t bits) {
    return reinterpret_cast<RandomEngineWithMock*>(random_engine())->RandomEngineWithMock::get_random_bits_128(rng_for_thread(0), bits);
}

RandomBitsAlgo get_random_bits_algo(void) {
    return *reinterpret_cast<RandomBitsAlgo*>(&(rng_for_thread(0)->u8[sizeof(thread_rng) - sizeof(uint32_t) - 1]));
}
uint32_t get_random_bits_available(void) {
    return rng_for_thread(0)->u32[sizeof(thread_rng) / sizeof(uint32_t) - 1];
}


} // anonymous namespace

namespace RandomMocker {

template<typename T>
IMock<T>::~IMock() {
    if (instance == this) {
        // discard cache state in rng
        size_t state_size = random_engine()->stateSize();
        memset(&thread_local_rng()->u8[state_size], 0, sizeof(*thread_local_rng()) - state_size);
        instance = nullptr;
    }
}

template<>
IMock<__uint128_t>* IMock<__uint128_t>::instance = nullptr;
template<>
IMock<uint64_t>* IMock<uint64_t>::instance = nullptr;
template<>
IMock<uint32_t>* IMock<uint32_t>::instance = nullptr;
template<>
IMock<int>* IMock<int>::instance = nullptr;

} // RandomMocker

/** @} */
