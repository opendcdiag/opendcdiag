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

#include <unit-tests/random_utils_mock.hpp>

namespace {

struct RandomEngineWithMock : public EngineWrapper<std::minstd_rand> {
    RandomEngineWithMock():
        EngineWrapper<std::minstd_rand>(LCG, 0)
    {
        // initialize the engine with "seed" according the one passed to GTest or time-based one.
        SeedSequence sseq{};
        uint64_t state = ::testing::UnitTest::GetInstance()->random_seed();
        for (int i = 0; i < sseq.size(); ++i) {
            // generate pseudo-random values with "old" LCG params. It is different
            // than std::minstd_rand, but it doesn't matter as long as we have some
            // variability in the seed state for different runs.
            state = state * 1103515245ULL + 12345ULL;
            sseq[i] = static_cast<uint32_t>(state >> 16);
        }
        seedGlobalEngine(sseq);
        // the engine is not fully created yet, "magic singleton" instance is not set,
        // so we cannot use random_engine() here!
    }

    long int generateInt(thread_rng* rng) override {
        if (RandomMock::Values<int>::get_instance()) {
            int val = RandomMock::Values<int>::get_instance()->get_value();
            if (val >= 0) {
                return val;
            }
        }
        int val = EngineWrapper<std::minstd_rand>::generateInt(rng);
        return val;
    }
    uint32_t generate32(thread_rng* rng) override {
        if (RandomMock::Values<uint32_t>::get_instance()) {
            return RandomMock::Values<uint32_t>::get_instance()->get_value();
        }
        return EngineWrapper<std::minstd_rand>::generate32(rng);
    }
    uint64_t generate64(thread_rng* rng) override {
        if (RandomMock::Values<uint64_t>::get_instance()) {
            return RandomMock::Values<uint64_t>::get_instance()->get_value();
        }
        return EngineWrapper<std::minstd_rand>::generate64(rng);
    }
    __uint128_t generate128(thread_rng* rng) override {
        if (RandomMock::Values<__uint128_t>::get_instance()) {
            return RandomMock::Values<__uint128_t>::get_instance()->get_value();
        }
        return EngineWrapper<std::minstd_rand>::generate128(rng);
    }

    // not visible anywhere except random_utils_tests.cpp, just to verify get_random_bits<>
    uint64_t get_random_bits_8(thread_rng* rng, uint32_t bits);
    uint64_t get_random_bits_32(thread_rng* rng, uint32_t bits);
    uint64_t get_random_bits_128(thread_rng* rng, uint32_t bits);

    uint32_t get_random_bits_available(thread_rng* rng) {
        return *EngineWrapper<std::minstd_rand>::get_random_bits_available(rng);
    }
    RandomBitsAlgo get_random_bits_algo(thread_rng* rng) {
        return *EngineWrapper<std::minstd_rand>::get_random_bits_algo(rng);
    }
};

static void set_random_engine(RandomEngineWrapper* e) {
    assert(false && "Unit tests are not intended to change the engine instance");
}
static RandomEngineWrapper* random_engine(void) {
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
    return dynamic_cast<RandomEngineWithMock*>(random_engine())->RandomEngineWithMock::get_random_bits_8(rng_for_thread(0), bits);
}
uint64_t RandomEngineWithMock::get_random_bits_32(thread_rng* rng, uint32_t bits) {
    return get_random_bits<uint64_t, &RandomEngineWrapper::generate32, 32, uint32_t>(rng, bits);
}
uint64_t get_random_bits_32(uint32_t bits) {
    return dynamic_cast<RandomEngineWithMock*>(random_engine())->RandomEngineWithMock::get_random_bits_32(rng_for_thread(0), bits);
}
uint64_t RandomEngineWithMock::get_random_bits_128(thread_rng* rng, uint32_t bits) {
    return get_random_bits<uint64_t, &RandomEngineWrapper::generate128, 128, __uint128_t>(rng, bits);
}
uint64_t get_random_bits_128(uint32_t bits) {
    return dynamic_cast<RandomEngineWithMock*>(random_engine())->RandomEngineWithMock::get_random_bits_128(rng_for_thread(0), bits);
}

RandomBitsAlgo get_random_bits_algo(void) {
    return dynamic_cast<RandomEngineWithMock*>(random_engine())->RandomEngineWithMock::get_random_bits_algo(rng_for_thread(0));
}
uint32_t get_random_bits_available(void) {
    return dynamic_cast<RandomEngineWithMock*>(random_engine())->RandomEngineWithMock::get_random_bits_available(rng_for_thread(0));
}

} // anonymous namespace

namespace RandomMock {

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

} // RandomMock
