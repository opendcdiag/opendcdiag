/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include <sandstone.h>
#include <bit>

// "overrides" for random functions including random_utils
#include <unit-tests/random_utils_mocked.cpp>

TEST(RandomUtils, random_sequence) {
    static constexpr size_t NUM_VALUES = 1000;
    uint32_t first = random();
    uint32_t same = 0;
    for (int i = 0; i < NUM_VALUES; i++) {
        if (random() == first) {
            same++;
        }
    }
    // if the seed is LCG:0, the same value will be generated every time
    EXPECT_LT(same, NUM_VALUES);
}

static bool second_mock(void) {
    RandomMocker::Mock<uint32_t> local_mock{{}};
    if (local_mock.all_values_used()) {
        return true;
    }
    return false;
}

TEST(RandomUtils, random_mocked) {
    RandomMocker::Mock<uint32_t> mock{{ 0x01234567U, 0x89abcdefU }};
    // cannot create second instance of the same mocker
    ASSERT_DEATH(second_mock(), "");

    EXPECT_EQ(random32(), 0x01234567U);
    EXPECT_FALSE(mock.all_values_used());
    EXPECT_EQ(random32(), 0x89abcdefU);
    EXPECT_TRUE(mock.all_values_used());
    // no more values
    ASSERT_DEATH(random32(), "");

    RandomMocker::Mock<uint64_t> mock64{{ 0x0123456789abcdefULL, }};
    EXPECT_EQ(random64(), 0x0123456789abcdefULL);
}

TEST(RandomUtils, get_random_bits) {
    {
        RandomMocker::Mock<int> mock_random{{}};
        EXPECT_EQ(get_random_bits(0), 0); // no bits fetched/consumed!
    }

    RandomMocker::Mock<int> mock_random{{ 0x12345678, 0x01234567, 0x79abcdef, 0x69696969, 0x5a5a5a5a, 0x54321059 }};
    // first value
    EXPECT_EQ(get_random_bits(8), 0x78);
    EXPECT_EQ(get_random_bits(8), 0x56);
    EXPECT_EQ(get_random_bits(8), 0x34);
    EXPECT_EQ(get_random_bits(7), 0x12);

    // second value
    EXPECT_EQ(get_random_bits(1), 0x01);
    EXPECT_EQ(get_random_bits(2), 0x03);
    EXPECT_EQ(get_random_bits(1), 0x00);

    EXPECT_EQ(get_random_bits(8), 0x56);

    EXPECT_EQ(get_random_bits(4), 0x04);
    EXPECT_EQ(get_random_bits(8), 0x23);
    // 24 bits consumed

    // 7 bits from second value, 17 bits from third
    EXPECT_EQ(get_random_bits(24), (0x01 & 0x7f) | ((0x79abcdef & 0x1ffff) << 7));

    // the rest of third value, no need to mask
    EXPECT_EQ(get_random_bits(14), (0x79abcdef >> 17));

    // do not even try to consume any bits!
    EXPECT_EQ(get_random_bits(0), 0x00);

    // long merge
    EXPECT_EQ(get_random_bits(64), 0x6d2d2d2d69696969ULL);
    // 2 bits from #5 consumed, 29 left

    EXPECT_EQ(get_random_bits(16), (0x54321059 >> 2) & 0xffff);
    EXPECT_EQ(get_random_bits(5), (0x54321059 >> 18) & 0x1f);

    // only 8 bits left, requesting more should fail
    // does ASSERT_DEATH internally use fork()? Internal state is **not** preserved after it,
    // therefore the bits available are kept after the call!
    EXPECT_DEATH(get_random_bits(9), "");
}

TEST(RandomUtils, get_random_bits_32) {
    RandomMocker::Mock<uint32_t> mock{{ 0x01234567, 0x89abcdef, 0xcbad }};
    // the cache is empty: fetch new value
    EXPECT_EQ(get_random_bits_32(4), 0x7);
    EXPECT_EQ(get_random_bits_algo(), RandomBitsAlgo::Temporary);
    EXPECT_EQ(get_random_bits_available(), 28);
    // in the cache there are 24 bits, just consume them
    EXPECT_EQ(get_random_bits_32(4), 0x6);
    EXPECT_EQ(get_random_bits_algo(), RandomBitsAlgo::Cached);
    EXPECT_EQ(get_random_bits_available(), 24);
    // additional bits from "temporary" cache are used
    EXPECT_EQ(get_random_bits_32(32), 0xef'012345);
    EXPECT_EQ(get_random_bits_algo(), RandomBitsAlgo::Temporary);
    EXPECT_EQ(get_random_bits_available(), 24);
    // too many bits requested, we need to assemble the value
    EXPECT_EQ(get_random_bits_32(36), 0xbad'89abcd);
    EXPECT_EQ(get_random_bits_algo(), RandomBitsAlgo::Assemble);
    EXPECT_EQ(get_random_bits_available(), 20);
    // some bits will be discarded! Next test should not see them!
}

TEST(RandomUtils, get_random_bits_8) {
    RandomMocker::Mock<uint32_t> mock{{ 0x12, 0x23, 0x34, 0x45, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 }};
    EXPECT_EQ(get_random_bits_8(4), 0x2);
    EXPECT_EQ(get_random_bits_algo(), RandomBitsAlgo::ExtendCache);
    EXPECT_EQ(get_random_bits_available(), 4);

    EXPECT_EQ(get_random_bits_8(8), 0x31);
    EXPECT_EQ(get_random_bits_algo(), RandomBitsAlgo::ExtendCache);
    EXPECT_EQ(get_random_bits_available(), 4);

    // two values must be added to the cache
    EXPECT_EQ(get_random_bits_8(17), 0x5'34'2);
    EXPECT_EQ(get_random_bits_algo(), RandomBitsAlgo::ExtendCache);
    EXPECT_EQ(get_random_bits_available(), 3);
    // empty the cache, 4>>1 = 2
    EXPECT_EQ(get_random_bits_8(3), 0x2);
    EXPECT_EQ(get_random_bits_algo(), RandomBitsAlgo::Cached);
    EXPECT_EQ(get_random_bits_available(), 0);

    EXPECT_EQ(get_random_bits_8(63), 0x0877665544332211ULL);
    EXPECT_EQ(get_random_bits_algo(), RandomBitsAlgo::Assemble);
    EXPECT_EQ(get_random_bits_available(), 1);

    EXPECT_EQ(get_random_bits_8(1), 0x1);
    EXPECT_EQ(get_random_bits_algo(), RandomBitsAlgo::Cached);
    EXPECT_EQ(get_random_bits_available(), 0);

    // the mock is empty
    EXPECT_DEATH(get_random_bits_8(1), "");
}

TEST(RandomUtils, get_random_bits_128) {
    static auto get128 = [](uint64_t low, uint64_t high) -> __uint128_t {
        return __uint128_t(low) | (__uint128_t(high) << 64);
    };
    RandomMocker::Mock<__uint128_t> mock{{
        get128(0x0123456789abcdefULL, 0xfedcba9876543210ULL),
        get128(0x0011223344556677ULL, 0x8899aabbccddeeffULL),
    }};
    EXPECT_EQ(get_random_bits_128(16), 0xcdef);
    EXPECT_EQ(get_random_bits_algo(), RandomBitsAlgo::Temporary);
    EXPECT_EQ(get_random_bits_available(), 112);

    EXPECT_EQ(get_random_bits_128(64), 0x3210'0123456789abULL);
    EXPECT_EQ(get_random_bits_algo(), RandomBitsAlgo::Cached);
    EXPECT_EQ(get_random_bits_available(), 48);

    EXPECT_EQ(get_random_bits_128(40), 0xdcba987654ULL);
    EXPECT_EQ(get_random_bits_algo(), RandomBitsAlgo::Cached);
    EXPECT_EQ(get_random_bits_available(), 8);

    EXPECT_EQ(get_random_bits_128(16), 0x77'feULL);
    EXPECT_EQ(get_random_bits_algo(), RandomBitsAlgo::Temporary);
    EXPECT_EQ(get_random_bits_available(), 120);

    // uint64 is not able to hold 80 bits
    EXPECT_DEATH(get_random_bits_128(80), "");
}

TEST(RandomUtils, get_random_value) {
    // "pairs" of (range, "random" result)
    struct ValueToMock {
        uint32_t range;
        uint32_t result;
        bool forced = false;
    };
    std::initializer_list<ValueToMock> values = {
        // first set
        { 2, 1 },  // 0+1
        { 4, 2 },  // 1+2
        { 5, 1 },  // 3+3
        { 10, 3 }, // 6+4
        { 3, 1 },  // 10+2
        { 8, 1 },  // 12+3
        { 7, 6 },  // 15+3
        { 9, 3 },  // 18+4
        { 1, 0 },  // nasty case, doesn't use any bits from random()
        { 16, 4 }, // 22+4
        { 2, 1 },  // 26+1
        { 32, 3 }, // 27+5, 1 bit in next random()
        { 5, 4 },  // 32+3
        { 123, 2 },// 35+7
        { 64, 10 },// 42+6
        { 100, 69 },//48+7
        { 8, 5 },  // 55+3
        { 69, 6 }, // 58+7, 3 bits in next random()
        { 3, 0 },  // 65+2
        { 4, 3 },  // 67+2
        { 2, 1 },  // 69+1
        { 9, 8 },  // 70+4
        { 10, 11 }, //74+4 sample rejection case, 7 times plus modulo
        { 10, 12 }, //78+4
        { 10, 13 }, //82+4
        { 10, 14 }, //86+4
        { 10, 15 }, //90+4, 3 bits in next random()
        { 10, 11 }, //94+4
        { 10, 12 }, //98+4 last try before modulo
        { 10, 13, true }, //102+4, 8th try to get value with a modulo operation
        { 20, 24 }, //106+5 // rejected value
        { 20, 19 }, //111+5 // but this is accepted one
        { 250, 25 },//116+8
                    // 124, no dangling bits
    };

    // prepare random() values according experiment definition above
    std::vector<int> mocked_values{};
    static constexpr uint32_t BITS_PER_RANDOM = 31;
    uint64_t value = 0;
    uint32_t bits_used = 0;
    for (auto v: values) {
        if (v.range > 1) {
            auto num_bits = [](uint32_t v) {
                return sizeof(uint32_t) * 8 - std::countl_zero(v);
            };
            // number of bits required to represent the result might be
            // smaller for ranges that are a power of two
            uint32_t bits = num_bits(v.range - 1);
            // verify the "test data"
            ASSERT_GT(bits, 0);
            ASSERT_GE(bits, num_bits(v.result));

            value |= v.result << bits_used;
            bits_used += bits;

            if (bits_used >= BITS_PER_RANDOM) {
                mocked_values.push_back(value & 0x7fffffff);
                bits_used -= BITS_PER_RANDOM;
                value >>= BITS_PER_RANDOM;
            }
        }
    }
    ASSERT_EQ(bits_used, 0);

    // and check all mocked random() values
    RandomMocker::Mock<int> mock_random{ mocked_values };
    EXPECT_EQ(get_random_value(1), 0); // always 0, no chunks consumed
    for (const auto& v: values) {
        if ((v.range > v.result)) {
            EXPECT_EQ(get_random_value(v.range), v.result);
        } else if (v.forced) {
            // 8th rejected value triggers modulo path
            EXPECT_EQ(get_random_value(v.range), v.result % v.range);
        }
    }

    // no more values available, the mock is empty too
    EXPECT_DEATH(get_random_value(2), "");
}

TEST(RandomUtils, get_random_value_uniformity) {
    std::vector<std::vector<uint64_t>> counts{};
    counts.push_back(std::vector<uint64_t>(2)); // 0 rejections
    counts.push_back(std::vector<uint64_t>(3)); // 1/4
    counts.push_back(std::vector<uint64_t>(5)); // 3/8
    counts.push_back(std::vector<uint64_t>(7)); // 1/8
    counts.push_back(std::vector<uint64_t>(11)); // 5/16
    counts.push_back(std::vector<uint64_t>(13)); // 3/16
    counts.push_back(std::vector<uint64_t>(23)); // 9/32
    counts.push_back(std::vector<uint64_t>(64)); // 0
    // average bits per value: 1 + 2 + 3 + 3 + 4 + 4 + 5 + 6 = 28 / 8 = 3.5 bits
    // each loop consumes 3 bits for selecting random counts (8 entries)
    // average rejection rate is (49/32)/8 = ~19%

    static constexpr size_t NUM_VALUES = 1'000'000ULL; // 125k per range
    static constexpr uint32_t BITS_PER_RANDOM = 31;
    static constexpr size_t NUM_RANDOM_CALLS = (6.5 * NUM_VALUES) / BITS_PER_RANDOM;


    std::vector<uint64_t> ranges(counts.size());
    // lets expect no fail is caught
    RandomMocker::Counting mock_random{};
    for (uint64_t loop = 0; loop < NUM_VALUES; loop++) {
        uint32_t index = get_random_value(counts.size());
        ASSERT_LT(index, counts.size());
        ranges[index]++;
        uint32_t range = counts[index].size();
        uint32_t r = get_random_value(range);
        ASSERT_LT(r, range);
        counts[index][r]++;
    }
    // expected is ~200k random() calls. Allow 20% for rejections and 1% for distribution variance
    EXPECT_GT(mock_random.get_count(), (NUM_RANDOM_CALLS / 1.01));
    EXPECT_LT(mock_random.get_count(), (NUM_RANDOM_CALLS * (1.20 * 1.01)));

    for (uint32_t index = 0; index < counts.size(); index++) {
        ASSERT_NE(ranges[index], 0);
        EXPECT_GT(ranges[index], (NUM_VALUES / counts.size()) / 1.01);
        EXPECT_LT(ranges[index], (NUM_VALUES / counts.size()) * 1.01);

        //#define OUTPUT_THE_DISTRIBUTION_STATS
        #ifdef OUTPUT_THE_DISTRIBUTION_STATS
        printf("range %d:", static_cast<int>(counts[index].size()));
        for (auto v : counts[index]) {
            double v_ratio = counts[index].size() * static_cast<double>(v) / ranges[index] - 1.0;
            printf(" %g", v_ratio);
        }
        printf(" (%ld values)\n", ranges[index]);
        #endif
    }
}
