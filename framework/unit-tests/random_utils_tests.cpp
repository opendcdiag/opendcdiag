/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include <sandstone.h>
#include <bit>

// "overrides" for random functions including random_utils
#include <unit-tests/random_utils_mocked.cpp>

static bool second_mock(void) {
    RandomMocker::Mock<uint32_t> local_mock{{}};
    if (local_mock.all_values_used()) {
        return true;
    }
    return false;
}

TEST(RandomUtils, random_mocked) {
    RandomMocker::Mock<uint32_t> mock{{0x01234567U, 0x89abcdefU}};
    // cannot create second instance of the same mocker
    ASSERT_DEATH(second_mock(), "");

    EXPECT_EQ(random32(), 0x01234567U);
    EXPECT_FALSE(mock.all_values_used());
    EXPECT_EQ(random32(), 0x89abcdefU);
    EXPECT_TRUE(mock.all_values_used());
    // no more values
    ASSERT_DEATH(random32(), "");

    RandomMocker::Mock<uint64_t> mock64{{0x0123456789abcdefULL}};
    EXPECT_EQ(random64(), 0x0123456789abcdefULL);
}

TEST(RandomUtils, get_random_bits) {
    {
        RandomMocker::Mock<int> mock_random{{}};
        EXPECT_EQ(get_random_bits(0), 0); // neither bit consumed!
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
    //fprintf(stderr, "7bit: %lx\n", get_random_bits(7));
    //fprintf(stderr, "17bit: %lx\n", get_random_bits(17));
    EXPECT_EQ(get_random_bits(24), (0x01 & 0x7f) | ((0x79abcdef & 0x1ffff) << 7));

    // the rest of third value, no need to mask
    EXPECT_EQ(get_random_bits(14), (0x79abcdef >> 17));

    // do not even try to consume any bits!
    EXPECT_EQ(get_random_bits(0), 0x00);

    // long merge
    EXPECT_EQ(get_random_bits<uint64_t>(64), 0x6d2d2d2d69696969ULL);
    // 2 bits from #5 consumed, 29 left

    EXPECT_EQ(get_random_bits(16), (0x54321059 >> 2) & 0xffff);
    EXPECT_EQ(get_random_bits(5), (0x54321059 >> 18) & 0x1f);

    // only 8 bits left, requesting more should fail
    // does ASSERT_DEATH internally use fork()? Internal state is **not** preserved after it,
    // therefore the bits available are kept after the call!
    EXPECT_DEATH(get_random_bits(9), "");
}

TEST(RandomUtils, get_random_value) {
    // "pairs" of (range, "random" result)
    struct ValueToMock {
        uint32_t first; // range
        uint32_t second; // result
        bool final = false;
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
        { 10, 13, true }, //102+4 8th "final" value to get modulo
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
        if (v.first > 1) {
            auto num_bits = [](uint32_t v) {
                return sizeof(uint32_t) * 8 - std::countl_zero(v);
            };
            // number of bits required to represent the result might be
            // smaller for ranges that are a power of two
            uint32_t bits = num_bits(v.first - 1);
            // verify the "test data"
            ASSERT_GT(bits, 0);
            ASSERT_GE(bits, num_bits(v.second));

            value |= v.second << bits_used;
            bits_used += bits;

            if (bits_used >= BITS_PER_RANDOM) {
                bits_used -= BITS_PER_RANDOM;
                mocked_values.push_back(value & 0x7fffffff);
                value >>= BITS_PER_RANDOM;
            }
        }
    }
    ASSERT_EQ(bits_used, 0);

    // and check all mocked random() values
    RandomMocker::Mock<int> mock_random{ mocked_values };
    EXPECT_EQ(get_random_value(1), 0); // always 0, no chunks consumed
    for (const auto& v: values) {
        if ((v.first > v.second)) {
            EXPECT_EQ(get_random_value(v.first), v.second);
        } else if (v.final) {
            // 8th rejected value triggers modulo path
            EXPECT_EQ(get_random_value(v.first), v.second % v.first);
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

    static constexpr size_t NUM_VALUES = 1'000'000ULL;
    static constexpr uint32_t BITS_PER_RANDOM = 31;
    static constexpr size_t NUM_RANDOM_CALLS = (6.5 * NUM_VALUES) / BITS_PER_RANDOM;


    std::vector<uint64_t> ranges(counts.size());

    srandom(std::chrono::system_clock::now().time_since_epoch().count());
    struct urng {
        using result_type = int32_t;
        static constexpr result_type min() { return 0; };
        static constexpr result_type max() { return INT32_MAX; };
        result_type operator()() { return random(); };
    };
    std::shuffle(counts.begin(), counts.end(), urng{});

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
    // expected is ~200k random() calls. Allow 20% for rejectsions and 1% for distribution variance
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
