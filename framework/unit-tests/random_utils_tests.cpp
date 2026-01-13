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
    // prepare random()) values according experiment definition above
    std::vector<int> mocked_values{};
    for (const auto& v: values) {
        if ((v.first > 1) && (v.final || (v.first > v.second))) {
            mocked_values.push_back(v.second);
        }
    }

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
