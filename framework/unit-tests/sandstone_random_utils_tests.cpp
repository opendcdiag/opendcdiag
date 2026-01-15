/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */


#include <gtest/gtest.h>
#include <sandstone.h>
#include <random_mock.hpp>


bool second_mock(void) {
    SandstoneRandomMocker<uint32_t> local_mock{{}};
    if (local_mock.all_values_used()) {
        return true;
    }
    return false;
}

// unit tests use LCG-like implementations
TEST(RandomUtils, random_mocked) {
    SandstoneRandomMocker<uint32_t> mock{{0x01234567U, 0x89abcdefU}};
    // cannot create second instance of the same mocker
    ASSERT_DEATH(second_mock(), "");

    EXPECT_EQ(random32(), 0x01234567U);
    EXPECT_FALSE(mock.all_values_used());
    EXPECT_EQ(random32(), 0x89abcdefU);
    EXPECT_TRUE(mock.all_values_used());
    // no more values
    ASSERT_DEATH(random32(), "");

    SandstoneRandomMocker<uint64_t> mock64{{0x0123456789abcdefULL}};
    EXPECT_EQ(random64(), 0x0123456789abcdefULL);
}

TEST(RandomUtils, get_random_bits) {
    {
        SandstoneRandomMocker<int> mock_random{};
        EXPECT_EQ(get_random_bits31(0), 0); // neither bit consumed!
    }

    SandstoneRandomMocker<int> mock_random{{ 0x12345678, 0x01234567, 0x79abcdef, 0x69696969, 0x1a5a5a5a, 0x54321059 }};
    // first value
    EXPECT_EQ(get_random_bits31(8), 0x78);
    EXPECT_EQ(get_random_bits31(8), 0x56);
    EXPECT_EQ(get_random_bits31(8), 0x34);
    EXPECT_EQ(get_random_bits31(7), 0x12);

    // second value
    EXPECT_EQ(get_random_bits31(1), 0x01);
    EXPECT_EQ(get_random_bits31(2), 0x03);
    EXPECT_EQ(get_random_bits31(1), 0x00);

    EXPECT_EQ(get_random_bits31(8), 0x56);

    EXPECT_EQ(get_random_bits31(4), 0x04);
    EXPECT_EQ(get_random_bits31(8), 0x23);

    // 7 bits from second value, 17 bits from third
    EXPECT_EQ(get_random_bits31(24), (0x01 << 17) | (0x79abcdef & 0x1ffff));
    // the rest of third value
    EXPECT_EQ(get_random_bits31(14), (0x79ab >> 1));

    // do not even try to consume any bits!
    EXPECT_EQ(get_random_bits31(0), 0x00);

    // long merge
    EXPECT_EQ(get_random_bits31(64), 0xd2d2d2d269696969ULL); // 2 bits form #5

    EXPECT_EQ(get_random_bits31(16), (0x54321059 >> 2) & 0xffff);
    EXPECT_EQ(get_random_bits31(5), (0x54321059 >> 18) & 0x1f);

    // only 8 bits left, requesting more should fail
    // does ASSERT_DEATH internally use fork()? Internal state is **not** preserved after it,
    // therefore the bits available are kept after the call!
    EXPECT_DEATH(get_random_bits31(9), "");
}

TEST(RandomUtils, get_random_value) {
    // "pairs" of (range, "random" result)
    std::vector<int> mocked_values{};
    std::initializer_list<std::pair<uint32_t, uint32_t>> values = {
        // first set
        { 2, 1 },
        { 4, 2 },
        { 5, 1 },
        { 10, 3 },
        { 3, 1 },
        { 8, 1 },
        { 7, 6 },
        { 9, 3 },
        { 1, 0 }, // nasty case, doesn't "consume" any bits from random()
        { 16, 4 },
        { 2, 1 },
        { 32, 3 },
        // "3" is still available, but less than needed for "5".. get second set
        { 5, 4 },
        { 123, 2 },
        { 8, 5 },
        { 69, 6 },
        { 3, 0 },
        { 4, 3 },
        { 2, 1 },
        { 263, 0 },
    };
    // prepare "random" values accoring expected values
    uint64_t value = 0;
    uint64_t multiplier = 1;
    for (auto v: values) {
        // the chunk will not fit 31 bits, add new set
        if (multiplier * v.first >= 0x80000000ULL) {
            mocked_values.push_back(value);
            multiplier = 1;
            value = 0;
        }
        value += multiplier * v.second;
        multiplier *= v.first;
    }
    mocked_values.push_back(value);

    SandstoneRandomMocker<int> mock_random{ mocked_values };
    EXPECT_EQ(get_random_value31(1), 0); // always 0, no chunks consumed
    for (auto v: values) {
        EXPECT_EQ(get_random_value31(v.first), v.second);
    }
    // no more values available, the mock is empty too
    EXPECT_DEATH(get_random_value31(2), "");
}
