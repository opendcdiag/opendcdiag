/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gtest/gtest.h"
#ifdef SANDSTONE_DEVICE_CPU
#include <devicedeps/cpu/topology.h>
#endif
#include <initializer_list>

static LogicalProcessorSet make_set(std::initializer_list<LogicalProcessorSet::Word> list)
{
    LogicalProcessorSet result(list.size() * LogicalProcessorSet::ProcessorsPerWord);
    std::copy(list.begin(), list.end(), result.array.begin());
    return result;
}

TEST(LogicalProcessorSet, BasicOperations)
{
    auto lastProcessor = LogicalProcessor(LogicalProcessorSet::MinSize - 1);
    LogicalProcessorSet set;
    EXPECT_EQ(set.size_bytes(), 0);
    EXPECT_EQ(set.count(), 0);
    EXPECT_FALSE(set.is_set(LogicalProcessor(0)));
    EXPECT_FALSE(set.is_set(LogicalProcessor(1)));
    EXPECT_FALSE(set.is_set(lastProcessor));
    EXPECT_EQ(set.size_bytes(), 0);

    set.set(LogicalProcessor(0));
    EXPECT_NE(set.size_bytes(), 0);
    EXPECT_EQ(set.count(), 1);
    EXPECT_TRUE(set.is_set(LogicalProcessor(0)));
    EXPECT_FALSE(set.is_set(LogicalProcessor(1)));
    EXPECT_FALSE(set.is_set(lastProcessor));

    set.unset(LogicalProcessor(0));
    EXPECT_EQ(set.count(), 0);
    EXPECT_FALSE(set.is_set(LogicalProcessor(0)));
    EXPECT_FALSE(set.is_set(LogicalProcessor(1)));
    EXPECT_FALSE(set.is_set(lastProcessor));

    set.set(lastProcessor);
    EXPECT_EQ(set.count(), 1);
    EXPECT_FALSE(set.is_set(LogicalProcessor(0)));
    EXPECT_FALSE(set.is_set(LogicalProcessor(1)));
    EXPECT_TRUE(set.is_set(lastProcessor));

    std::fill(set.array.begin(), set.array.end(), -1);
    EXPECT_EQ(set.count(), set.array.size() * LogicalProcessorSet::ProcessorsPerWord);
}

TEST(LogicalProcessorSet, LargeSet)
{
    {
        auto largeProcessor = LogicalProcessor(LogicalProcessorSet::MinSize);
        LogicalProcessorSet set;
        EXPECT_EQ(set.size_bytes(), 0);
        EXPECT_FALSE(set.is_set(largeProcessor));
        EXPECT_EQ(set.size_bytes(), 0);
        set.set(largeProcessor);
        EXPECT_NE(set.size_bytes(), 0);
        EXPECT_GT(set.size_bytes(), LogicalProcessorSet::MinSize / LogicalProcessorSet::ProcessorsPerWord);
        EXPECT_TRUE(set.is_set(largeProcessor));
        EXPECT_FALSE(set.is_set(LogicalProcessor(0)));
    }

    {
        auto largeProcessor = LogicalProcessor(LogicalProcessorSet::MinSize * 2);
        LogicalProcessorSet set;
        EXPECT_FALSE(set.is_set(largeProcessor));
        set.set(largeProcessor);
        EXPECT_TRUE(set.is_set(largeProcessor));
        EXPECT_FALSE(set.is_set(LogicalProcessor(0)));
    }

    {
        auto largeProcessor = LogicalProcessor(32768);
        LogicalProcessorSet set;
        EXPECT_FALSE(set.is_set(largeProcessor));
        set.set(largeProcessor);
        EXPECT_TRUE(set.is_set(largeProcessor));
        EXPECT_FALSE(set.is_set(LogicalProcessor(0)));
    }
}

TEST(LogicalProcessorSet, FromAmbient)
{
    LogicalProcessorSet set = make_set({0xf});
    EXPECT_EQ(set.count(), 4);
    EXPECT_TRUE(set.is_set(LogicalProcessor(0)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(1)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(2)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(3)));
    EXPECT_FALSE(set.is_set(LogicalProcessor(4)));
    EXPECT_FALSE(set.is_set(LogicalProcessor(5)));
    EXPECT_FALSE(set.is_set(LogicalProcessor(6)));
    EXPECT_FALSE(set.is_set(LogicalProcessor(7)));

    set = make_set({ uint64_t(-1) });
    EXPECT_EQ(set.count(), 64);
    EXPECT_TRUE(set.is_set(LogicalProcessor(0)));
    EXPECT_FALSE(set.is_set(LogicalProcessor(64)));

    set = make_set({ uint64_t(-1), uint32_t(-1) });
    EXPECT_EQ(set.count(), 96);
    EXPECT_TRUE(set.is_set(LogicalProcessor(0)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(64)));
    EXPECT_FALSE(set.is_set(LogicalProcessor(96)));

    set = make_set({0x55});
    EXPECT_EQ(set.count(), 4);
    EXPECT_TRUE(set.is_set(LogicalProcessor(0)));
    EXPECT_FALSE(set.is_set(LogicalProcessor(1)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(2)));
    EXPECT_FALSE(set.is_set(LogicalProcessor(3)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(4)));
    EXPECT_FALSE(set.is_set(LogicalProcessor(5)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(6)));
    EXPECT_FALSE(set.is_set(LogicalProcessor(7)));

    set = make_set({0xf, 0xf, 0xf, 0xf});
    EXPECT_EQ(set.count(), 16);
    EXPECT_TRUE(set.is_set(LogicalProcessor(0)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(1)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(2)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(3)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(64)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(65)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(66)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(67)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(128)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(129)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(130)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(131)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(192)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(193)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(194)));
    EXPECT_TRUE(set.is_set(LogicalProcessor(195)));
}

TEST(LogicalProcessorSet, ApplyLimit)
{
    LogicalProcessorSet set = make_set({0xf});
    EXPECT_EQ(set.count(), 4);
    set.limit_to(64);
    EXPECT_EQ(set.array[0], 0xf);
    set.limit_to(4);
    EXPECT_EQ(set.array[0], 0xf);
    set.limit_to(3);
    EXPECT_EQ(set.array[0], 0x7);
    set.limit_to(2);
    EXPECT_EQ(set.array[0], 0x3);
    set.limit_to(1);
    EXPECT_EQ(set.array[0], 0x1);

    set = make_set({0xf});
    set.limit_to(1);
    EXPECT_EQ(set.array[0], 0x1);

    set = make_set({ uint64_t(-1) });
    EXPECT_EQ(set.count(), 64);
    set.limit_to(127);
    EXPECT_EQ(set.array[0], uint64_t(-1));
    set.limit_to(64);
    EXPECT_EQ(set.array[0], uint64_t(-1));
    set.limit_to(4);
    EXPECT_EQ(set.array[0], 0xf);

    set = make_set({ uint64_t(-1), uint32_t(-1) });
    EXPECT_EQ(set.count(), 96);
    set.limit_to(127);
    EXPECT_EQ(set.array[0], uint64_t(-1));
    EXPECT_EQ(set.array[1], uint32_t(-1));
    set.limit_to(64);
    EXPECT_EQ(set.array[0], uint64_t(-1));
    EXPECT_EQ(set.array[1], 0);
    set.limit_to(4);
    EXPECT_EQ(set.array[0], 0xf);
    EXPECT_EQ(set.array[1], 0);

    set = make_set({ uint64_t(-1), uint32_t(-1) });
    set.limit_to(63);
    EXPECT_EQ(set.array[0], uint64_t(-1) >> 1);
    EXPECT_EQ(set.array[1], 0);

    set = make_set({ uint64_t(-1), uint64_t(-1) });
    EXPECT_EQ(set.count(), 128);
    set.limit_to(255);
    EXPECT_EQ(set.array[0], uint64_t(-1));
    EXPECT_EQ(set.array[1], uint64_t(-1));
    set.limit_to(128);
    EXPECT_EQ(set.array[0], uint64_t(-1));
    EXPECT_EQ(set.array[1], uint64_t(-1));
    set.limit_to(64);
    EXPECT_EQ(set.array[0], uint64_t(-1));

    set = make_set({0x55});
    EXPECT_EQ(set.count(), 4);
    set.limit_to(4);
    EXPECT_EQ(set.array[0], 0x55);
    set.limit_to(3);
    EXPECT_EQ(set.array[0], 0x15);
    set.limit_to(2);
    EXPECT_EQ(set.array[0], 0x5);
    set.limit_to(1);
    EXPECT_EQ(set.array[0], 0x1);

    set = make_set({0x55});
    set.limit_to(2);
    EXPECT_EQ(set.array[0], 0x5);

    set = make_set({0xaa});
    EXPECT_EQ(set.count(), 4);
    set.limit_to(4);
    EXPECT_EQ(set.array[0], 0xaa);
    set.limit_to(3);
    EXPECT_EQ(set.array[0], 0x2a);
    set.limit_to(2);
    EXPECT_EQ(set.array[0], 0xa);
    set.limit_to(1);
    EXPECT_EQ(set.array[0], 0x2);

    set = make_set({ UINT64_C(0x5555'5555'5555'5555) });
    EXPECT_EQ(set.count(), 32);
    set.limit_to(64);
    EXPECT_EQ(set.array[0], UINT64_C(0x5555'5555'5555'5555));
    set.limit_to(32);
    EXPECT_EQ(set.array[0], UINT64_C(0x5555'5555'5555'5555));
    set.limit_to(16);
    EXPECT_EQ(set.array[0], UINT64_C(0x5555'5555));

    set = make_set({ UINT64_C(0xaaaa'aaaa'aaaa'aaaa) });
    EXPECT_EQ(set.count(), 32);
    set.limit_to(64);
    EXPECT_EQ(set.array[0], UINT64_C(0xaaaa'aaaa'aaaa'aaaa));
    set.limit_to(32);
    EXPECT_EQ(set.array[0], UINT64_C(0xaaaa'aaaa'aaaa'aaaa));
    set.limit_to(16);
    EXPECT_EQ(set.array[0], UINT64_C(0xaaaa'aaaa));

    set = make_set({ 1, 1, 1, 0xf, 1 });
    EXPECT_EQ(set.count(), 8);
    set.limit_to(7);
    EXPECT_EQ(set.array[0], 0x1);
    EXPECT_EQ(set.array[1], 0x1);
    EXPECT_EQ(set.array[2], 0x1);
    EXPECT_EQ(set.array[3], 0xf);
    EXPECT_EQ(set.array[4], 0);

    set = make_set({ 1, 1, 1, 0xf, 1 });
    set.limit_to(6);
    EXPECT_EQ(set.array[0], 0x1);
    EXPECT_EQ(set.array[1], 0x1);
    EXPECT_EQ(set.array[2], 0x1);
    EXPECT_EQ(set.array[3], 0x7);
    EXPECT_EQ(set.array[4], 0);
}
