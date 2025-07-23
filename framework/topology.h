/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_TOPOLOGY_H
#define INC_TOPOLOGY_H

#include <sandstone.h>

#include <array>
#include <bit>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "gettid.h"

struct DeviceRange
{
    // a contiguous range
    int starting_device;
    int device_count;
};

enum class LogicalProcessor : int {};

struct LogicalProcessorSetOps
{
    using Word = unsigned long long;
    static constexpr int ProcessorsPerWord = CHAR_BIT * sizeof(Word);

    static constexpr Word bitFor(LogicalProcessor n)
    {
        return 1ULL << (unsigned(n) % ProcessorsPerWord);
    }

    static void setInArray(std::span<Word> array, LogicalProcessor n)
    {
        wordForInArray(array, n) |= bitFor(n);
    }

    static Word &wordForInArray(std::span<Word> array, LogicalProcessor n)
    {
        return array[int(n) / ProcessorsPerWord];
    }

    static Word constWordForInArray(std::span<const Word> array, LogicalProcessor n)
    {
        int idx = int(n) / ProcessorsPerWord;
        return idx < array.size() ? array[idx] : 0;
    }
};

class LogicalProcessorSet : private LogicalProcessorSetOps
{
    // a possibly non-contiguous range
public:
    using LogicalProcessorSetOps::Word;
    using LogicalProcessorSetOps::ProcessorsPerWord;
    static constexpr int MinSize = 1024;
    std::vector<Word> array;

    LogicalProcessorSet() noexcept = default;
    LogicalProcessorSet(int minimumSize)
    {
        ensureSize(minimumSize - 1);
    }

    void clear()
    {
        *this = LogicalProcessorSet{};
    }

    size_t size_bytes() const
    {
        return unsigned(array.size()) * sizeof(Word);
    }

    void set(LogicalProcessor n)
    {
        wordFor(n) |= bitFor(n);
    }

    void unset(LogicalProcessor n)
    {
        wordFor(n) &= ~bitFor(n);
    }

    bool is_set(LogicalProcessor n) const
    {
        return wordFor(n) & bitFor(n);
    }

    int count() const
    {
        int total = 0;
        for (const Word &w : array)
            total += std::popcount(w);
        return total;
    }

    bool empty() const
    {
        for (const Word &w: array)
            if (w)
                return false;
        return true;
    }

    void limit_to(int limit)
    {
        // find the first Word we need to change
        auto it = std::begin(array);
        for ( ; it != std::end(array) && limit > 0; ++it) {
            int n = std::popcount(*it);
            limit -= n;
        }

        if (limit < 0) {
            // clear enough upper bits on the last Word
            Word &x = it[-1];
            for ( ; limit < 0; ++limit) {
                Word bit = std::bit_floor(x);
                x &= ~bit;
            }
        }

        if (it != std::end(array))
            std::fill(it, std::end(array), 0);      // clear to the end
    }

private:
    void ensureSize(int n)
    {
        static_assert((MinSize % ProcessorsPerWord) == 0);
        static constexpr size_t MinSizeCount = MinSize / ProcessorsPerWord;
        size_t idx = size_t(n) / ProcessorsPerWord;
        if (idx >= array.size())
            array.resize(std::max(idx + 1, MinSizeCount));
    }

    Word &wordFor(LogicalProcessor n)
    {
        ensureSize(int(n));
        return wordForInArray(array, n);
    }

    Word wordFor(LogicalProcessor n) const noexcept
    {
        return constWordForInArray(array, n);
    }
};

LogicalProcessorSet ambient_logical_processor_set();
bool pin_to_logical_processor(LogicalProcessor, const char *thread_name = nullptr);
bool pin_to_logical_processors(DeviceRange, const char *thread_name);

void apply_deviceset_param(char *param);
void init_topology(const LogicalProcessorSet &enabled_cpus);
void restrict_topology(DeviceRange range);

#endif /* INC_TOPOLOGY_H */
