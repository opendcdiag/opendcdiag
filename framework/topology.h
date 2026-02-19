/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_TOPOLOGY_H
#define INC_TOPOLOGY_H

#include <bit>
#include <memory>
#include <limits>
#include <span>
#include <string>
#include <vector>

#include <assert.h>
#include <stdint.h>

#include "gettid.h"

enum class RescheduleMode : int8_t {
    none    = 0,
    queue,
    barrier,
    random,
};

class DeviceScheduler {
public:
    virtual ~DeviceScheduler() = default;
    virtual void reschedule_to_next_device() = 0;
    virtual void finish_reschedule() = 0;
};

std::unique_ptr<DeviceScheduler> make_rescheduler(RescheduleMode mode);

using PerThreadFailures = std::vector<__uint128_t>;

struct DeviceRange
{
    // a contiguous range
    int starting_device;
    int device_count;
};

enum class LogicalProcessor : int { None = -1 };

struct LogicalProcessorSetOps
{
    using Word = unsigned long long;
    static constexpr int ProcessorsPerWord = std::numeric_limits<Word>::digits;

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
        size_t idx = int(n) / ProcessorsPerWord;
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

    // Returns the number of the next processor set in this set, -1 if none.
    // The @a from parameter indicates which one to start from
    LogicalProcessor next(LogicalProcessor from = {}) const
    {
        size_t i = size_t(from) / ProcessorsPerWord;
        if (i >= array.size())
            return LogicalProcessor(-1);

        if (unsigned n = size_t(from) % ProcessorsPerWord) {
            // is any bit set in this Word higher than or equal to from's?
            if (Word word = array[i] & (Word(-1) << n))
                return LogicalProcessor(i * ProcessorsPerWord + std::countr_zero(word));
            ++i;
        }

        // find Word with a bit set
        for ( ; i < array.size(); ++i) {
            if (array[i] == 0)
                continue;

            return LogicalProcessor(i * ProcessorsPerWord + std::countr_zero(array[i]));
        }
        return LogicalProcessor(-1);
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
bool pin_thread_to_logical_processor(LogicalProcessor n, tid_t thread_id, const char *thread_name = nullptr);
bool pin_to_logical_processors(DeviceRange, const char *thread_name);

void apply_deviceset_param(const char *param);
void slice_plan_init(int max_cores_per_slice);

template <typename EnabledDevices>
EnabledDevices detect_devices();

template <typename EnabledDevices>
void setup_devices(const EnabledDevices& enabled_devices);

void restrict_topology(DeviceRange range);
void rebuild_topology();
void analyze_test_failures_for_topology(const struct test *test, const PerThreadFailures &per_thread_failures);
std::string build_failure_mask_for_topology(const struct test* test);

void print_temperature_of_device();

template <typename... Args> constexpr uint32_t scramble(Args ...args)
{
    // Create a pattern based exclusively on the topology that we'll use
    // to seed the thread's generator. Algorithm very loosely inspired by
    // https://en.wikipedia.org/wiki/MurmurHash version 3.
    uint32_t r = 0;
    auto scramble = [](uint32_t &r, uint32_t k) {
        k *= 0xcc9e2d51;
        k = std::rotl(k, 15);
        k *= 0x1b873593;
        k = r ^= k;
        r = std::rotl(r, 13);
        r = r * 5 + 0xe6546b64;
        return k;
    };
    return (scramble(r, args), ...);
}
uint32_t mixin_from_device_info(int thread_num);

#endif /* INC_TOPOLOGY_H */
