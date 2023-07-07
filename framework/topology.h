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
#include <string>
#include <vector>

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

class LogicalProcessorSet;

class Topology
{
public:

    // Thread corresponds to the OS CPU.
    struct Thread {
        int id; // thread id within the core (e.g. 0 or 1 for SMT)
        int cpu; // sandstone internal CPU id, e.g. tests get this identifier
        int oscpu; // logical CPU id, as reported and recognized by the OS
        Thread() noexcept : id(-1), cpu(-1), oscpu(-1) {}
    };

    struct Core {
        int id;
        std::vector<Thread> threads;
        Core() noexcept : id(-1) {}
    };

    struct Package {
        int id;
        std::vector<Core> cores;
        Package() noexcept : id(-1) {}
    };

    std::vector<Package> packages;

    Topology(std::vector<Package> pkgs) {
        packages = pkgs;
    }

    bool isValid() const        { return !packages.empty(); }
    std::string build_falure_mask(const struct test *test) const;

    static Topology topology();
};

enum class LogicalProcessor : int {};
class LogicalProcessorSet
{
public:
#if defined(__linux__) || defined(_WIN32)
    static constexpr int Size = 1024;
#else
    static constexpr int Size = 256;
#endif

    using Word = unsigned long long;
    static constexpr int ProcessorsPerWord = CHAR_BIT * sizeof(Word);
    Word array[Size / ProcessorsPerWord];

    void clear()
    { *this = LogicalProcessorSet{}; }

    void set(LogicalProcessor n)
    { wordFor(n) |= bitFor(n); }
    void unset(LogicalProcessor n)
    { wordFor(n) &= ~bitFor(n); }
    bool is_set(LogicalProcessor n) const
    { return wordFor(n) & bitFor(n); }

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
    void add_package(Topology::Package pkg)
    {
        for (Topology::Core& core : pkg.cores)
            for (Topology::Thread& thread : core.threads)
                set(LogicalProcessor(thread.oscpu));
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

    Word &wordFor(LogicalProcessor n)
    { return array[int(n) / ProcessorsPerWord]; }
    const Word &wordFor(LogicalProcessor n) const
    { return array[int(n) / ProcessorsPerWord]; }
    static constexpr Word bitFor(LogicalProcessor n)
    { return 1ULL << (unsigned(n) % ProcessorsPerWord); }
};

LogicalProcessorSet ambient_logical_processor_set();
bool pin_to_logical_processor(LogicalProcessor, const char *thread_name = nullptr);

void load_cpu_info(/*in*/ const LogicalProcessorSet &enabled_cpus);
void apply_cpuset_param(char *param);

#endif /* INC_TOPOLOGY_H */
