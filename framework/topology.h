/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_TOPOLOGY_H
#define INC_TOPOLOGY_H

#include <sandstone.h>

#include <array>
#include <optional>
#include <string>
#include <vector>

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

struct LogicalProcessorSet;

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
    std::string build_falure_mask(const struct test *test);

    static Topology topology();
};

enum class LogicalProcessor : int {};
class LogicalProcessorSet
{
public:
    static constexpr int Size = 1024;

    using Word = unsigned long long;
    Word array[Size / (CHAR_BIT * sizeof(Word))];

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
            total += __builtin_popcountll(w);
        return total;
    }

    bool empty() const
    {
        for (const Word &w: array)
            if (w)
                return false;
        return true;
    }
    void add_package(Topology::Package pkg) {
        for (Topology::Core& core : pkg.cores)
            for (Topology::Thread& thread : core.threads)
                set(LogicalProcessor(thread.oscpu));
    }

private:

    Word &wordFor(LogicalProcessor n)
    { return array[int(n) / (CHAR_BIT * sizeof(Word))]; }
    const Word &wordFor(LogicalProcessor n) const
    { return array[int(n) / (CHAR_BIT * sizeof(Word))]; }
    static constexpr Word bitFor(LogicalProcessor n)
    { return 1ULL << (unsigned(n) % (CHAR_BIT * sizeof(Word))); }
};

LogicalProcessorSet ambient_logical_processor_set();
bool pin_to_logical_processor(LogicalProcessor, const char *thread_name = nullptr);

void load_cpu_info(/*in/out*/ const LogicalProcessorSet &enabled_cpus);

#endif /* INC_TOPOLOGY_H */
