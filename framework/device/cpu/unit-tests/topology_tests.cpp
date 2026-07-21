/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_unittests_utils.h"
#include "topology_cpu.h"
#include "cpu_device.h"

#include "gtest/gtest.h"

#include <cstddef>
#include <cstring>
#include <span>
#include <utility>
#include <vector>

namespace {
using Thread = Topology::Thread;

Topology topo_global;

Thread make_thread(int cpu, int hwid, int thread_id, int core_id, int module_id,
                   int die_id, int numa_id, int package_id, NativeCoreType type)
{
    Thread t = {};
    t.cpu_number = cpu;
    t.hwid = hwid;
    t.thread_id = int8_t(thread_id);
    t.core_id = int16_t(core_id);
    t.module_id = int16_t(module_id);
    t.die_id = int16_t(die_id);
    t.numa_id = int16_t(numa_id);
    t.package_id = int16_t(package_id);
    t.native_core_type = type;
    return t;
}

std::vector<cpu_info_t> make_cpu_info_entries()
{
    std::vector<cpu_info_t> cpu_info(UNITTESTS_THREAD_COUNT);
    for (int i = 0; i < UNITTESTS_THREAD_COUNT; ++i) {
        cpu_info[i].cpu_number = i;
        cpu_info[i].thread_id = 0;
        cpu_info[i].core_id = i;
        cpu_info[i].module_id = i;
        cpu_info[i].die_id = -1;
        cpu_info[i].native_core_type = core_type_performance;
        cpu_info[i].package_id = 0;
        cpu_info[i].numa_id = (i < 8) ? 0 : 1;
    }
    return cpu_info;
}

// TODO: This is creating Topology from scratch. Future works can unittests build_topology() as well,
// and we would be able to call it here.
Topology make_two_numa_topology()
{
    Topology topo;
    auto make_core = [](const cpu_info_t *cpu) {
        return Topology::Core{ std::span(cpu, cpu + 1) };
    };

    Topology::Package package;
    package.cores.reserve(UNITTESTS_THREAD_COUNT);
    for (int i = 0; i < UNITTESTS_THREAD_COUNT; ++i) {
        package.cores.push_back(make_core(&device_info[i]));
    }

    Topology::CoreGrouping numa0;
    numa0.cores.insert(numa0.cores.end(), package.cores.begin(), package.cores.begin() + 8);
    package.groups.push_back(std::move(numa0));

    Topology::CoreGrouping numa1;
    numa1.cores.insert(numa1.cores.end(), package.cores.begin() + 8, package.cores.end());
    package.groups.push_back(std::move(numa1));

    topo.packages.push_back(std::move(package));
    return topo;
}

void expect_plan(const SlicePlans::Slices &actual, const std::vector<std::pair<int, int>> &expected)
{
    ASSERT_EQ(actual.size(), expected.size());
    for (size_t i = 0; i < actual.size(); ++i) {
        EXPECT_EQ(actual[i].device_range.starting_device, expected[i].first);
        EXPECT_EQ(actual[i].device_range.device_count, expected[i].second);
    }
}


// Replicates TopologyDetector's ordering so tests can assert their storage is
// laid out the way build_topology() requires.
bool detector_less(const Thread &a, const Thread &b)
{
    unsigned __int128 x, y;
    std::memcpy(&x, &a.cpu_number, sizeof(x));
    std::memcpy(&y, &b.cpu_number, sizeof(y));
    return x < y;
}

// To add a new topology: fill a StorageBuilder in that sorted order (add_core()
// keeps cpu_number/hwid unique and sequential) and describe the expected result
// with a vector<ExpectedPackage>.
struct StorageBuilder
{
    std::vector<Thread> threads;

    void add_core(int package_id, int numa_id, int die_id, int module_id, int core_id,
                  int threads_per_core, NativeCoreType type)
    {
        for (int t = 0; t < threads_per_core; ++t) {
            int index = int(threads.size());
            threads.push_back(make_thread(index, index, t, core_id, module_id, die_id,
                                          numa_id, package_id, type));
        }
    }
};

// A core is described by the index of its first Thread in the storage and the
// number of Threads it holds.
struct ExpectedCore
{
    int first_thread_index;
    int thread_count;
};
struct ExpectedPackage
{
    int id;
    // groups[g] lists the cores of the g-th CoreGrouping; the package's own
    // cores are the concatenation of all groups, in order.
    std::vector<std::vector<ExpectedCore>> groups;
};

void expect_cores(std::span<const Topology::Core> cores, const Thread *storage,
                  const std::vector<ExpectedCore> &expected)
{
    ASSERT_EQ(cores.size(), expected.size());
    for (size_t i = 0; i < cores.size(); ++i) {
        EXPECT_EQ(cores[i].threads.data(), storage + expected[i].first_thread_index);
        EXPECT_EQ(cores[i].threads.size(), size_t(expected[i].thread_count));
    }
}

void expect_topology(const Topology &topo, const Thread *storage,
                     const std::vector<ExpectedPackage> &expected)
{
    ASSERT_EQ(topo.packages.size(), expected.size());
    for (size_t p = 0; p < expected.size(); ++p) {
        const Topology::Package &pkg = topo.packages[p];
        EXPECT_EQ(pkg.id(), expected[p].id);

        std::vector<ExpectedCore> all_cores;
        for (const auto &group : expected[p].groups)
            all_cores.insert(all_cores.end(), group.begin(), group.end());
        expect_cores(pkg.cores, storage, all_cores);

        ASSERT_EQ(pkg.groups.size(), expected[p].groups.size());
        for (size_t g = 0; g < pkg.groups.size(); ++g)
            expect_cores(pkg.groups[g].cores, storage, expected[p].groups[g]);
    }
}
}

const Topology &Topology::topology()
{
    return topo_global;
}

// ---- Slice planning tests ------------------------------------

TEST(Topology, SlicePlansCreationMax3)
{
    auto cpu_info = make_cpu_info_entries();
    device_info = cpu_info.data();
    topo_global = make_two_numa_topology();

    SlicePlans plans;
    slice_plan_init_for_device(plans.plans, 3);

    expect_plan(plans.plans[SlicePlans::IsolateSockets], {
        { 0, 16 },
    });
    expect_plan(plans.plans[SlicePlans::IsolateCoreGroup], {
        { 0, 8 }, { 8, 8 },
    });
    expect_plan(plans.plans[SlicePlans::Heuristic], {
        { 0, 3 }, { 3, 3 }, { 6, 2 },
        { 8, 3 }, { 11, 3 }, { 14, 2 },
    });
}

TEST(Topology, SlicePlansCreationDefaultMax)
{
    auto cpu_info = make_cpu_info_entries();
    device_info = cpu_info.data();
    topo_global = make_two_numa_topology();

    SlicePlans plans;
    slice_plan_init_for_device(plans.plans, 0);

    expect_plan(plans.plans[SlicePlans::Heuristic], {
        { 0, 8 }, { 8, 8 },
    });
}

// ---- Topology::build_topology() tests ------------------------------------

TEST(BuildTopology, Empty)
{
    Topology topo = Topology::build_topology({});
    EXPECT_FALSE(topo.isValid());
    EXPECT_TRUE(topo.packages.empty());
}

// single package (id 0), two threads per core, module/die/numa unknown (-1),
// unknown core type: a single core-group holding every core.
TEST(BuildTopology, SinglePackageTwoThreadsPerCore)
{
    constexpr int core_count = 8;
    StorageBuilder storage;
    for (int core = 0; core < core_count; ++core)
        storage.add_core(0, -1, -1, -1, core, 2, core_type_unknown);
    ASSERT_TRUE(std::ranges::is_sorted(storage.threads, detector_less));

    Topology topo = Topology::build_topology(storage.threads);

    std::vector<ExpectedCore> cores;
    for (int core = 0; core < core_count; ++core)
        cores.push_back({ core * 2, 2 });
    expect_topology(topo, storage.threads.data(), {
        { 0, { cores } },
    });
}

// single package (id != 0), one thread per core, module_id == core_id / 2,
// homogeneous known core type: still a single core-group.
TEST(BuildTopology, SinglePackageHomogeneousCoreType)
{
    constexpr int core_count = 8;
    StorageBuilder storage;
    for (int core = 0; core < core_count; ++core)
        storage.add_core(3, -1, -1, core / 2, core, 1, core_type_performance);
    ASSERT_TRUE(std::ranges::is_sorted(storage.threads, detector_less));

    Topology topo = Topology::build_topology(storage.threads);

    std::vector<ExpectedCore> cores;
    for (int core = 0; core < core_count; ++core)
        cores.push_back({ core, 1 });
    expect_topology(topo, storage.threads.data(), {
        { 3, { cores } },
    });
}

// single package (id != 0), one thread per core, module_id == core_id / 2,
// heterogeneous known core type: the change of native_core_type splits the
// package into two core-groups. Performance (1) sorts before efficiency (2).
TEST(BuildTopology, SinglePackageHeterogeneousCoreType)
{
    constexpr int perf_cores = 4;
    constexpr int eff_cores = 4;
    StorageBuilder storage;
    int core = 0;
    for (int i = 0; i < perf_cores; ++i, ++core)
        storage.add_core(5, -1, -1, core / 2, core, 1, core_type_performance);
    for (int i = 0; i < eff_cores; ++i, ++core)
        storage.add_core(5, -1, -1, core / 4 * 2, core, 1, core_type_efficiency);
    ASSERT_TRUE(std::ranges::is_sorted(storage.threads, detector_less));

    Topology topo = Topology::build_topology(storage.threads);

    std::vector<ExpectedCore> perf, eff;
    for (int c = 0; c < perf_cores; ++c)
        perf.push_back({ c, 1 });
    for (int c = 0; c < eff_cores; ++c)
        eff.push_back({ perf_cores + c, 1 });
    expect_topology(topo, storage.threads.data(), {
        { 5, { perf, eff } },
    });
}

// two packages, two threads per core, module_id == core_id / 2, 4 dies and
// 2 NUMA domains per socket (2 dies per NUMA domain). numa_id is globally
// unique; die_id is per-package. Each die becomes its own core-group.
TEST(BuildTopology, TwoPackagesDiesAndNuma)
{
    constexpr int packages = 2;
    constexpr int dies_per_package = 4;
    constexpr int cores_per_die = 2;
    StorageBuilder storage;
    for (int pkg = 0; pkg < packages; ++pkg) {
        int core = 0;
        for (int die = 0; die < dies_per_package; ++die) {
            int numa = pkg * 2 + die / 2;       // globally unique NUMA ids
            for (int c = 0; c < cores_per_die; ++c, ++core)
                storage.add_core(pkg, numa, die, core / 2, core, 2, core_type_unknown);
        }
    }
    ASSERT_TRUE(std::ranges::is_sorted(storage.threads, detector_less));

    Topology topo = Topology::build_topology(storage.threads);

    std::vector<ExpectedPackage> expected;
    constexpr int threads_per_package = dies_per_package * cores_per_die * 2;
    for (int pkg = 0; pkg < packages; ++pkg) {
        int base = pkg * threads_per_package;
        ExpectedPackage ep{ pkg, {} };
        for (int die = 0; die < dies_per_package; ++die) {
            std::vector<ExpectedCore> group;
            for (int c = 0; c < cores_per_die; ++c) {
                int first = base + (die * cores_per_die + c) * 2;
                group.push_back({ first, 2 });
            }
            ep.groups.push_back(std::move(group));
        }
        expected.push_back(std::move(ep));
    }
    expect_topology(topo, storage.threads.data(), expected);
}

// 16 packages, one core per package, one thread per core, unknown core type.
TEST(BuildTopology, ManySinglecorePackages)
{
    constexpr int packages = 16;
    StorageBuilder storage;
    for (int pkg = 0; pkg < packages; ++pkg)
        storage.add_core(pkg, -1, -1, -1, 0, 1, core_type_unknown);
    ASSERT_TRUE(std::ranges::is_sorted(storage.threads, detector_less));

    Topology topo = Topology::build_topology(storage.threads);

    std::vector<ExpectedPackage> expected;
    for (int pkg = 0; pkg < packages; ++pkg)
        expected.push_back({ pkg, { { { pkg, 1 } } } });
    expect_topology(topo, storage.threads.data(), expected);
}
