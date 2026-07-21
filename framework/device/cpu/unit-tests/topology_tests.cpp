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

// Saves and restores the mutable globals the framework stubs expose, so a test
// that describes an unusual topology cannot leak state into later tests.
struct TopologyStateGuard
{
    device_info_t *saved_device_info = device_info;
    int saved_device_count = unittests_device_count;
    ~TopologyStateGuard()
    {
        device_info = saved_device_info;
        unittests_device_count = saved_device_count;
    }
};


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

// ---- Grouped-core view tests ---------------------------------

TEST(ViewTopology, EmptyYieldsNothing)
{
    TopologyStateGuard guard;
    device_info = nullptr;

    {
        Topology topo;
        auto cores = topo.cores();
        static_assert(std::ranges::forward_range<decltype(cores)>);
        static_assert(std::ranges::view<decltype(cores)>);
        EXPECT_TRUE(cores.begin() == cores.begin());
        EXPECT_FALSE(cores.begin() != cores.begin());
        EXPECT_TRUE(cores.begin() == cores.end());          // range is empty
        EXPECT_FALSE(cores.begin() != cores.end());
        EXPECT_TRUE(cores.empty());
        EXPECT_FALSE(cores);
        for (auto it = cores.begin(); it != cores.end(); ++it) {
            static_assert(std::forward_iterator<decltype(it)>);
            // range was empty
            FAIL();
        }

        EXPECT_TRUE(topo.modules().empty());
        EXPECT_TRUE(topo.dies().empty());
        EXPECT_TRUE(topo.numa_domains().empty());
        EXPECT_FALSE(topo.modules());
        EXPECT_FALSE(topo.dies());
        EXPECT_FALSE(topo.numa_domains());
    }
    {
        Topology::CoreGrouping group;
        auto modules = group.modules();
        static_assert(std::ranges::forward_range<decltype(modules)>);
        static_assert(std::ranges::view<decltype(modules)>);
        EXPECT_TRUE(modules.begin() == modules.begin());
        EXPECT_FALSE(modules.begin() != modules.begin());
        EXPECT_TRUE(modules.begin() == modules.end());          // range is empty
        EXPECT_FALSE(modules.begin() != modules.end());
        EXPECT_TRUE(modules.empty());
        EXPECT_FALSE(modules);
        for (auto it = modules.begin(); it != modules.end(); ++it) {
            static_assert(std::forward_iterator<decltype(it)>);
            // range was empty
            FAIL();
        }

        EXPECT_TRUE(group.dies().empty());
        EXPECT_TRUE(group.numa_domains().empty());
        EXPECT_FALSE(group.dies());
        EXPECT_FALSE(group.numa_domains());
    }
}

// module/die/numa are all -1 here; the views group them like any other id (one
// run of -1), whereas find_*_by_id(-1) returns empty.
TEST(ViewTopology, NonEmptyBasics)
{
    static constexpr int core_count = 8;
    TopologyStateGuard guard;
    device_info = nullptr;

    StorageBuilder storage;
    for (int core = 0; core < core_count; ++core)
        storage.add_core(0, -1, -1, -1, core, 2, core_type_unknown);
    ASSERT_TRUE(std::ranges::is_sorted(storage.threads, detector_less));
    ASSERT_EQ(storage.threads.size(), core_count * 2); // two threads per core
    Topology topo = Topology::build_topology(storage.threads);

    {
        auto cores = topo.cores();
        EXPECT_TRUE(cores.begin() == cores.begin());
        EXPECT_FALSE(cores.begin() != cores.begin());
        EXPECT_TRUE(cores.begin() != cores.end());
        EXPECT_FALSE(cores.begin() == cores.end());
        EXPECT_FALSE(cores.empty());
        int core_counter = 0;
        for (const Topology::Core &core : cores) {
            EXPECT_EQ(core.id(), core_counter);
            EXPECT_EQ(&core.threads.front(), &storage.threads[core_counter * 2]);
            ++core_counter;
        }
        EXPECT_EQ(core_counter, core_count);

        auto it = cores.begin();
        auto copy = it;
        EXPECT_EQ(it->id(), copy->id());
        EXPECT_EQ(it++, copy++);
        EXPECT_EQ(++it, ++copy);
        EXPECT_EQ(it->id(), copy->id());
        EXPECT_EQ(std::to_address(it), std::to_address(copy));  // they still point to the same Core
        EXPECT_EQ(std::next(cores.begin(), core_count), cores.end());
    }

    // we should find exactly one of the following
    auto check_view_has_one_element = [](const auto &view) {
        using View = std::decay_t<decltype(view)>;
        static_assert(std::ranges::forward_range<View>);
        static_assert(std::ranges::view<View>);
        EXPECT_TRUE(view);
        EXPECT_FALSE(view.empty());
        auto it = view.begin();
        EXPECT_EQ(std::ranges::distance(it, view.end()), 1);
        EXPECT_TRUE(it != view.end());
        EXPECT_FALSE(it == view.end());
        EXPECT_EQ(it->id(), -1);
        EXPECT_EQ(std::next(it), view.end());
        std::span cores = it->cores;
        EXPECT_EQ(++it, view.end());

        EXPECT_FALSE(cores.empty());
        EXPECT_EQ(cores.size(), core_count);
        EXPECT_EQ(cores.data()->threads.size(), 2);
    };
    check_view_has_one_element(topo.modules());
    check_view_has_one_element(topo.dies());
    check_view_has_one_element(topo.numa_domains());
    check_view_has_one_element(topo.packages[0].modules());
    check_view_has_one_element(topo.packages[0].dies());
    check_view_has_one_element(topo.packages[0].numa_domains());
}

// 24 quad-core modules (still homogeneous)
TEST(ViewTopology, ModulesWithinSinglePackage)
{
    static constexpr int module_count = 24;
    static constexpr int cores_per_module = 4;
    static constexpr int core_count = module_count * cores_per_module;
    TopologyStateGuard guard;
    device_info = nullptr;

    StorageBuilder storage;
    int module = 0;
    for (int i = 0; i < module_count; ++i, module += 64) {
        for (int j = 0; j < cores_per_module; ++j)
            storage.add_core(5, -1, 0, module, module + j, 1, core_type_efficiency);
    }
    ASSERT_TRUE(std::ranges::is_sorted(storage.threads, detector_less));
    ASSERT_EQ(storage.threads.size(), core_count);
    Topology topo = Topology::build_topology(storage.threads);

    {
        auto modules = topo.modules();
        EXPECT_TRUE(modules.begin() == modules.begin());
        EXPECT_FALSE(modules.begin() != modules.begin());
        EXPECT_TRUE(modules.begin() != modules.end());
        EXPECT_FALSE(modules.begin() == modules.end());
        EXPECT_FALSE(modules.empty());

        int module_counter = 0;
        for (auto module : modules) {
            EXPECT_EQ(module.cores.size(), cores_per_module);
            EXPECT_EQ(module.cores.front().id(), module_counter * 64);
            EXPECT_EQ(&module.cores.front().threads.front(), &storage.threads[module_counter * cores_per_module]);
            ++module_counter;
        }
        EXPECT_EQ(module_counter, module_count);

        auto it = modules.begin();
        auto copy = it;
        EXPECT_EQ(it++, copy++);
        EXPECT_EQ(++it, ++copy);
        EXPECT_EQ(it->cores.data(), copy->cores.data());  // they still point to the same thing
    }

    // single one of each of the following
    auto check_view_has_one_element = [](const auto &view, int id) {
        EXPECT_TRUE(view);
        EXPECT_FALSE(view.empty());
        auto it = view.begin();
        EXPECT_EQ(std::ranges::distance(it, view.end()), 1);
        EXPECT_TRUE(it != view.end());
        EXPECT_FALSE(it == view.end());
        EXPECT_EQ(it->id(), id);
        std::span cores = it->cores;
        EXPECT_EQ(++it, view.end());

        EXPECT_EQ(cores.size(), core_count);
        EXPECT_FALSE(cores.empty());
        EXPECT_EQ(cores.size(), core_count);
        EXPECT_EQ(cores.data()->threads.size(), 1);
    };
    check_view_has_one_element(topo.dies(), 0);
    check_view_has_one_element(topo.numa_domains(), -1);
    check_view_has_one_element(topo.packages[0].dies(), 0);
    check_view_has_one_element(topo.packages[0].numa_domains(), -1);
}

// Two packages, 4 dies / 2 NUMA domains each, 1 thread per core. die_id and
// module_id repeat in package 1.
TEST(ViewTopology, WholeSystemChainsAndResetsPerPackage)
{
    static constexpr int cores_per_die = 2;
    static constexpr int dies_per_pkg = 4;
    static constexpr int numa_domains_per_pkg = 2;
    static constexpr int cores_per_numa_domain = cores_per_die * dies_per_pkg / numa_domains_per_pkg;
    static constexpr int cores_per_pkg = cores_per_die * dies_per_pkg;
    auto size = [](const auto &view) { return std::ranges::distance(view); };
    TopologyStateGuard guard;
    device_info = nullptr;

    StorageBuilder storage;
    for (int pkg = 0, numa = 0; pkg < 2; ++pkg) {
        int core = 0;
        for (int die = 0; die < dies_per_pkg; ++die) {
            for (int c = 0; c < cores_per_die; ++c, ++core)
                storage.add_core(pkg, numa, die, core, core * 2, 1, core_type_unknown);
            numa += (die & 1);
        }
    }
    ASSERT_TRUE(std::ranges::is_sorted(storage.threads, detector_less));
    Topology topo = Topology::build_topology(storage.threads);
    ASSERT_EQ(topo.packages.size(), 2u);
    ASSERT_EQ(topo.packages[0].groups.size(), dies_per_pkg);
    ASSERT_EQ(topo.packages[1].groups.size(), dies_per_pkg);

    EXPECT_EQ(size(topo.cores()), cores_per_pkg * topo.packages.size());
    EXPECT_EQ(size(topo.packages[0].cores), cores_per_pkg);
    EXPECT_EQ(size(topo.packages[1].cores), cores_per_pkg);

    {
        int numa_id = 0;
        auto sysnuma = topo.numa_domains();
        auto pkgnuma = topo.packages[0].numa_domains();
        EXPECT_FALSE(sysnuma.empty());
        EXPECT_FALSE(pkgnuma.empty());
        EXPECT_EQ(size(pkgnuma), numa_domains_per_pkg);
        EXPECT_EQ(size(sysnuma), numa_domains_per_pkg * topo.packages.size());

        // co-iteration on the first package:
        auto sit = sysnuma.begin();
        auto pit = pkgnuma.begin();
        for ( ; pit != pkgnuma.end(); ++pit, ++sit, ++numa_id) {
            EXPECT_NE(sit, sysnuma.end());
            EXPECT_EQ(sit->id(), numa_id);
            EXPECT_EQ(pit->id(), numa_id);

            Topology::NumaDomain group = *sit;
            EXPECT_EQ(&group.cores.front().threads.front(), &storage.threads[numa_id * cores_per_numa_domain]);
            EXPECT_EQ(group.cores.size(), cores_per_numa_domain);
            EXPECT_EQ(sit->cores.size(), cores_per_numa_domain);
        }

        // co-iteration on the second package:
        // numa_ids are not repeated
        pkgnuma = topo.packages[1].numa_domains();
        EXPECT_FALSE(pkgnuma.empty());
        EXPECT_EQ(size(pkgnuma), numa_domains_per_pkg);
        for (pit = pkgnuma.begin(); pit != pkgnuma.end(); ++pit, ++sit, ++numa_id) {
            EXPECT_NE(sit, sysnuma.end());
            EXPECT_EQ(sit->id(), numa_id);
            EXPECT_EQ(pit->id(), numa_id);

            Topology::NumaDomain group = *sit;
            EXPECT_EQ(&group.cores.front().threads.front(), &storage.threads[numa_id * cores_per_numa_domain]);
            EXPECT_EQ(group.cores.size(), cores_per_numa_domain);
            EXPECT_EQ(sit->cores.size(), cores_per_numa_domain);
        }
        EXPECT_EQ(sit, sysnuma.end());
    }
    {
        int die_id = 0;
        auto sysdie = topo.dies();
        auto pkgdie = topo.packages[0].dies();
        EXPECT_FALSE(sysdie.empty());
        EXPECT_FALSE(pkgdie.empty());
        EXPECT_EQ(size(pkgdie), dies_per_pkg);
        EXPECT_EQ(size(sysdie), dies_per_pkg * topo.packages.size());

        // co-iteration on the first package:
        auto sit = sysdie.begin();
        auto pit = pkgdie.begin();
        for ( ; pit != pkgdie.end(); ++pit, ++sit, ++die_id) {
            EXPECT_NE(sit, sysdie.end());
            EXPECT_EQ(sit->id(), die_id);
            EXPECT_EQ(pit->id(), die_id);

            Topology::Die group = *sit;
            EXPECT_EQ(&group.cores.front().threads.front(), &storage.threads[die_id * cores_per_die]);
            EXPECT_EQ(group.cores.size(), cores_per_die);
            EXPECT_EQ(sit->cores.size(), cores_per_die);
        }

        // co-iteration on the second package:
        die_id = 0;         // die IDs are repeated
        pkgdie = topo.packages[1].dies();
        EXPECT_FALSE(pkgdie.empty());
        EXPECT_EQ(size(pkgdie), dies_per_pkg);
        for (pit = pkgdie.begin(); pit != pkgdie.end(); ++pit, ++sit, ++die_id) {
            EXPECT_NE(sit, sysdie.end());
            EXPECT_EQ(sit->id(), die_id);
            EXPECT_EQ(pit->id(), die_id);

            Topology::Die group = *sit;
            EXPECT_EQ(&group.cores.front().threads.front(), &storage.threads[cores_per_pkg + die_id * cores_per_die]);
            EXPECT_EQ(group.cores.size(), cores_per_die);
            EXPECT_EQ(sit->cores.size(), cores_per_die);
        }
        EXPECT_EQ(sit, sysdie.end());
    }
}

TEST(ViewTopology, SystemIteration)
{
    static constexpr int threads_per_core = 2;
    static constexpr int cores_per_module = 4;
    static constexpr int modules_per_die = 16;
    static constexpr int cores_per_die = cores_per_module * modules_per_die;
    static constexpr int dies_per_pkg = 4;
    static constexpr int cores_per_pkg = cores_per_die * dies_per_pkg;
    static constexpr int numa_domains_per_pkg = 2;
    static constexpr int cores_per_numa_domain = cores_per_die * dies_per_pkg / numa_domains_per_pkg;
    auto size = [](const auto &view) { return std::ranges::distance(view); };
    TopologyStateGuard guard;
    device_info = nullptr;

    StorageBuilder storage;
    for (int pkg = 0, numa = 0; pkg < 2; ++pkg) {
        int core = 0;
        int module = 0;
        for (int die = 0; die < dies_per_pkg; ++die) {
            for (int m = 0; m < modules_per_die; ++m, ++module) {
                for (int c = 0; c < cores_per_module; ++c, ++core)
                    storage.add_core(pkg, numa, die, module, core * threads_per_core,
                                     threads_per_core, core_type_performance);
            }
            numa += (die & 1);
        }
    }
    ASSERT_TRUE(std::ranges::is_sorted(storage.threads, detector_less));
    Topology topo = Topology::build_topology(storage.threads);
    ASSERT_EQ(topo.packages.size(), 2u);
    ASSERT_EQ(topo.packages[0].groups.size(), dies_per_pkg);
    ASSERT_EQ(topo.packages[1].groups.size(), dies_per_pkg);

    const Topology::Thread *current_core = &storage.threads[0];
    for (const Topology::Package &p : topo.packages) {
        EXPECT_EQ(size(p.cores), cores_per_pkg);
        EXPECT_EQ(size(p.numa_domains()), numa_domains_per_pkg);

        for (const auto numa_domain : p.numa_domains()) {
            EXPECT_EQ(size(numa_domain.cores), cores_per_numa_domain);
            for (const auto die : numa_domain.dies()) {
                EXPECT_EQ(size(die.cores), cores_per_die);
                for (const auto module : die.modules()) {
                    EXPECT_EQ(size(module.cores), cores_per_module);
                    for (const auto core : module.cores) {
                        EXPECT_EQ(core.id(), current_core->core_id);
                        EXPECT_EQ(&core.threads.front(), current_core);
                        current_core += threads_per_core;
                    }

                    // verify we don't exceed the module
                    EXPECT_EQ(size(module.modules()), 1);
                    EXPECT_EQ(size(module.dies()), 1);
                    EXPECT_EQ(size(module.numa_domains()), 1);
                }
                // verify we don't exceed the die
                EXPECT_EQ(size(die.dies()), 1);
                EXPECT_EQ(size(die.numa_domains()), 1);
            }
            // verify we don't exceed the NUMA domain
            EXPECT_EQ(size(numa_domain.numa_domains()), 1);
        }
    }

    current_core = &storage.threads[0];
    for (const Topology::Package &p : topo.packages) {
        EXPECT_EQ(size(p.dies()), dies_per_pkg);
        for (const auto die : p.dies()) {
            EXPECT_EQ(size(die.cores), cores_per_die);
            for (const auto module : die.modules()) {
                EXPECT_EQ(size(module.cores), cores_per_module);
                for (const auto core : module.cores) {
                    EXPECT_EQ(core.id(), current_core->core_id);
                    current_core += threads_per_core;
                }

                // verify we don't exceed the module
                EXPECT_EQ(size(module.modules()), 1);
                EXPECT_EQ(size(module.dies()), 1);
                EXPECT_EQ(size(module.numa_domains()), 1);
            }
            // verify we don't exceed the die
            EXPECT_EQ(size(die.dies()), 1);
            EXPECT_EQ(size(die.numa_domains()), 1);
        }
    }

    current_core = &storage.threads[0];
    for (const Topology::Package &p : topo.packages) {
        for (const Topology::CoreGrouping &g : p.groups) {
            // there should be one die in each group (and half a NUMA domain)
            EXPECT_EQ(g.cores.size(), cores_per_die);
            EXPECT_EQ(size(g.modules()), modules_per_die);
            for (const auto module : g.modules()) {
                EXPECT_EQ(size(module.cores), cores_per_module);
                for (const auto core : module.cores) {
                    EXPECT_EQ(core.id(), current_core->core_id);
                    current_core += threads_per_core;
                }

                // verify we don't exceed the module
                EXPECT_EQ(size(module.modules()), 1);
                EXPECT_EQ(size(module.dies()), 1);
                EXPECT_EQ(size(module.numa_domains()), 1);
            }

            // verify we don't exceed the group
            EXPECT_EQ(size(g.numa_domains()), 1);
            EXPECT_EQ(size(g.dies()), 1);
        }
    }

    current_core = &storage.threads[0];
    for (const Topology::Package &p : topo.packages) {
        EXPECT_EQ(size(p.modules()), modules_per_die * dies_per_pkg);
        for (const auto module : p.modules()) {
            EXPECT_EQ(size(module.cores), cores_per_module);
            for (const auto core : module.cores) {
                EXPECT_EQ(core.id(), current_core->core_id);
                current_core += threads_per_core;
            }

            // verify we don't exceed the module
            EXPECT_EQ(size(module.modules()), 1);
            EXPECT_EQ(size(module.dies()), 1);
            EXPECT_EQ(size(module.numa_domains()), 1);
        }
    }

    current_core = &storage.threads[0];
    for (const auto numa_domain : topo.numa_domains()) {
        EXPECT_EQ(size(numa_domain.cores), cores_per_numa_domain);
        for (const auto die : numa_domain.dies()) {
            EXPECT_EQ(size(die.cores), cores_per_die);
            for (const auto module : die.modules()) {
                EXPECT_EQ(size(module.cores), cores_per_module);
                for (const auto core : module.cores) {
                    EXPECT_EQ(core.id(), current_core->core_id);
                    current_core += threads_per_core;
                }

                // verify we don't exceed the module
                EXPECT_EQ(size(module.modules()), 1);
                EXPECT_EQ(size(module.dies()), 1);
                EXPECT_EQ(size(module.numa_domains()), 1);
            }
            // verify we don't exceed the die
            EXPECT_EQ(size(die.dies()), 1);
            EXPECT_EQ(size(die.numa_domains()), 1);
        }
        // verify we don't exceed the NUMA domain
        EXPECT_EQ(size(numa_domain.numa_domains()), 1);
    }

    current_core = &storage.threads[0];
    for (const auto numa_domain : topo.numa_domains()) {
        EXPECT_EQ(size(numa_domain.cores), cores_per_numa_domain);
        for (const auto module : numa_domain.modules()) {
            EXPECT_EQ(size(module.cores), cores_per_module);
            for (const auto core : module.cores) {
                EXPECT_EQ(core.id(), current_core->core_id);
                current_core += threads_per_core;
            }

            // verify we don't exceed the module
            EXPECT_EQ(size(module.modules()), 1);
            EXPECT_EQ(size(module.dies()), 1);
            EXPECT_EQ(size(module.numa_domains()), 1);
        }
        // verify we don't exceed the NUMA domain
        EXPECT_EQ(size(numa_domain.numa_domains()), 1);
    }

    current_core = &storage.threads[0];
    for (const auto die : topo.dies()) {
        EXPECT_EQ(size(die.cores), cores_per_die);
        for (const auto module : die.modules()) {
            EXPECT_EQ(size(module.cores), cores_per_module);
            for (const auto core : module.cores) {
                EXPECT_EQ(core.id(), current_core->core_id);
                current_core += threads_per_core;
            }

            // verify we don't exceed the module
            EXPECT_EQ(size(module.modules()), 1);
            EXPECT_EQ(size(module.dies()), 1);
            EXPECT_EQ(size(module.numa_domains()), 1);
        }
        // verify we don't exceed the die
        EXPECT_EQ(size(die.dies()), 1);
        EXPECT_EQ(size(die.numa_domains()), 1);
    }

    current_core = &storage.threads[0];
    for (const auto module : topo.modules()) {
        EXPECT_EQ(size(module.cores), cores_per_module);
        for (const auto core : module.cores) {
            EXPECT_EQ(core.id(), current_core->core_id);
            current_core += threads_per_core;
        }

        // verify we don't exceed the module
        EXPECT_EQ(size(module.modules()), 1);
        EXPECT_EQ(size(module.dies()), 1);
        EXPECT_EQ(size(module.numa_domains()), 1);
    }

    auto cores = topo.cores();
    EXPECT_EQ(size(cores), cores_per_pkg * topo.packages.size());
    current_core = &storage.threads[0];
    for (const auto core : cores) {
        EXPECT_EQ(core.id(), current_core->core_id);
        current_core += threads_per_core;
    }
}