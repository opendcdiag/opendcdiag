/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_unittests_utils.h"
#include "topology_cpu.h"
#include "cpu_device.h"

#include "gtest/gtest.h"

#include <span>
#include <utility>
#include <vector>

namespace {
Topology topo_global;

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
}

const Topology &Topology::topology()
{
    return topo_global;
}

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
