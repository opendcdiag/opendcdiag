/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_unittests_utils.h"
#include "topology_gpu.h"
#include "gpu_device.h"

#include "gtest/gtest.h"

namespace {
gpu_info_t make_gpu_info_entry(int subdevice_index, __uint128_t bdf, int16_t numa_id = -1)
{
    gpu_info_t res{};

    res.subdevice_index = subdevice_index;
    res.numa_id = numa_id;
    // does not really matter how we assign bdf. It just has to be unique.
    res.bdf.domain = bdf;
    res.bdf.bus = bdf >> 32;
    res.bdf.device = bdf >> 64;
    res.bdf.function = bdf >> 96;

    return res;
}
}

Topology topo_global;

const Topology &Topology::topology()
{
    return topo_global;
}

TEST(Topology, HeterogenousTopology)
{
    std::vector<gpu_info_t> gpu_info;
    gpu_info.reserve(UNITTESTS_THREAD_COUNT);

    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xdecafc0ffee)); // end

    gpu_info.emplace_back(make_gpu_info_entry(0, 0xdeadfacade)); // 2-elem root
    gpu_info.emplace_back(make_gpu_info_entry(1, 0xdeadfacade));

    gpu_info.emplace_back(make_gpu_info_entry(0, 0xbeefface)); // 3-elem root
    gpu_info.emplace_back(make_gpu_info_entry(1, 0xbeefface));
    gpu_info.emplace_back(make_gpu_info_entry(2, 0xbeefface));

    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xdeadbeef)); // end

    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xabd1cab1e)); // end

    gpu_info.emplace_back(make_gpu_info_entry(0, 0xdefaced)); // 2-elem root
    gpu_info.emplace_back(make_gpu_info_entry(1, 0xdefaced));

    gpu_info.emplace_back(make_gpu_info_entry(0, 0xc0ffee)); // 5-elem root
    gpu_info.emplace_back(make_gpu_info_entry(1, 0xc0ffee));
    gpu_info.emplace_back(make_gpu_info_entry(2, 0xc0ffee));
    gpu_info.emplace_back(make_gpu_info_entry(3, 0xc0ffee));
    gpu_info.emplace_back(make_gpu_info_entry(4, 0xc0ffee));

    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xbadbabe)); // end

    device_info = gpu_info.data();
    Topology topo = build_topology();

    EXPECT_EQ(topo.devices.size(), 8);

    EXPECT_TRUE(std::holds_alternative<Topology::EndDevice>(topo.devices[0]));

    EXPECT_TRUE(std::holds_alternative<Topology::RootDevice>(topo.devices[1]));
    EXPECT_EQ(std::get<Topology::RootDevice>(topo.devices[1]).size(), 2);

    EXPECT_TRUE(std::holds_alternative<Topology::RootDevice>(topo.devices[2]));
    EXPECT_EQ(std::get<Topology::RootDevice>(topo.devices[2]).size(), 3);

    EXPECT_TRUE(std::holds_alternative<Topology::EndDevice>(topo.devices[3]));

    EXPECT_TRUE(std::holds_alternative<Topology::EndDevice>(topo.devices[4]));

    EXPECT_TRUE(std::holds_alternative<Topology::RootDevice>(topo.devices[5]));
    EXPECT_EQ(std::get<Topology::RootDevice>(topo.devices[5]).size(), 2);

    EXPECT_TRUE(std::holds_alternative<Topology::RootDevice>(topo.devices[6]));
    EXPECT_EQ(std::get<Topology::RootDevice>(topo.devices[6]).size(), 5);

    EXPECT_TRUE(std::holds_alternative<Topology::EndDevice>(topo.devices[7]));
}

TEST(Topology, TailingRoot)
{
    std::vector<gpu_info_t> gpu_info;
    gpu_info.reserve(UNITTESTS_THREAD_COUNT);

    gpu_info.emplace_back(make_gpu_info_entry(0, 0xdecaf));
    gpu_info.emplace_back(make_gpu_info_entry(1, 0xdecaf));
    gpu_info.emplace_back(make_gpu_info_entry(2, 0xdecaf));
    gpu_info.emplace_back(make_gpu_info_entry(3, 0xdecaf));
    gpu_info.emplace_back(make_gpu_info_entry(4, 0xdecaf));
    gpu_info.emplace_back(make_gpu_info_entry(5, 0xdecaf));
    gpu_info.emplace_back(make_gpu_info_entry(6, 0xdecaf));
    gpu_info.emplace_back(make_gpu_info_entry(7, 0xdecaf));
    gpu_info.emplace_back(make_gpu_info_entry(8, 0xdecaf));
    gpu_info.emplace_back(make_gpu_info_entry(9, 0xdecaf));

    gpu_info.emplace_back(make_gpu_info_entry(0, 0xbadcafe));
    gpu_info.emplace_back(make_gpu_info_entry(1, 0xbadcafe));
    gpu_info.emplace_back(make_gpu_info_entry(2, 0xbadcafe));
    gpu_info.emplace_back(make_gpu_info_entry(3, 0xbadcafe));
    gpu_info.emplace_back(make_gpu_info_entry(4, 0xbadcafe));
    gpu_info.emplace_back(make_gpu_info_entry(5, 0xbadcafe));

    device_info = gpu_info.data();
    Topology topo = build_topology();

    EXPECT_EQ(topo.devices.size(), 2);

    EXPECT_TRUE(std::holds_alternative<Topology::RootDevice>(topo.devices[0]));
    EXPECT_EQ(std::get<Topology::RootDevice>(topo.devices[0]).size(), 10);

    // commit of a tailing root happens after the while loop
    EXPECT_TRUE(std::holds_alternative<Topology::RootDevice>(topo.devices[1]));
    EXPECT_EQ(std::get<Topology::RootDevice>(topo.devices[1]).size(), 6);
}

TEST(Topology, NumaDomainsGrouping)
{
    std::vector<gpu_info_t> gpu_info;
    gpu_info.reserve(UNITTESTS_THREAD_COUNT);

    // Interleave sparse NUMA IDs and unknown (-1) to verify grouping by ID.
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0x1, -1));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0x2, 2));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0x3, -1));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0x4, 9));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0x5, 2));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0x6, 9));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0x7, 0));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0x8, 0));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0x9, 9));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xa, 2));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xb, -1));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xc, 5));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xd, 5));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xe, 5));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xf, 2));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0x10, 9));

    device_info = gpu_info.data();
    Topology topo = build_topology();

    ASSERT_EQ(topo.numa_domains.size(), 5);

    EXPECT_EQ(topo.numa_domains[0].id(), -1);
    EXPECT_EQ(topo.numa_domains[0].devices.size(), 3);

    EXPECT_EQ(topo.numa_domains[1].id(), 2);
    EXPECT_EQ(topo.numa_domains[1].devices.size(), 4);

    EXPECT_EQ(topo.numa_domains[2].id(), 9);
    EXPECT_EQ(topo.numa_domains[2].devices.size(), 4);

    EXPECT_EQ(topo.numa_domains[3].id(), 0);
    EXPECT_EQ(topo.numa_domains[3].devices.size(), 2);

    EXPECT_EQ(topo.numa_domains[4].id(), 5);
    EXPECT_EQ(topo.numa_domains[4].devices.size(), 3);

    for (const auto& domain: topo.numa_domains) {
        for (const auto* dev: domain.devices) {
            EXPECT_EQ(dev->numa_id, domain.id());
        }
    }
}

TEST(Topology, SlicePlansCreation)
{
    std::vector<gpu_info_t> gpu_info;
    gpu_info.reserve(UNITTESTS_THREAD_COUNT);

    // NUMA 0, 3-elem root
    gpu_info.emplace_back(make_gpu_info_entry(0, 0xfeed0, 0));
    gpu_info.emplace_back(make_gpu_info_entry(1, 0xfeed0, 0));
    gpu_info.emplace_back(make_gpu_info_entry(2, 0xfeed0, 0));

    // NUMA 1, end device
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xbeef1, 1));

    // NUMA 0, end device
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xface0, 0));

    // NUMA 1, end device
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xbeef2, 1));

    // NUMA 0, end devices
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xface1, 0));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xface2, 0));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xface3, 0));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xface4, 0));

    // NUMA 1, end devices
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xbeef3, 1));
    gpu_info.emplace_back(make_gpu_info_entry(-1, 0xbeef4, 1));

    // NUMA 1, 4-elem root
    gpu_info.emplace_back(make_gpu_info_entry(0, 0xc0ff1, 1));
    gpu_info.emplace_back(make_gpu_info_entry(1, 0xc0ff1, 1));
    gpu_info.emplace_back(make_gpu_info_entry(2, 0xc0ff1, 1));
    gpu_info.emplace_back(make_gpu_info_entry(3, 0xc0ff1, 1));

    ASSERT_EQ(gpu_info.size(), UNITTESTS_THREAD_COUNT);

    device_info = gpu_info.data();
    topo_global = build_topology();

    auto expect_plan = [](const auto& actual, const std::vector<std::pair<int, int>>& expected) {
        ASSERT_EQ(actual.size(), expected.size());
        auto expected_it = expected.begin();
        for (size_t i = 0; i < actual.size(); ++i, ++expected_it) {
            EXPECT_EQ(actual[i].starting_device, expected_it->first);
            EXPECT_EQ(actual[i].device_count, expected_it->second);
        }
    };

    SlicePlans plans;
    slice_plan_init_for_device(plans.plans, 3);

    expect_plan(plans.plans[SlicePlans::IsolateSockets], {
        { 0, 16 },
    });
    // Current impl first discovers NUMA 0, then NUMA 1. This is why those indices are not 'sorted'.
    expect_plan(plans.plans[SlicePlans::IsolateNuma], {
        { 0, 3 }, { 4, 1 }, { 6, 4 },  // NUMA 0
        { 3, 1 }, { 5, 1 }, { 10, 6 },  // NUMA 1
    });
    expect_plan(plans.plans[SlicePlans::Heuristic], {
        { 0, 3 }, { 4, 1 }, { 6, 3 }, {9, 1},     // 4 > 3, split
        { 3, 1 }, { 5, 1 }, { 10, 2 }, { 12, 4 }, // 4 > 3 but we don't split root devices
    });

    // For default heuristic DefaultMaxCoresPerSlice=32 is big enough to be same as isolate numa
    for (auto& plan : plans.plans) {
        plan.clear();
    }
    slice_plan_init_for_device(plans.plans, 0);
    expect_plan(plans.plans[SlicePlans::Heuristic], {
        { 0, 3 }, { 4, 1 }, { 6, 4 },
        { 3, 1 }, { 5, 1 }, { 10, 6 },
    });
}
