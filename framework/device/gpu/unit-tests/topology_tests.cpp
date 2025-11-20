/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_unittests_utils.h"
#include "topology_gpu.h"
#include "gpu_device.h"

#include "gtest/gtest.h"

namespace {
gpu_info_t make_gpu_info_entry(int subdevice_index, __uint128_t bdf)
{
    gpu_info_t res;

    res.subdevice_index = subdevice_index;
    // does not really matter how we assign bdf. It just has to be unique.
    res.bdf.domain = bdf;
    res.bdf.bus = bdf >> 32;
    res.bdf.device = bdf >> 64;
    res.bdf.function = bdf >> 96;

    return res;
}
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
