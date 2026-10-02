/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_p.h"
#include "sandstone_unittests_utils.h"
#include "topology_idxd.hpp"
#include "idxd_device.h"

#include "gtest/gtest.h"

namespace {
wq_info_t make_wq_info_entry(int device_id, int wq_id, accfg_device_type dev_type, accfg_device_version dev_version, __uint128_t bdf)
{
    wq_info_t res{};

    res.device_id = device_id;
    res.wq_id = wq_id;
    res.dev_type = dev_type;
    res.dev_version = dev_version;
    // does not really matter how we assign bdf. It just has to be unique.
    res.bdf.domain = bdf;
    res.bdf.bus = bdf >> 32;
    res.bdf.device = bdf >> 64;
    res.bdf.function = bdf >> 96;

    return res;
}

}

Topology topo_global;

#ifdef __llvm__
thread_local int thread_num = 0;
#else
__thread int thread_num __attribute__((tls_model("initial-exec"))) = 0;
#endif

#undef log_message_skip
void log_message_skip(int, SkipCategory, const char*, ...)
{}

namespace {
struct PrepareTestFixture
{
    wq_info_t wq{};
    struct test test = {};

    PrepareTestFixture(accfg_device_type dev_type = ACCFG_DEVICE_DSA,
                       accfg_device_version dev_version = ACCFG_DEVICE_VERSION_2)
    {
        wq = make_wq_info_entry(0, 0, dev_type, dev_version, 0);
        auto& device = topo_global.devices.emplace_back();
        device.dev_type = dev_type;
        device.dev_version = dev_version;
        auto& group = device.groups.emplace_back();
        auto& topology_wq = group.wqs.emplace_back();
        topology_wq.wq = &wq;
        topology_wq.targetable = true;
        wq.path = { 0, 0 };
    }

    ~PrepareTestFixture()
    {
        topo_global.devices.clear();
    }
};
}

const Topology &Topology::topology()
{
    return topo_global;
}

// mock empty impl - we don't call libaccel-config in unit-tests.
int AccfgCtx::init()
{
    return EXIT_SUCCESS;
}

TEST(Topology, HeterogenousTopology)
{
    std::vector<wq_info_t> wq_info;
    wq_info.reserve(UNITTESTS_THREAD_COUNT);

    // dsa0
    wq_info.emplace_back(make_wq_info_entry(0, 0, ACCFG_DEVICE_DSA, ACCFG_DEVICE_VERSION_1, 0xdecafc0ffee));
    wq_info.emplace_back(make_wq_info_entry(0, 1, ACCFG_DEVICE_DSA, ACCFG_DEVICE_VERSION_1, 0xdecafc0ffee));
    wq_info.emplace_back(make_wq_info_entry(0, 2, ACCFG_DEVICE_DSA, ACCFG_DEVICE_VERSION_1, 0xdecafc0ffee));
    wq_info.emplace_back(make_wq_info_entry(0, 3, ACCFG_DEVICE_DSA, ACCFG_DEVICE_VERSION_1, 0xdecafc0ffee));
    wq_info.emplace_back(make_wq_info_entry(0, 4, ACCFG_DEVICE_DSA, ACCFG_DEVICE_VERSION_1, 0xdecafc0ffee));
    wq_info.emplace_back(make_wq_info_entry(0, 5, ACCFG_DEVICE_DSA, ACCFG_DEVICE_VERSION_1, 0xdecafc0ffee));
    wq_info.emplace_back(make_wq_info_entry(0, 6, ACCFG_DEVICE_DSA, ACCFG_DEVICE_VERSION_1, 0xdecafc0ffee));
    wq_info.emplace_back(make_wq_info_entry(0, 7, ACCFG_DEVICE_DSA, ACCFG_DEVICE_VERSION_1, 0xdecafc0ffee));

    // iax1
    wq_info.emplace_back(make_wq_info_entry(1, 0, ACCFG_DEVICE_IAX, ACCFG_DEVICE_VERSION_2, 0xbeefface));
    wq_info.emplace_back(make_wq_info_entry(1, 1, ACCFG_DEVICE_IAX, ACCFG_DEVICE_VERSION_2, 0xbeefface));
    wq_info.emplace_back(make_wq_info_entry(1, 2, ACCFG_DEVICE_IAX, ACCFG_DEVICE_VERSION_2, 0xbeefface));
    wq_info.emplace_back(make_wq_info_entry(1, 3, ACCFG_DEVICE_IAX, ACCFG_DEVICE_VERSION_2, 0xbeefface));

    // iax3
    wq_info.emplace_back(make_wq_info_entry(3, 0, ACCFG_DEVICE_IAX, ACCFG_DEVICE_VERSION_2, 0xbadc0ffee));
    wq_info.emplace_back(make_wq_info_entry(3, 1, ACCFG_DEVICE_IAX, ACCFG_DEVICE_VERSION_2, 0xbadc0ffee));
    wq_info.emplace_back(make_wq_info_entry(3, 2, ACCFG_DEVICE_IAX, ACCFG_DEVICE_VERSION_2, 0xbadc0ffee));
    wq_info.emplace_back(make_wq_info_entry(3, 3, ACCFG_DEVICE_IAX, ACCFG_DEVICE_VERSION_2, 0xbadc0ffee));

    device_info = wq_info.data();
    Topology topo = build_topology(nullptr);

    EXPECT_EQ(topo.devices.size(), 3);

    EXPECT_EQ(topo.devices[0].id, 0);
    EXPECT_EQ(topo.devices[0].dev_type, ACCFG_DEVICE_DSA);
    EXPECT_EQ(topo.devices[0].wqs.size(), 8);

    EXPECT_EQ(topo.devices[1].id, 1);
    EXPECT_EQ(topo.devices[1].dev_type, ACCFG_DEVICE_IAX);
    EXPECT_EQ(topo.devices[1].wqs.size(), 4);

    EXPECT_EQ(topo.devices[2].id, 3);
    EXPECT_EQ(topo.devices[2].dev_type, ACCFG_DEVICE_IAX);
    EXPECT_EQ(topo.devices[2].wqs.size(), 4);
}

TEST(PrepareTestForDevice, DeviceAgnosticTestPassesWithTargetableWq)
{
    PrepareTestFixture fixture;

    EXPECT_EQ(prepare_test_for_device(&fixture.test), TestResult::Passed);
}

TEST(PrepareTestForDevice, VersionRequirementSkipsOlderWq)
{
    PrepareTestFixture fixture;
    fixture.test.minimum_cpu = device_feature_dsa_v3;

    EXPECT_EQ(prepare_test_for_device(&fixture.test), TestResult::Skipped);
}

TEST(PrepareTestForDevice, IaxRequirementPassesWithMatchingWq)
{
    PrepareTestFixture fixture(ACCFG_DEVICE_IAX, ACCFG_DEVICE_VERSION_2);
    fixture.test.minimum_cpu = device_feature_iax_v2;

    EXPECT_EQ(prepare_test_for_device(&fixture.test), TestResult::Passed);
}

TEST(PrepareTestForDevice, DeviceAgnosticTestSkipsWithoutTargetableWq)
{
    PrepareTestFixture fixture;
    topo_global.devices.clear();

    EXPECT_EQ(prepare_test_for_device(&fixture.test), TestResult::Skipped);
}

TEST(PrepareTestForDevice, WrongDeviceFamilySkips)
{
    PrepareTestFixture fixture;
    fixture.test.minimum_cpu = device_feature_iax_v2;

    EXPECT_EQ(prepare_test_for_device(&fixture.test), TestResult::Skipped);
}

TEST(PrepareTestForDevice, SupportedOperationPasses)
{
    PrepareTestFixture fixture;
    topo_global.devices[0].op_cap.bits[IDXD_OPCODE_MEMMOVE / 32] |=
        1u << (IDXD_OPCODE_MEMMOVE % 32);
    fixture.test.minimum_cpu = device_feature_op_memmove;

    EXPECT_EQ(prepare_test_for_device(&fixture.test), TestResult::Passed);
}

TEST(PrepareTestForDevice, UnsupportedOperationSkips)
{
    PrepareTestFixture fixture;
    fixture.test.minimum_cpu = device_feature_op_memmove;

    EXPECT_EQ(prepare_test_for_device(&fixture.test), TestResult::Skipped);
}

TEST(PrepareTestForDevice, UndefinedFeatureBitsAbort)
{
    PrepareTestFixture fixture;
    fixture.test.minimum_cpu = idxd_all_features_mask + 1;

    EXPECT_DEATH(prepare_test_for_device(&fixture.test), "Undefined feature bits");
}

TEST(PrepareTestForDevice, MixedDeviceFeaturesAbort)
{
    PrepareTestFixture fixture;
    fixture.test.minimum_cpu = device_feature_dsa_op_noop | device_feature_iax_op_noop;

    EXPECT_DEATH(prepare_test_for_device(&fixture.test), "Ambiguous features");
}
