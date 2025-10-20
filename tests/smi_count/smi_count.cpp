/**
 * @file
 *
 * @copyright
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b smi_count
 * This test is not really a test in the sense that it will never fail.  It is intended to simply
 * print differences in the number of SMI (System Management Interrupts) that have occurred since
 * either the beginning of the sandstone run or the last time this test itself has run
 */

#include "sandstone_p.h"
#include "test_base.hpp"

#include <vector>
#include <cinttypes>

namespace {
class SmiCountTest : public SandstoneTest::Base
{
    std::vector<uint64_t> smi_counts_start;

    int initialize_smi_counts()
    {
        std::optional<uint64_t> v = InterruptMonitor::count_smi_events(cpu_info[0].cpu_number);
        if (!v) {
            return EXIT_SKIP;
        }
        smi_counts_start.resize(thread_count());
        smi_counts_start[0] = *v;
        for (int i = 1; i < thread_count(); i++) {
            smi_counts_start[i] = InterruptMonitor::count_smi_events(cpu_info[i].cpu_number).value_or(0);
        }
        return EXIT_SUCCESS;
    }

public:
    static constexpr auto quality_level = TestQuality::Production;
    static constexpr char description[] = "Counts SMI events";
    static constexpr SandstoneTest::Base::Parameters parameters{
        .desired_duration = -1,
        .fracture_loop_count = -1,
    };

    int preinit()
    {
        return initialize_smi_counts();
    }

    int init()
    {
        return InterruptMonitor::InterruptMonitorWorks ? EXIT_SUCCESS : EXIT_SKIP;
    }

    int run(const Device& device)
    {
        if (smi_counts_start.size() > device.id) {
            int real_cpu_number = cpu_info[device.id].cpu_number;
            auto initial_count = smi_counts_start[device.id];
            auto current_count = InterruptMonitor::count_smi_events(real_cpu_number);
            if (current_count) {
                uint64_t difference = *current_count - initial_count;

                if (difference) {
                    log_platform_message(SANDSTONE_LOG_INFO "SMI count difference detected: %" PRIu64 " new SMI detected on thread %d cpu_number %d\n",
                                        difference, device.id, real_cpu_number);
                }
            }
        }
        return EXIT_SUCCESS;
    }

    int cleanup()
    {
        return initialize_smi_counts();
    }
};
} // end anonymous namespace

DECLARE_TEST_CLASS(smi_count, SmiCountTest);
