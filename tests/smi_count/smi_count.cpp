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
#include <vector>
#include <numeric>
#include <cassert>
#include <inttypes.h>
#include <limits.h>
#include <map>

extern void initialize_smi_counts();

static int smi_count_run(struct test *test, int cpu)
{
    (void) test;

    if (sApp->smi_counts_start.size() > cpu) {
        int real_cpu_number = cpu_info[cpu].cpu_number;
        auto initial_count = sApp->smi_counts_start[cpu];
        auto current_count = sApp->count_smi_events(real_cpu_number);
        if (current_count) {
            uint64_t difference = *current_count - initial_count;

            if (difference) {
                log_platform_message(SANDSTONE_LOG_INFO "SMI count difference detected: %" PRIu64 " new SMI detected on thread %d cpu_number %d\n",
                                     difference, cpu, real_cpu_number);
            }
        }
    }
    return EXIT_SUCCESS;
}

DECLARE_TEST(smi_count, "Counts SMI events")
    .test_init = [](struct test *t) { return InterruptMonitor::InterruptMonitorWorks ? EXIT_SUCCESS : EXIT_SKIP; },
    .test_run = smi_count_run,
    .test_cleanup = [](struct test * t) { initialize_smi_counts(); return EXIT_SUCCESS; },
    .desired_duration = -1,
    .fracture_loop_count = -1,
    .quality_level = TEST_QUALITY_PROD,
END_DECLARE_TEST
