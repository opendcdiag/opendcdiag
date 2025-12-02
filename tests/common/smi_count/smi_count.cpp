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

#include "interrupt_monitor.hpp"

#include <cinttypes>
#include <vector>

namespace {
// we can use global variable, since write to this vector is done by single thread (initialize_smi_counts),
// and in smi_count_run it's read-only + each thread reads different memory location.
std::vector<uint64_t> smi_counts_start;

int initialize_smi_counts(struct test*)
{
    std::optional<uint64_t> v = InterruptMonitor::count_smi_events(cpu_info[0].cpu_number);
    if (!v) {
        log_skip(RuntimeSkipCategory, "Could not read msr");
        return EXIT_SKIP;
    }
    smi_counts_start.resize(thread_count());
    smi_counts_start[0] = *v;
    for (int i = 1; i < thread_count(); i++) {
        smi_counts_start[i] = InterruptMonitor::count_smi_events(cpu_info[i].cpu_number).value_or(0);
    }
    return EXIT_SUCCESS;
}

int smi_count_run(struct test *test, int thread)
{
    (void) test;

    if (int(smi_counts_start.size()) > thread) {
        int real_cpu_number = cpu_info[thread].cpu_number;
        auto initial_count = smi_counts_start[thread];
        auto current_count = InterruptMonitor::count_smi_events(real_cpu_number);
        if (current_count) {
            uint64_t difference = *current_count - initial_count;

            if (difference) {
                log_platform_message(SANDSTONE_LOG_INFO "SMI count difference detected: %" PRIu64 " new SMI detected on thread %d cpu_number %d\n",
                                     difference, thread, real_cpu_number);
            }
        }
    }
    return EXIT_SUCCESS;
}
} // end anonymous namespace

DECLARE_TEST(smi_count, "Counts SMI events")
    .test_preinit = initialize_smi_counts,
    .test_init = [](struct test *t) { return EXIT_SUCCESS; },
    .test_run = smi_count_run,
    .test_cleanup = initialize_smi_counts,
    .desired_duration = -1,
    .fracture_loop_count = -1,
    .quality_level = InterruptMonitor::InterruptMonitorWorks ? TEST_QUALITY_PROD : TEST_QUALITY_SKIP,
END_DECLARE_TEST
