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

#ifdef __unix__
#include "sandstone_p.h"
#include <vector>
#include <numeric>
#include <cassert>
#include <inttypes.h>
#include <limits.h>
#include <map>

#define KEY_EXISTS(map, key)  (map.count(key) > 0)

static int smi_count_run(struct test *test, int cpu)
{
    (void) test;

    int real_cpu_number = cpu_info[cpu].cpu_number;

    if (KEY_EXISTS(sApp->smi_counts_start, real_cpu_number)) {
        auto initial_count = sApp->smi_counts_start[real_cpu_number];
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
    .test_run = smi_count_run,
    .desired_duration = -1,
    .fracture_loop_count = -1,
    .quality_level = TEST_QUALITY_PROD,
END_DECLARE_TEST
#endif /* __unix__ */
