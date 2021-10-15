/**
 * @file
 *
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b mce_check
 * @parblock
 * This test just checks the number of Machine Check Events that the
 * system has reported and compares it agains the number reported at
 * the beginning of the sandstone run.  If there is a difference then
 * it reports an error.
 *
 * The purpose of this is to report that a new machine check event was
 * listed in the logs during the execution of all the tests.
 *
 * This "test" is not really a test in the same way that it does not
 * cause or look for any errors it creates.  If it fails, it means that
 * one of the previous tests executed by this execution of sandstone
 * likely caused a Machine Check Abort (MCA)
 *
 * Checking is done by ensuring the code always leaves by the expected
 * path.  If this test fails it is likely going to be a seg-fault or
 * UD fault due to a miscalculated jump target.
 * @endparblock
 */

#include "sandstone_p.h"
#include <vector>
#include <numeric>
#include <cassert>
#include <limits.h>

static int mce_check_run(struct test *test, int cpu)
{
    int errorcount = 0;
    (void) test;
    if (cpu != 0)
        return EXIT_SUCCESS;

    std::vector<uint32_t> counts = sApp->get_mce_interrupt_counts();

    if (counts.size() != sApp->mce_counts_start.size()) {
        report_fail_msg("Number of CPUs changed during execution, test is not valid.");
        return EXIT_FAILURE;
    }

    std::vector<uint32_t> differences(counts.size());
    for (int i = 0; i < counts.size(); ++i)
        differences[i] = counts[i] - sApp->mce_counts_start[i];

    // set up for the next iteration (in case there's one)
    sApp->mce_count_last = std::accumulate(counts.begin(), counts.end(), uint64_t(0));
    sApp->mce_counts_start = std::move(counts);
    counts.clear();

    // check the CPUs we were running tests on
    for (int i = 0; i < num_cpus(); ++i) {
        // translate our thread number to the OS CPU number
        cpu = cpu_info[i].cpu_number;
        assert(cpu < differences.size());

        if (differences[i] != 0) {
            log_message(i, SANDSTONE_LOG_ERROR "MCE detected");
            differences[i] = 0;
            ++errorcount;
        }
    }

    // check if there's any CPU that reported an MCE but we weren't testing on
    for (size_t i = 0; i < differences.size(); ++i) {
        if (differences[i] != 0) {
            log_message(-1, SANDSTONE_LOG_ERROR "MCE detected on OS CPU %zu that wasn't part of the test set", i);
            ++errorcount;
        }
    }

    if (errorcount)
        log_platform_message(SANDSTONE_LOG_ERROR "MCE interrupts detected on %d CPUs", errorcount);
    return errorcount;
}


// The MCE test is special in that it is not handled like a normal test
// We do not use the macros to specify it because we do not want it to
// be in the acutal test list - it is an "inserted" test in that the test
// is always inserted in the end.
struct test mce_test = {  // This variable is used in the framework!
#ifdef TEST_ID_mce_check
        .id = SANDSTONE_STRINGIFY(TEST_ID_mce_check),
        .description = nullptr,
#else
        .id = "mce_check",
        .description = "Machine Check Exceptions/Events count",
#endif
        .test_run = mce_check_run,
        .desired_duration = -1,
        .fracture_loop_count = -1,
        .quality_level = INT_MAX,
};
// Do not convert to use the test declaration macros - read above
