/**
 * @copyright
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b simple_add
 * @parblock
 * simple_add repeatedly adds the same two random numbers on each thread
 * and checks all threads produce the same result.
 * @endparblock
 */

#include "sandstone.h"

static unsigned int value1;
static unsigned int value2;
static unsigned int golden_sum;

static int simple_add_init(struct test *test)
{
        value1 = random32();
        value2 = random32();
        golden_sum = value1 + value2;

        return EXIT_SUCCESS;
}

static int simple_add_run(struct test *test, int cpu)
{
        unsigned int sum;

        TEST_LOOP(test, 1 << 20) {
                sum = value1 + value2;
                if (sum != golden_sum) {
                        report_fail_msg("Add failed.  Expected %u got %u",
                                        golden_sum, sum);
                }
        }
        
        return EXIT_SUCCESS;
}

DECLARE_TEST(simple_add, "Repeatedly add two integer numbers")
        .test_init = simple_add_init,
        .test_run = simple_add_run,
        .quality_level = TEST_QUALITY_BETA,
END_DECLARE_TEST


