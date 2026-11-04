/**
 * @copyright
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b simple_add
 * @parblock
 * simple_add repeatedly adds the same two random numbers on each worker
 * and checks each sum against the captured golden output.
 * @endparblock
 */

#include "sandstone.h"
#include "crosscheck.h"

#include <stdint.h>
#include <stdlib.h>

DECLARE_CROSS_CHECK_INPUT(simple_add_values, uint32_t);
DECLARE_CROSS_CHECK_OUTPUT(simple_add_sum, uint32_t);

static int simple_add_init(struct test *test)
{
    uint32_t values[] = { random32(), random32() };
    capture_input(simple_add_values, values, 2, "Addends");
    const struct CrossCheckInputView_simple_add_values input = get_input(simple_add_values);
    uint32_t sum = input.data[0] + input.data[1];
    capture_output(simple_add_sum, &sum, 1, "Sum of two unsigned integers");

    return EXIT_SUCCESS;
}

static int simple_add_run(struct test *test, int cpu)
{
    const struct CrossCheckInputView_simple_add_values input = get_input(simple_add_values);

    TEST_LOOP(test, 1 << 20) {
        uint32_t sum = input.data[0] + input.data[1];
        capture_output(simple_add_sum, &sum, 1, "Sum of two unsigned integers");
    }

    return EXIT_SUCCESS;
}

DECLARE_TEST(simple_add, "Repeatedly add two integer numbers")
    .test_init = simple_add_init,
    .test_run = simple_add_run,
    .quality_level = TEST_QUALITY_BETA,
END_DECLARE_TEST
