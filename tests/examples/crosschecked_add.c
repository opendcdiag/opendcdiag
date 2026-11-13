/**
 * @copyright
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b crosschecked_add
 * @parblock
 * Repeatedly add framework-owned immutable inputs and submit the sums for
 * invariance and post-join verification. Init's golden computation participates
 * in verification without becoming an authoritative reference.
 * @endparblock
 *
 * @test @b consensus_add
 * @parblock
 * Reuse the same worker computation with init only setting inputs. Workers'
 * submitted sums participate in consensus verification without an init output.
 * At least two successful workers are required for cross-checking.
 * @endparblock
 */

#include "crosscheck.h"

CROSSCHECK_INPUT(addends, uint32_t);
CROSSCHECK_OUTPUT(sum, uint32_t);

static int crosschecked_add_init(struct test *test)
{
    uint32_t scratch[] = {random32(), random32()};

    set_input(addends, scratch, 2, "Addends");

    __auto_type input = get_input(addends);
    uint32_t result = input.data[0] + input.data[1];
    submit_output(sum, &result, 1, "Golden sum computed in init");

    return EXIT_SUCCESS;
}

static int crosschecked_add_run(struct test *test, int cpu)
{
    __auto_type input = get_input(addends);

    TEST_LOOP(test, 1 << 20) {
        uint32_t result = input.data[0] + input.data[1];
        submit_output(sum, &result, 1, "Worker sum");
    }

    return EXIT_SUCCESS;
}

DECLARE_TEST(crosschecked_add, "Cross-check repeated integer additions")
    .test_init = crosschecked_add_init,
    .test_run = crosschecked_add_run,
    .quality_level = TEST_QUALITY_BETA,
END_DECLARE_TEST

static int consensus_add_init(struct test *test)
{
    uint32_t scratch[] = {random32(), random32()};

    set_input(addends, scratch, 2, "Addends");

    return EXIT_SUCCESS;
}

DECLARE_TEST(consensus_add, "Cross-check integer additions among workers")
    .test_init = consensus_add_init,
    .test_run = crosschecked_add_run,
    .quality_level = TEST_QUALITY_BETA,
END_DECLARE_TEST
