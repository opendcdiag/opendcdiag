/**
 * @copyright
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b consensus_add
 * @parblock
 * Repeatedly add framework-owned immutable inputs with init only setting inputs.
 * Submitted sums are compared across distinct eligible CPUs, not worker identities.
 * One CPU provides local self-checking without a cross-CPU comparison.
 * @endparblock
 *
 * @test @b crosschecked_add
 * @parblock
 * Reuse the same worker computation with init also submitting on its observed
 * CPU, sharing that CPU's slot with workers without an extra vote or an
 * authoritative reference.
 * @endparblock
 */

#include "crosscheck.h"

CROSSCHECK_INPUT(addends, uint32_t);
CROSSCHECK_OUTPUT(sum, uint32_t);

static int consensus_add_init(struct test *)
{
    uint32_t scratch[] = {random32(), random32()};

    set_input(addends, scratch, "Addends");

    return EXIT_SUCCESS;
}

static int crosschecked_add_run(struct test *test, int)
{
    const auto input = get_input(addends);

    TEST_LOOP(test, 1 << 20) {
        uint32_t result = input[0] + input[1];
        submit_output(sum, &result, 1, "Worker sum");
    }

    return EXIT_SUCCESS;
}

static int crosschecked_add_init(struct test *)
{
    uint32_t scratch[] = {random32(), random32()};

    set_input(addends, scratch, "Addends");

    const auto input = get_input(addends);
    uint32_t result = input[0] + input[1];
    submit_output(sum, &result, 1, "Sum computed in init");

    return EXIT_SUCCESS;
}

DECLARE_TEST(consensus_add, "Cross-check worker integer additions across CPUs")
    .test_init = consensus_add_init,
    .test_run = crosschecked_add_run,
    .quality_level = TEST_QUALITY_BETA,
END_DECLARE_TEST

DECLARE_TEST(crosschecked_add, "Cross-check repeated integer additions")
    .test_init = crosschecked_add_init,
    .test_run = crosschecked_add_run,
    .quality_level = TEST_QUALITY_BETA,
END_DECLARE_TEST
