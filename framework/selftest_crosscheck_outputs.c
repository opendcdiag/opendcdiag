/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck.h"
#include "selftest_crosscheck_outputs.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

CROSSCHECK_INPUT(output_numbers, uint32_t);
CROSSCHECK_OUTPUT(output_words, uint32_t);
CROSSCHECK_OUTPUT(output_flags, bool);
CROSSCHECK_OUTPUT(output_empty, uint32_t);

void selftest_crosscheck_outputs_c_input(uint32_t generation)
{
    uint32_t source[] = {generation, 5};
    set_input(output_numbers, source, 2, "owned C output computation inputs");
    memset(source, 0, sizeof(source));
}

void selftest_crosscheck_outputs_c_golden(void)
{
    __auto_type input = get_input(output_numbers);
    uint32_t words[] = {input.data[0] + input.data[1], input.data[0] * input.data[1]};
    const bool flags[] = {true, false};
    submit_output(output_words, words, 2, "authoritative golden words");
    submit_output(output_flags, flags, 2, NULL);
    submit_output(output_empty, (const uint32_t *)NULL, 0, NULL);
    words[0] = 0;
}

int selftest_crosscheck_outputs_c_run(struct test *test, int thread)
{
    __auto_type input = get_input(output_numbers);
    const bool bad_first = strcmp(test->id, "selftest_crosscheck_output_c_bad_first") == 0;
    const bool bad_later = strcmp(test->id, "selftest_crosscheck_output_c_bad_later") == 0;
    const bool golden_count = strcmp(test->id, "selftest_crosscheck_output_c_golden_count") == 0;
    const bool later_count = strcmp(test->id, "selftest_crosscheck_output_c_later_count") == 0;
    for (int i = 0; i < 3; ++i) {
        uint32_t words[] = {input.data[0] + input.data[1], input.data[0] * input.data[1]};
        if (bad_first)
            ++words[0];
        if (bad_later && i > 0)
            ++words[1];
        const bool flags[] = {true, false};
        submit_output(output_empty, (const uint32_t *)NULL, 0, NULL);
        submit_output(output_flags, flags, 2, "ignored C description");
        submit_output(output_words, words, golden_count || (later_count && i > 0) ? 1 : 2, NULL);
        words[0] = 0;
    }
    log_info("output post-submit sentinel");
    return EXIT_SUCCESS;
}
