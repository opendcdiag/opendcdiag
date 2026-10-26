/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

CROSSCHECK_INPUT(crosscheck_c_numbers, uint32_t);
CROSSCHECK_INPUT(crosscheck_c_flags, bool);
CROSSCHECK_INPUT(crosscheck_c_empty, uint32_t);
CROSSCHECK_OUTPUT(crosscheck_c_sum, uint32_t);

static int selftest_crosscheck_inputs_c_check(void)
{
    struct CrossCheckInputView_crosscheck_c_numbers numbers = get_input(crosscheck_c_numbers);
    struct CrossCheckInputView_crosscheck_c_flags flags = get_input(crosscheck_c_flags);
    if (numbers.count != 3 || flags.count != 3 || get_input(crosscheck_c_empty).count != 0)
        report_fail_msg("C cross-check input sizes changed");
    uint32_t sum = 0;
    for (size_t i = 0; i < numbers.count; ++i) {
        if (flags.data[i])
            sum += numbers.data[i];
    }
    if (sum != 18 || !flags.data[0] || flags.data[1] || !flags.data[2])
        report_fail_msg("C cross-check inputs did not preserve the captured values");
    submit_output(crosscheck_c_sum, &sum, 1, "captured C input computation");
    return EXIT_SUCCESS;
}

int selftest_crosscheck_inputs_c_init(struct test *test)
{
    uint32_t numbers[] = { 7, 9, 11 };
    bool flags[] = { true, false, true };
    set_input(crosscheck_c_numbers, numbers, 3, "C integer array");
    set_input(crosscheck_c_flags, flags, 3, "C boolean array");
    set_input(crosscheck_c_empty, (const uint32_t *)NULL, 0, NULL);
    memset(numbers, 0, sizeof(numbers));
    memset(flags, 0, sizeof(flags));
    return selftest_crosscheck_inputs_c_check();
}

int selftest_crosscheck_inputs_c_run(struct test *test, int thread)
{
    return selftest_crosscheck_inputs_c_check();
}
