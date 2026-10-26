/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "crosscheck.h"
#include "selftest_crosscheck_outputs.h"

#include <stddef.h>
#include <stdint.h>

DECLARE_CROSS_CHECK_OUTPUT(output_flags, uint8_t);

void selftest_crosscheck_outputs_c_conflict(void)
{
    const uint8_t flags[] = {1, 0};
    capture_output(output_flags, flags, 2, NULL);
}
