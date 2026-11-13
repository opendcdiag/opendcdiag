/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"

#include <stdint.h>
#include <stdlib.h>

int selftest_memcmp_c_run(struct test *test, int thread)
{
    uint32_t actual[] = { thread, 0x11111111, thread + 1 };
    uint32_t expected[] = { thread, 0x22222222, thread + 1 };

    memcmp_or_fail(actual, expected, 3, "C worker stack-local mismatch");
    log_error("C worker unexpectedly continued after memcmp_or_fail: %u, %u",
              actual[0], expected[0]);
    return EXIT_SUCCESS;
}
