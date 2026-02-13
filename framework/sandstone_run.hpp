/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_RUN_H
#define SANDSTONE_RUN_H

TestResult child_run(/*nonconst*/ struct test *test, int child_number);
TestResult run_one_test(const test_cfg_info &test_cfg, PerThreadFailures &per_thread_failures);

#endif // SANDSTONE_RUN_H
