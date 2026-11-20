/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SELFTEST_CROSSCHECK_OUTPUTS_H
#define SELFTEST_CROSSCHECK_OUTPUTS_H

#include "sandstone.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
extern const struct test_group group_positive, group_negative;

int selftest_crosscheck_outputs_c_run(struct test *, int);
void selftest_crosscheck_outputs_c_vote(const uint32_t *data, size_t count);
void selftest_crosscheck_outputs_c_input(uint32_t generation);
void selftest_crosscheck_outputs_c_init_outputs(void);
void selftest_crosscheck_outputs_c_conflict(void);
void selftest_crosscheck_outputs_cpp_peer(bool conflict);
#ifdef __cplusplus
}
#endif

#endif // SELFTEST_CROSSCHECK_OUTPUTS_H
