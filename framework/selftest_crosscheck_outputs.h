/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SELFTEST_CROSSCHECK_OUTPUTS_H
#define SELFTEST_CROSSCHECK_OUTPUTS_H

#include "sandstone.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
int selftest_crosscheck_outputs_init(struct test *);
int selftest_crosscheck_outputs_run(struct test *, int);
int selftest_crosscheck_outputs_cleanup(struct test *);
int selftest_crosscheck_votes_init(struct test *);
int selftest_crosscheck_votes_run(struct test *, int);
int selftest_crosscheck_votes_cleanup(struct test *);
int selftest_crosscheck_outputs_c_run(struct test *, int);
void selftest_crosscheck_outputs_c_input(uint32_t generation);
void selftest_crosscheck_outputs_c_golden(void);
void selftest_crosscheck_outputs_c_conflict(void);
void selftest_crosscheck_outputs_cpp_peer(bool conflict);
#ifdef __cplusplus
}
#endif

#endif // SELFTEST_CROSSCHECK_OUTPUTS_H
