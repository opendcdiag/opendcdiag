/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SELFTEST_CROSSCHECK_OUTPUTS_H
#define SELFTEST_CROSSCHECK_OUTPUTS_H

#include "sandstone.h"

extern const struct test_group group_positive, group_negative;

extern "C" {
void selftest_crosscheck_outputs_cpp_peer(bool conflict);
}

#endif // SELFTEST_CROSSCHECK_OUTPUTS_H
