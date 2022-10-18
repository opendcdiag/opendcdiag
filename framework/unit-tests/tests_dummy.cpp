/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"

// This defines a dummy test just so the __start_tests and __stop_tests
// symbols get defined by the linker.

DECLARE_TEST_INNER2(dummy, nullptr)
END_DECLARE_TEST

