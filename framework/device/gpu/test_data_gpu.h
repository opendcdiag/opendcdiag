/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_TEST_DATA_GPU_H
#define INC_TEST_DATA_GPU_H

#include "test_data.h"

namespace PerThreadData {
struct alignas(64) TestGpu : TestCommon
{
    /* Thread's something */
    int foo;

    void init()
    {
        TestCommon::init();
    }
};

using Test = TestGpu;

} // namespace PerThreadData

#endif /* INC_TEST_DATA_GPU_H */
