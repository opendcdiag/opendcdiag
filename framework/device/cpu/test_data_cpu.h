/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_TEST_DATA_CPU_H
#define INC_TEST_DATA_CPU_H

#include "test_data.h"

namespace PerThreadData {
struct alignas(64) TestCpu : TestCommon
{
    /* Thread's effective CPU frequency during execution */
    double effective_freq_mhz;

    void init()
    {
        TestCommon::init();
        effective_freq_mhz = 0.0;
    }
};

using Test = TestCpu;

} // namespace PerThreadData

#endif /* INC_TEST_DATA_CPU_H */
