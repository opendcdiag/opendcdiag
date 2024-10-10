/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"

bool read_msr(int cpu, uint32_t msr, uint64_t * value)
{
    errno = ENOSYS;
    return false;
}

bool write_msr(int cpu, uint32_t msr, uint64_t value)
{
    errno = ENOSYS;
    return false;
}
