/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <topology.h>

#include <limits>

#include <windows.h>

static constexpr unsigned MaxLogicalProcessorsPerGroup =
        std::numeric_limits<KAFFINITY>::digits;

static constexpr LogicalProcessor from_processor_number(PROCESSOR_NUMBER n)
{
    return LogicalProcessor(n.Group * MaxLogicalProcessorsPerGroup + n.Number);
}

LogicalProcessorSet ambient_logical_processor_set()
{
    LogicalProcessorSet result = {};        // memsets to zero
    static_assert(sizeof(result.array[0]) * CHAR_BIT == MaxLogicalProcessorsPerGroup);

    WORD group_count = GetActiveProcessorGroupCount();
    PROCESSOR_NUMBER number = {};
    for (number.Group = 0; number.Group < group_count; ++number.Group) {
        DWORD processors = GetActiveProcessorCount(number.Group);
        for (number.Number = 0; number.Number < processors; number.Number++)
            result.set(from_processor_number(number));
    }
    return result;
}
