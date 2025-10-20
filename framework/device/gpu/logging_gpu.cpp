/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "logging.h"
#include "test_data_gpu.h"

#if !SANDSTONE_NO_LOGGING
std::string AbstractLogger::thread_id_header_for_device(int cpu, int verbosity)
{
    std::string line;
    return line;
}

void AbstractLogger::print_thread_header_for_device(int fd, PerThreadData::Test *thr)
{

}

void AbstractLogger::print_fixed_for_device()
{

}

#endif // !SANDSTONE_NO_LOGGING
