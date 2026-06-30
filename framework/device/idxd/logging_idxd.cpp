/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "logging.h"

#if !SANDSTONE_NO_LOGGING
std::string AbstractLogger::thread_id_header_for_device(int thread, LogLevelVerbosity verbosity)
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

void dump_device_state(std::string&, int)
{

}

#else
void dump_device_state(std::string&, int)
{}
#endif // !SANDSTONE_NO_LOGGING
