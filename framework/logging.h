/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_LOGGING_H
#define INC_LOGGING_H

#include "sandstone_chrono.h"

#include <string>

std::string format_duration(MonotonicTimePoint tp, FormatDurationOptions opts = FormatDurationOptions::WithoutUnit);

std::string thread_id_header_for_device(int device, int verbosity);

void print_thread_header_kv_for_device(int fd, int device, const char *prefix);
void print_thread_header_tap_for_device(int fd, int device, int verbosity);

#endif /* INC_LOGGING_H */
