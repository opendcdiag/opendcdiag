/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

// PLEASE READ BEFORE EDITING:
//     This is a clean file, meaning everyrthing in it is properly unit tested
//     Please do not add anything to this file unless it is unit tested.
//     All unit tests should be put in framework/unit-tests/sandstone_utils.cpp

#ifndef SANDSTONE_UTILS_H_INCLUDED
#define SANDSTONE_UTILS_H_INCLUDED

#include "sandstone.h"

#include <string>

#include <stdarg.h>
#include <sysexits.h>

/*
 * Extra exit codes, from systemd.exec(3)
 */
#define EXIT_NOTINSTALLED 5     /* The program is not installed. */
#define EXIT_MEMORY     204     /* Failed to perform an action due to memory shortage. */

// Macro to help create a std::string from variable arguments: @p fmt must be
// both the printf-style format string and the last argument before the variadic list
#define va_start_and_stdprintf(fmt)                     \
    __extension__ ({                                    \
        va_list va; va_start(va, fmt);                  \
        auto r = vstdprintf(fmt, va);                   \
        va_end(va);                                     \
        std::move(r);                                   \
    })

std::string format_single_type(DataType type, int typeSize, const uint8_t *data, bool detailed);
std::string stdprintf(const char *fmt, ...) ATTRIBUTE_PRINTF(1, 2);
std::string vstdprintf(const char *fmt, va_list va);

#endif //SANDSTONE_UTILS_H_INCLUDED
