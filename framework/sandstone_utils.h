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
#include <unistd.h>

/*
 * Extra exit codes, from systemd.exec(3)
 * Make sure they're listed in sysexit_reason() in logging.cpp too.
 */
#define EXIT_NOPERMISSION 4     /* The user has insufficient privileges. */
#define EXIT_NOTINSTALLED 5     /* The program is not installed. */
#define EXIT_MEMORY     204     /* Failed to perform an action due to memory shortage. */

/* Extra codes used by the application only */
#define EXIT_INVALID        2
//#define EXIT_ABORTED        3
#define EXIT_INTERRUPTED    128     /* OR'ed with signal */

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

#ifdef _WIN32
inline int dprintf(int fd, const char *fmt, ...)
{
    std::string msg = va_start_and_stdprintf(fmt);
    return write(fd, msg.data(), msg.size());
}
#endif

struct AutoClosingFile
{
    FILE *f = nullptr;
    AutoClosingFile(FILE *f = nullptr) : f(f) {}
    ~AutoClosingFile() { if (f) fclose(f); }
    AutoClosingFile(const AutoClosingFile &) = delete;
    AutoClosingFile(AutoClosingFile &&other) : f(other.f) { other.f = nullptr; }
    AutoClosingFile &operator=(const AutoClosingFile &) = delete;
    AutoClosingFile &operator=(AutoClosingFile &&other)
    {
        if (f)
            fclose(f);
        f = other.f;
        other.f = nullptr;
        return *this;
    }
    operator FILE *() const { return f; }
};

#endif //SANDSTONE_UTILS_H_INCLUDED
