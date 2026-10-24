/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

// Standalone comparison tests need these symbols to link. The stubs abort()
// on mismatches; death tests can verify that the reporting path is reached.

#include "sandstone.h"

#include <cstdlib>

#undef _memcmp_fail_report

extern "C" void _report_fail_msg(const char *, int, const char *, ...)
{
    std::abort();
}

extern "C" void _memcmp_fail_report(const void *, const void *, size_t, DataType, const char *, ...)
{
    std::abort();
}

extern "C" void _memcmp_fail_report_cb(const void *, const void *, size_t, DataType,
                                     char *(*)(void *, ptrdiff_t), void *)
{
    std::abort();
}

extern "C" bool _memcmp_or_fail_check_fmt(const char *, ...)
{
    return true;
}

extern "C" bool _memcmp_fail_check_cb(char *(*)(void *, ptrdiff_t), void *, size_t)
{
    return true;
}

namespace SandstoneMemcmpOrFail {

[[noreturn, gnu::cold]] void
report(const void *, const void *, size_t, DataType, FormatterCallback,
       const void *, void *)
{
    std::abort();
}

// test_formatter() is only called on the match path (assert()-gated
// self-check of the formatter callback), so it's not [[noreturn]] upstream;
// just run the callback for real.
bool test_formatter(std::function<std::string ()> cb, size_t)
{
    cb();
    return true;
}

bool test_formatter(std::function<std::string (ptrdiff_t)> cb, size_t)
{
    cb(0);
    return true;
}

} // namespace SandstoneMemcmpOrFail
