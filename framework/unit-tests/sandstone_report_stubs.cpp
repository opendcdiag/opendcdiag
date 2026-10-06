/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

// Gtests that only exercise the success path of reporting helpers still need
// these symbols to link. The stubs abort() if they are ever reached.

#include "sandstone.h"

#include <cstdlib>

extern "C" void _report_fail_msg(const char *, int, const char *, ...)
{
    std::abort();
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
