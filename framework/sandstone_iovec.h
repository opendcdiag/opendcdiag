/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_IOVEC_H
#define SANDSTONE_IOVEC_H

#include <sandstone_utils.h>

#include <string_view>
#include <sys/uio.h>
#include <unistd.h>

namespace {
[[maybe_unused]] static struct iovec IoVec(struct iovec vec)
{
    return vec;
}

[[maybe_unused]] static struct iovec IoVec(std::string_view str = {})
{
    return { .iov_base = const_cast<char *>(str.data()), .iov_len = str.size() };
}

[[maybe_unused]] static struct iovec IoVec(const char *str)
{
    return IoVec(std::string_view(str));
}

template <typename... Args>
[[maybe_unused]] ssize_t writeln(int fd, Args &&... args)
{
    iovec vec[] = { IoVec(args)..., IoVec("\n") };
    return writev(fd, vec, std::size(vec));
}

#ifdef _WIN32
[[maybe_unused]] int dprintf(int fd, const char *fmt, ...)
{
    std::string msg = va_start_and_stdprintf(fmt);
    return write(fd, msg.data(), msg.size());
}
#endif
}

#endif  // SANDSTONE_IOVEC_H
