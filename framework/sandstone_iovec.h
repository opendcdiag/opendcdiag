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
template <typename... Args>
inline ssize_t writevec(int fd, const Args &... args)
{
    struct IoVecMaker {
        struct iovec operator()(struct iovec vec)
        {
            return vec;
        }

        struct iovec operator()(const void *ptr, size_t size)
        {
            return { .iov_base = const_cast<void *>(ptr), .iov_len = size };
        }

        struct iovec operator()(std::string_view str)
        {
            return operator()(str.data(), str.size());
        }

        struct iovec operator()(const char *str)
        {
            return operator()(str, strlen(str));
        }

        struct iovec operator()(const char &c)
        {
            return operator()(&c, 1);
        }

        struct iovec operator()(const uint8_t &b)
        {
            return operator()(&b, 1);
        }
    } maker;

    iovec vec[] = { maker(args)... };
    return writev(fd, vec, std::size(vec));
}

template <typename... Args>
inline ssize_t writeln(int fd, Args &&... args)
{
    return writevec(fd, std::forward<Args>(args)..., '\n');
}
}

#endif  // SANDSTONE_IOVEC_H
