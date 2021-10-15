/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_IOVEC_H
#define SANDSTONE_IOVEC_H

#include <sandstone_utils.h>

#include <string_view>
#include <sys/uio.h>
#include <unistd.h>

namespace {
struct IoVec : iovec
{
    constexpr IoVec() : iovec{nullptr, 0} {}
    IoVec(char &c)
        : IoVec(std::string_view(&c, 1))
    {
    }
    IoVec(const char *str)
        : IoVec(std::string_view(str))
    {
    }
    IoVec(std::string_view str)
    {
        iov_base = const_cast<char *>(str.data());
        iov_len = str.size();
    }
};
static_assert(sizeof(IoVec[2]) == sizeof(struct iovec[2]));

template <typename... Args>
[[maybe_unused]] ssize_t writeln(int fd, Args &&... args)
{
    IoVec vec[] = { IoVec(args)..., "\n" };
    return writev(fd, vec, std::size(vec));
}

#if _POSIX_VERSION < 200809L && !defined(__GLIBC__)
[[maybe_unused]] int dprintf(int fd, const char *fmt, ...)
{
    std::string msg = va_start_and_stdprintf(fmt);
    return write(fd, msg.data(), msg.size());
}
#endif
}

#endif  // SANDSTONE_IOVEC_H
