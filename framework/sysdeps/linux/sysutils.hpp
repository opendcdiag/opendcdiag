/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SYSDEPS_LINUX_SYSUTILS_H
#define SYSDEPS_LINUX_SYSUTILS_H

#include <cerrno>
#include <charconv>
#include <numeric>
#include <string>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

struct CpuListRange
{
    int start;
    int stop;

    static std::vector<int> to_vector(const std::vector<CpuListRange>& ranges)
    {
        std::vector<int> res;
        for (auto& range : ranges) {
            if (range.start != range.stop) {
                auto oldsize = res.size();
                res.resize(oldsize + range.stop - range.start + 1);
                std::iota(res.begin() + oldsize, res.end(), range.start);
            } else {
                res.emplace_back(range.start);
            }
        }
        return res;
    }
};

/// Returns a vector of cpulist ranges read from cpulist file.
inline std::vector<CpuListRange> read_cpulist_file(const std::string& file)
{
    std::vector<CpuListRange> res;

    int fd = open(file.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return res;

    std::string contents;
    char buffer[4096];
    while (true) {
        ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count > 0) {
            contents.append(buffer, count);
        } else if (count == 0) {
            break;
        } else if (errno != EINTR) {
            close(fd);
            return {};
        }
    }
    close(fd);

    const char* ptr = contents.data();
    size_t token_end = contents.find_first_of(" \t\n\r\f\v");
    const char* const endptr = ptr + (token_end == std::string::npos ? contents.size() : token_end);
    while (ptr != endptr) {
        CpuListRange range{};
        auto [nextptr, ec] = std::from_chars(ptr, endptr, range.start);
        if (ec != std::errc()) {
            return res;
        }
        ptr = nextptr;
        if (ptr != endptr && *ptr == '-') {
            // it's a range
            auto [nextptr2, ec] = std::from_chars(ptr + 1, endptr, range.stop);
            if (ec != std::errc()) {
                return res;
            }
            ptr = nextptr2;
        } else {
            // it was a single number
            range.stop = range.start;
        }
        if (ptr != endptr && *ptr == ',') {
            ++ptr;   // there's more
        }
        res.emplace_back(range);
    }

    return res;
}

#endif /* SYSDEPS_LINUX_SYSUTILS_H */
