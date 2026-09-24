/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "device/device.h"
#include "topology.h"

#include <algorithm>
#include <charconv>
#include <format>
#include <fstream>
#include <numeric>
#include <string>
#include <system_error>
#include <vector>

template <typename BdfType>
    requires requires(const BdfType& bdf) { bdf.domain; bdf.bus; bdf.device; bdf.function; }
std::vector<int> find_numa_local_cpus(const BdfType& bdf)
{
    std::vector<int> res;
    auto address = std::format("{:04x}:{:02x}:{:02x}.{:01x}", static_cast<uint32_t>(bdf.domain),
        static_cast<uint32_t>(bdf.bus), static_cast<uint32_t>(bdf.device), static_cast<uint32_t>(bdf.function));
    auto file = std::format("/sys/bus/pci/devices/{}/local_cpulist", address);

    std::ifstream infile;
    infile.open(file.data(), std::ios::binary);
    if (!infile.is_open()) {
        return res;
    }

    std::string contents;
    infile >> contents;
    infile.close();

    struct Range { int start, stop; };
    std::vector<Range> ranges;
    const char* ptr = contents.data();
    const char* const endptr = ptr + contents.size();
    while (ptr != endptr) {
        auto& range = ranges.emplace_back();
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
    }

    for (auto& range : ranges) {
        if (range.start != range.stop) {
            std::vector<int> tmp(range.stop - range.start + 1);
            std::iota(tmp.begin(), tmp.end(), range.start);
            res.insert(res.end(), tmp.begin(), tmp.end());
        } else {
            res.emplace_back(range.start);
        }
    }

    return res;
}

int cpulist_intersection(std::vector<int>& list1, const std::vector<int>& list2, size_t start1, bool remove)
{
    if (list1.empty())
        return -1;

    start1 %= list1.size();
    int res = list1[start1];
    for (size_t i = 0; i < list1.size(); ++i) {
        const int cpu = list1[(start1 + i) % list1.size()];
        if (list2.empty() || std::binary_search(list2.begin(), list2.end(), cpu)) {
            res = cpu;
            break;
        }
    }

    if (remove) {
        list1.erase(std::remove(list1.begin(), list1.end(), res), list1.end());
    }

    return res;
}

#if SANDSTONE_DEVICE_IDXD
template std::vector<int> find_numa_local_cpus<bdf_t>(const bdf_t&);
#elif SANDSTONE_DEVICE_GPU
template std::vector<int> find_numa_local_cpus<ze_pci_address_ext_t>(const ze_pci_address_ext_t&);
#endif
