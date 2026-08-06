/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "topology_cpu.h"

#include <map>
#include <vector>

static void populate_core_group(Topology::CoreGrouping *group, const Topology::Thread *begin,
                                const Topology::Thread *end)
{
    // fill in the threads
    auto fill_in_threads = [&](auto &where, auto what) {
        const Topology::Thread *first = begin;
        const Topology::Thread *last = first;
        for ( ; last != end; ++last) {
            if (last->*what == first->*what)
                continue;
            where.push_back({ { first, last } });
            first = last;
        }
        // add any remainders
        where.push_back({ { first, end } });
    };

    fill_in_threads(group->cores, &Topology::Thread::core_id);
    // fill_in_threads(group->modules, &Topology::Thread::module_id);
}

Topology Topology::build_topology(std::span<const Thread> threads)
{
    const cpu_info_t *info = threads.data();
    const cpu_info_t *const end = threads.data() + threads.size();

    std::vector<Topology::Package> packages;
    if (threads.empty())
        return Topology({});
    if (int max_package_id = end[-1].package_id; max_package_id >= 0)
        packages.reserve(max_package_id + 1);
    else
        return Topology({});

    while (info != end) {
        if (info->package_id < 0 || info->core_id < 0 || info->thread_id < 0)
            return Topology({});

        Topology::Package *pkg = &packages.emplace_back();

        // scan forward to the end of this package
        const Topology::Thread *first = info;
        const Topology::Thread *groupfirst = info;
        int core_count = 0;
        for (int last_core_id = -1; info != end; ++info) {
            if (info->core_id < 0 || info->thread_id < 0)
                return Topology({});
            if (info->package_id != first->package_id)
                break;
            if (info->core_id != last_core_id) {
                ++core_count;
                last_core_id = info->core_id;
            }

            bool is_new_group = info->numa_id != groupfirst->numa_id;
            if (!is_new_group)
                is_new_group = info->die_id != groupfirst->die_id;
            if (!is_new_group)
                is_new_group = info->native_core_type != groupfirst->native_core_type;
            if (is_new_group) {
                populate_core_group(&pkg->groups.emplace_back(), groupfirst, info);
                groupfirst = info;
            }
        }

        // populate the full core
        pkg->cores.reserve(core_count + 1);
        populate_core_group(pkg, first, info);

        // populate the last core group, which may be the only one too
        Topology::CoreGrouping *lastgroup = &pkg->groups.emplace_back();
        if (pkg->groups.size() == 1)
            lastgroup->CoreGrouping::operator=(*pkg);    // just copy the Package
        else
            populate_core_group(lastgroup, groupfirst, info);
    }

    return Topology(std::move(packages));
}

Topology::Data Topology::clone() const
{
    Data result;
    result.all_threads.assign(device_info, device_info + device_count());
    result.packages = packages;

    // now update all spans to point to the data we carry
    for (Package &pkg : result.packages) {
        for (Core &core : pkg.cores) {
            int starting_cpu = core.threads.front().cpu();
            int ending_cpu = core.threads.back().cpu();
            core.threads = { result.all_threads.data() + starting_cpu,
                             result.all_threads.data() + ending_cpu + 1 };
        }
    }
    return result;
}
