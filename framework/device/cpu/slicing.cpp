/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"
#include "topology.h"
#include "topology_cpu.h"

#include <cassert>
#include <cstddef>
#include <vector>

void slice_plan_init_for_device(SlicePlans::SlicesArray& plans, int max_cores_per_slice)
{
    // The heuristic is enabled by max_cores_per_slice == 0 and a valid
    // topology:
    // - if the CPU Set has less than MinimumCpusPerSocket (4)
    //   logical processors per socket (on average), we ignore the topology and
    //   will instead run in slices of up to DefaultMaxCoresPerSlice (32)
    //   logical processors.
    // - otherwise, we'll have at least one slice per socket
    //   * if the socket has more than 32 cores or is a hybrid part, we'll
    //     attempt to slice it, first according to core types and then at NUMA
    //     node boundaries
    //   * if a core group has more than 32 cores, we'll attempt to split it
    //     evenly so each slice has at most 32 cores (64 threads on a system with
    //     2 threads per core)
    // - we always keep the cores of a given module and threads of a core
    //   in the same slice
    //   * this means on some situations the slices may have more than 32 cores
    //     (i.e. the 32nd and 33rd core were part of the same module)
    //
    // If the user specifies a --max-cores-per-slice option in the
    // command-line, it will bypass the heuristic but keep the slice balancing
    // as described above. Be aware bypasses the minimum average processor per
    // socket check.

    int max_cpu = num_cpus();
    const Topology &topology = Topology::topology();
    while (topology.isValid()) {     // not a loop, just so we can use break
        static constexpr int MinimumCpusPerSocket = SlicePlans::MinimumCpusPerSocket;
        static constexpr int DefaultMaxCoresPerSlice = SlicePlans::DefaultMaxCoresPerSlice;

        if (max_cores_per_slice == 0) {
            // apply defaults
            int average_cpus_per_socket = max_cpu / topology.packages.size();
            max_cores_per_slice = DefaultMaxCoresPerSlice;
            if (average_cpus_per_socket < MinimumCpusPerSocket)
                break;
        }

        // set up proper plans
        std::vector<DeviceRange> &isolate_socket = plans[SlicePlans::IsolateSockets];
        std::vector<DeviceRange> &isolate_numa = plans[SlicePlans::IsolateNuma];
        std::vector<DeviceRange> &split = plans[SlicePlans::Heuristic];
        auto push_to = [](std::vector<DeviceRange> &to, auto start, auto end) {
            int start_cpu = start[0].threads.front().cpu();
            int end_cpu = end[-1].threads.back().cpu();
            assert(end_cpu >= start_cpu);
            to.push_back(DeviceRange{ start_cpu, end_cpu + 1 - start_cpu });
        };

        for (const Topology::Package &p : topology.packages) {
            if (p.cores.size() == 0)
                continue;       // untested socket

            push_to(isolate_socket, p.cores.begin(), p.cores.end());

            // if we have to split, we'll try to split along NUMA node lines
            for (const Topology::NumaNode &n : p.numa_domains) {
                if (n.cores.size() == 0)
                    continue;   // untested node (shouldn't happen!)

                push_to(isolate_numa, n.cores.begin(), n.cores.end());

                auto begin = n.cores.begin();
                const auto end = n.cores.end();
                ptrdiff_t slice_count = n.cores.size() / max_cores_per_slice;
                if (n.cores.size() % max_cores_per_slice)
                    ++slice_count;  // round up (also makes at least 1)
                ptrdiff_t slice_size = (n.cores.size() + slice_count - 1) / slice_count;

                // populate slices of roughly slice_size cores, but keep
                // modules within the same slice
                while (end - begin > slice_size) {
                    auto e = begin + slice_size;
                    while (e != end && e[-1].threads[0].module_id == e[0].threads[0].module_id)
                        ++e;
                    push_to(split, begin, e);
                    begin = e;
                }
                if (begin != end)
                    push_to(split, begin, end);
            }
        }
        return;
    }

    if (max_cores_per_slice == 0) {
        // set to full system
        std::vector plan = { DeviceRange{ 0, thread_count() } };
        plans.fill(plan);
    } else {
        // dumb plan, not *cores*
        int slice_count = (max_cpu - 1) / max_cores_per_slice + 1;
        std::vector<DeviceRange> plan;
        plan.reserve(slice_count);

        int slice_size = max_cpu / slice_count;
        if (max_cpu % slice_count)
            ++slice_size;       // round up the slice size
        int cpu = 0;
        for ( ; cpu < max_cpu - slice_size; cpu += slice_size)
            plan.push_back(DeviceRange{ cpu, slice_size });
        plan.push_back(DeviceRange{ cpu, max_cpu - cpu });
        plans.fill(plan);
    }
}
