/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "topology.h"
#include "topology_gpu.h"
#include "sandstone_p.h"

#include <algorithm>
#include <set>
#include <span>

struct gpu_info_t *cpu_info = nullptr;

int num_packages()
{
    // Return fixed 1
    // TODO: reconsider what to return
    return 1;
}

std::unique_ptr<DeviceScheduler> make_rescheduler(std::string_view mode)
{
    return nullptr;
}

namespace {
int parse_int(char* arg, const char* orig_arg) {
    errno = 0;
    char *endptr = arg;
    long n = strtol(arg, &endptr, 0);
    if (n == 0 && errno) {
        fprintf(stderr, "%s: error: Invalid GPU set parameter: %s (%m)\n",
                program_invocation_name, orig_arg);
        exit(EX_USAGE);
    }
    if (n != int(n)) {
        fprintf(stderr, "%s: error: Invalid GPU set parameter: %s (out of range)\n",
                program_invocation_name, orig_arg);
        exit(EX_USAGE);
    }
    arg = endptr;       // advance
    return int(n);
};
}

/// We support two modes:
/// --deviceset=0,1,2            -> numa-local continuous cpus are auto attached (for example 0,1,2 or 0,32,1) (if present in the system)
/// --deviceset=g0c2,g1c4,g2c10  -> manually specified cpus are attached (if present in the system)
/// By "present in the system" we can mean constrained set of cpus enabled by 'taskset'.
/// TODO: should we allow to specify concrete GPUs/sockets/tiles/whatever (multi-socket GPU)?
/// TODO: specify concrete physical card, not just the index from the drver (which may change like Gaudi's)
void apply_deviceset_param(char *param)
{
    if (SandstoneConfig::RestrictedCommandLine)
        return;

    struct GpuNumberMatch {
        int gpu_number;
        bool operator()(const gpu_info_t &gpu)
        { return gpu.gpu_number == gpu_number; }
    };

    std::span<gpu_info_t> old_gpu_info(cpu_info, sApp->thread_count);
    std::vector<gpu_info_t> new_gpu_info;
    int total_matches = 0;

    std::set<uint32_t> result; // set of unique gpu numbers to disallow duplicate entries
    new_gpu_info.reserve(old_gpu_info.size());

    bool add = true;
    if (*param == '!') {
        // we're removing from the existing set
        new_gpu_info = { old_gpu_info.begin(), old_gpu_info.end() };
        add = false;
        ++param;
    }

    static const auto apply_to_set = [&](const gpu_info_t &gpu) {
        if (result.contains(gpu.gpu_number)) { // we've got a duplicate
            return;
        }

        if (add) {
            auto it = std::lower_bound(new_gpu_info.begin(), new_gpu_info.end(), gpu);
            new_gpu_info.insert(it, gpu);
        } else {
            auto it = std::find_if(new_gpu_info.begin(), new_gpu_info.end(), GpuNumberMatch{gpu.gpu_number} );
            if (it == new_gpu_info.end())
                return;
            new_gpu_info.erase(it);
        }
        result.insert(gpu.gpu_number);
        ++total_matches;
    };

    std::string p = param;
    for (char *arg = strtok(p.data(), ","); arg; arg = strtok(nullptr, ",")) {
        const char *orig_arg = arg;
        char c = *arg;
        if (c >= '0' && c <= '9') {
            // gpu number
            int gpu_number = parse_int(arg, orig_arg);
            if (*arg != '\0') {
                fprintf(stderr, "%s: error: Invalid GPU set parameter: %s (could not parse)\n",
                        program_invocation_name, orig_arg);
                exit(EX_USAGE);
            }

            auto it = std::find_if(old_gpu_info.begin(), old_gpu_info.end(), GpuNumberMatch{gpu_number} );
            if (it == old_gpu_info.end()) {
                fprintf(stderr, "%s: error: Invalid GPU set parameter: %s (no such gpu)\n",
                        program_invocation_name, orig_arg);
                exit(EX_USAGE);
            }
            apply_to_set(*it);
        } else if (c == 'g') { //   "gXXcYY" format
            arg++;
            int gpu_number = parse_int(arg, orig_arg);

            if (*arg != 'c') {
                fprintf(stderr, "%s: error: Invalid CPU format for GPU %u: %s (correct format is 'gXXcYY')\n",
                        program_invocation_name, gpu_number, orig_arg);
                exit(EX_USAGE);
            }
            auto it = std::find_if(old_gpu_info.begin(), old_gpu_info.end(), GpuNumberMatch{gpu_number} );
            if (it == old_gpu_info.end()) {
                fprintf(stderr, "%s: error: Invalid GPU set parameter: %s (no such gpu)\n",
                        program_invocation_name, orig_arg);
                exit(EX_USAGE);
            }

            arg++;
            int cpu_number = parse_int(arg, orig_arg);

            // check if cpu is enabled in the system
            LogicalProcessorSet enabled_cpus = ambient_logical_processor_set();
            if (!enabled_cpus.is_set(LogicalProcessor{cpu_number})) {
                fprintf(stderr, "%s: error: Invalid CPU set parameter for GPU %u: %s (no such cpu)\n",
                        program_invocation_name, gpu_number, orig_arg);
                exit(EX_USAGE);
            }

            // assign logical cpu number and apply the changed gpu to the set
            it->cpu_number = cpu_number;
            apply_to_set(*it);
            // TODO: this enables erasing. I can disable erasing for gXXcYY format as it's a bit confusing to support that.
        }
    }

    if (total_matches == 0) {
        fprintf(stderr, "%s: error: --deviceset matched nothing, this is probably not what you wanted.\n",
                program_invocation_name);
        exit(EX_USAGE);
    }
    if (!add && new_gpu_info.size() == 0) {
        fprintf(stderr, "%s: error: negated --deviceset matched everything, this is probably not "
                        "what you wanted.\n", program_invocation_name);
        exit(EX_USAGE);
    }

    assert(total_matches == result.size());
    if (add)
        assert(total_matches == new_gpu_info.size());
    else
        assert(total_matches == old_gpu_info.size() - new_gpu_info.size());

    // update_topology(new_gpu_info);
}

std::string build_failure_mask_for_topology(const struct test* test)
{
    return {};
}

uint32_t mixin_from_device_info(int thread_num)
{
    return thread_num;
}

void print_temperature_of_device()
{

}

template <>
GpusSet detect_devices<GpusSet>()
{
    sApp->thread_count = 1;
    return GpusSet{};
}

template <>
void setup_devices<GpusSet>(const GpusSet &enabled_devices)
{

}

void restrict_topology(DeviceRange range)
{

}

void analyze_test_failures_for_topology(const struct test *test, const PerThreadFailures &per_thread_failures)
{

}

void slice_plan_init(int max_cores_per_slice)
{
    std::vector plan = { DeviceRange{ 0, thread_count() } };
    sApp->slice_plans.plans.fill(plan);
}
