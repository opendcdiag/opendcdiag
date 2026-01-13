/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "topology.h"
#include "topology_gpu.h"
#include "sandstone_p.h"
#include "ze_enumeration.h"

#include <algorithm>

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

/// Detect and return a set of all Intel devices present in the system.
template <>
GpusSet detect_devices<GpusSet>()
{
    GpusSet enabled_devices;
    auto ret = for_each_ze_device([&](ze_device_handle_t device_handle, ze_driver_handle_t driver, const MultiSliceGpu& indices) {
        enabled_devices.emplace(indices, ZeDeviceCtx{ .driver = driver, .ze_handle = device_handle });
        return EXIT_SUCCESS;
    });
    ret += for_each_zes_device([&](zes_device_handle_t device_handle, ze_driver_handle_t, const MultiSliceGpu& indices) {
        if (!enabled_devices.count(indices)) {
            return EXIT_FAILURE;
        }
        enabled_devices.at(indices).zes_handle = device_handle; // matching indices must mean the exact same device
        return EXIT_SUCCESS;
    });

    if (ret != EXIT_SUCCESS) [[unlikely]] {
        fprintf(stderr, "%s: internal error: gpu enumeration failed!\n",
                program_invocation_name);
        return enabled_devices;
    }
    if (enabled_devices.empty()) [[unlikely]] {
        fprintf(stderr, "%s: internal error: gpu devices set appears to be empty!\n",
                program_invocation_name);
        return enabled_devices;
    }

    sApp->thread_count = enabled_devices.size();
    sApp->user_thread_data.resize(sApp->thread_count);

    return enabled_devices;
}

namespace {
/// Processes 'sparse' LogicalProcessorSet and returns a vector of enabled logical cpus
/// that can be easily iterated over.
std::vector<int> find_enabled_logical_cpus()
{
    std::vector<int> res;

    auto enabled_cpus = ambient_logical_processor_set();
    auto cpus_to_find = std::min(thread_count(), enabled_cpus.count());

    auto next_cpu = 0;
    while (cpus_to_find) {
        while (!enabled_cpus.is_set(LogicalProcessor{next_cpu})) {
            next_cpu++;
        }
        res.emplace_back(next_cpu++);
        cpus_to_find--;
    }

    return res;
}
}

/// Builds whole cpu_info array, then builds topology based on that.
template <>
void setup_devices<GpusSet>(const GpusSet &enabled_devices)
{
    cpu_info = sApp->shmem->device_info;

    assert(enabled_devices.size() == thread_count());
    gpu_info_t* info = cpu_info;
    const gpu_info_t* cend = cpu_info + thread_count();

    auto enabled_cpus = find_enabled_logical_cpus();
    auto enabled_cpu_index = 0;

    std::ranges::for_each(enabled_devices, [&](auto& enabled_device) {
        // TODO: there is no info about numa-locality for Intel GPUs, nor L0 API calls to query it.
        // For those reasons we assign CPUs in the order returned from ambient_logical_processor_set().
        info->cpu_number = enabled_cpus[enabled_cpu_index++ % enabled_cpus.size()];

        info->package_id = -1; // unknown and not needed
        info->gpu_number = enabled_device.first.gpu_number;
        info->device_index = enabled_device.first.device_index;
        info->subdevice_index = enabled_device.first.subdevice_index;

        // We do not store them in gpu_info, only use them to get properties of interest.
        auto ze_handle = enabled_device.second.ze_handle;
        auto zes_handle = enabled_device.second.zes_handle;

        ze_pci_ext_properties_t pci_prop = { .stype = ZE_STRUCTURE_TYPE_PCI_EXT_PROPERTIES };
        zeDevicePciGetPropertiesExt(ze_handle, &pci_prop);
        info->bdf = pci_prop.address;

        zes_device_properties_t zes_device_prop = { .stype = ZES_STRUCTURE_TYPE_DEVICE_PROPERTIES };
        zesDeviceGetProperties(zes_handle, &zes_device_prop);
        info->num_subdevices = zes_device_prop.numSubdevices;

        ze_device_properties_t device_prop = { .stype = ZE_STRUCTURE_TYPE_DEVICE_PROPERTIES };
        zeDeviceGetProperties(ze_handle, &device_prop);
        info->device_properties = device_prop;

        ze_device_compute_properties_t compute_prop = { .stype = ZE_STRUCTURE_TYPE_DEVICE_COMPUTE_PROPERTIES };
        zeDeviceGetComputeProperties(ze_handle, &compute_prop);
        info->compute_properties = std::move(compute_prop);

        info++;
    });
    assert(info == cend);

    // cached_topology() = build_topology();
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
