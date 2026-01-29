/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "topology.h"
#include "topology_gpu.h"
#include "sandstone_p.h"
#include "ze_enumeration.h"

#include <algorithm>
#include <format>
#include <fstream>
#include <numeric>
#include <set>
#include <span>

struct gpu_info_t *device_info = nullptr;

int num_packages()
{
    // Return fixed 1
    // TODO: reconsider what to return
    return 1;
}

std::unique_ptr<DeviceScheduler> make_rescheduler(RescheduleMode mode)
{
    return nullptr;
}

namespace {
Topology &cached_topology()
{
    static Topology cached_topology = Topology();
    return cached_topology;
}
}

const Topology &Topology::topology()
{
    return cached_topology();
}

int for_each_topo_device(std::function<int(gpu_info_t&)> func)
{
    const auto& topo = Topology::topology();
    for (const auto& device : topo.devices) {
        if (std::holds_alternative<Topology::RootDevice>(device)) {
            auto tiles = std::get<Topology::RootDevice>(device);
            for (const auto& dev : tiles) {
                auto info = device_info[dev.gpu()];
                auto ret = func(info);
                if (ret != EXIT_SUCCESS)
                    return ret;
            }
        } else {
            auto dev = std::get<Topology::EndDevice>(device);
            auto info = device_info[dev->gpu()];
            auto ret = func(info);
            if (ret != EXIT_SUCCESS)
                return ret;
        }
    }
    return EXIT_SUCCESS;
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

/// Updates device_info and topology based on new_gpu_info.
void update_topology(std::span<const gpu_info_t> new_gpu_info)
{
    gpu_info_t* end = std::copy(new_gpu_info.begin(), new_gpu_info.end(), device_info);
    int new_thread_count = new_gpu_info.size();
    if (int excess = sApp->thread_count - new_thread_count; excess > 0) {
        // reset excess entries
        std::fill_n(end, excess, gpu_info_t{});
    }

    sApp->thread_count = new_thread_count;
    cached_topology() = build_topology();
}
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

    std::span<gpu_info_t> old_gpu_info(device_info, sApp->thread_count);
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

    LogicalProcessorSet enabled_cpus;
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
            if (enabled_cpus.size_bytes() == 0) {
                enabled_cpus = ambient_logical_processor_set();
            }
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

    update_topology(new_gpu_info);
}

/// Builds mask based on the topology type in a following fashion:
///     ..X..X      for 6 EndDevices
///     ..:X.:.X    for 3 RootDevices (2 EndDevices each)
std::string build_failure_mask_for_topology(const struct test* test)
{
    std::string mask;
    int totalfailcount = 0;
    for_each_topo_device([&](gpu_info_t& info) {
        if (info.subdevice_index == 0 && !mask.empty()) {
            // is RootDevice, and first of the root - prepend with ':'
            mask += ':';
        }
        if (sApp->thread_data(info.gpu())->has_failed()) {
            totalfailcount++;
            mask += 'X';
        } else {
            mask += '.';
        }
        return EXIT_SUCCESS;
    });

    if (totalfailcount == 0) {
        return {};
    }
    return mask;
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
/// Processes 'sparse' LogicalProcessorSet and returns a vector of enabled logical cpus.
std::vector<int> to_vector(const LogicalProcessorSet& set)
{
    std::vector<int> res;

    int i = 0;
    for (LogicalProcessor lp = set.next(); lp != LogicalProcessor::None; ++i) {
        auto& next_cpu = res.emplace_back(std::to_underlying(lp));
        lp = set.next(LogicalProcessor(next_cpu + 1));
    }
    assert(i == set.count());

    return res;
}

/// Reads affinity for given PCI device and constructs a vector of all local logical cpus.
std::vector<int> find_numa_local_cpus(const ze_pci_address_ext_t& bdf)
{
    std::vector<int> res;
    auto address = std::format("{:04x}:{:02x}:{:02x}.{:01x}", bdf.domain, bdf.bus, bdf.device, bdf.function);
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
    char* ptr = contents.data();
    char* endptr;
    while (ptr != contents.data() + contents.size()) {
        auto& range = ranges.emplace_back();
        range.start = strtol(ptr, &endptr, 10);
        if (*endptr == '-') {
            // it's a range
            range.stop = strtol(endptr + 1, &endptr, 10);
        } else {
            // it was a single number
            range.stop = range.start;
        }
        if (*endptr == ',') {
            ++endptr;   // there's more
        }
        ptr = endptr;
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

/// Tries to find an intersection of enabled_cpus and NUMA local CPUs. If no such exists,
/// assigns first cpu from enabled_cpus. Removes the assigned CPU from enabled_cpus
/// to avoid duplicates.
int try_assign_local_cpu(std::vector<int>& enabled_cpus, const ze_pci_address_ext_t& bdf)
{
    int res = -1;
    auto local_cpus = find_numa_local_cpus(bdf);
    if (!local_cpus.empty()) {
        std::vector<int> available_cpus;
        std::ranges::set_intersection(enabled_cpus, local_cpus, std::back_inserter(available_cpus));
        if (!available_cpus.empty()) {
            res = available_cpus[0];
        } else {
            res = enabled_cpus[0];
        }
    } else {
        res = enabled_cpus[0];
    }
    enabled_cpus.erase(std::remove(enabled_cpus.begin(), enabled_cpus.end(), res), enabled_cpus.end());

    return res;
}

#ifdef __linux // TODO: AFAIK we do not plan to support windows, so this ifdef may be redundant
int16_t detect_package_id_via_os(int cpu)
{
    int16_t res = -1;
    if (cpu < 0) { [[unlikely]]
        return res;
    }
    auto file = std::format("/sys/devices/system/cpu/cpu{}/topology/physical_package_id", cpu);

    std::ifstream infile;
    infile.open(file.data());
    if (!infile.is_open()) { [[unlikely]]
        fprintf(stderr, "%s: internal error: unable to find physical_package_id file\n",
                program_invocation_name);
        return res;
    }
    infile >> res;
    infile.close();

    return res;
}
#endif

#define CHECK_EXIT(...) \
    do { \
        auto result = (__VA_ARGS__); \
        if (result != ZE_RESULT_SUCCESS) { \
            fprintf(stderr, "%s: internal error: could not set gpu_info\n", \
                program_invocation_name); \
            exit(EX_USAGE); \
        } \
    } while (0)
}

/// Builds whole device_info array, then builds topology based on that.
template <>
void setup_devices<GpusSet>(const GpusSet &enabled_devices)
{
    device_info = sApp->shmem->device_info;

    assert(enabled_devices.size() == thread_count());
    gpu_info_t* info = device_info;
    const gpu_info_t* cend = device_info + thread_count();

    auto enabled_cpus = to_vector(ambient_logical_processor_set());
    if (enabled_cpus.size() < enabled_devices.size()) {
        fprintf(stderr, "%s: error: not enough CPUs available (%ld CPUs vs %ld GPUs)\n",
                program_invocation_name, enabled_cpus.size(), enabled_devices.size());
        exit(EX_USAGE);
    }

    for (auto &enabled_device : enabled_devices) {
        info->gpu_number = enabled_device.first.gpu_number;
        info->device_index = enabled_device.first.device_index;
        info->subdevice_index = enabled_device.first.subdevice_index;

        // We do not store them in gpu_info, only use them to get properties of interest.
        auto ze_handle = enabled_device.second.ze_handle;
        auto zes_handle = enabled_device.second.zes_handle;

        ze_pci_ext_properties_t pci_prop = { .stype = ZE_STRUCTURE_TYPE_PCI_EXT_PROPERTIES };
        CHECK_EXIT(zeDevicePciGetPropertiesExt(ze_handle, &pci_prop));
        info->bdf = pci_prop.address; // TODO: consider storing as formatted string

        info->cpu_number = try_assign_local_cpu(enabled_cpus, info->bdf);
        info->package_id = detect_package_id_via_os(info->cpu_number);

        zes_device_properties_t zes_device_prop = { .stype = ZES_STRUCTURE_TYPE_DEVICE_PROPERTIES };
        CHECK_EXIT(zesDeviceGetProperties(zes_handle, &zes_device_prop));
        info->num_subdevices = zes_device_prop.numSubdevices;

        ze_device_properties_t device_prop = { .stype = ZE_STRUCTURE_TYPE_DEVICE_PROPERTIES };
        CHECK_EXIT(zeDeviceGetProperties(ze_handle, &device_prop));
        info->device_properties = device_prop;

        ze_device_compute_properties_t compute_prop = { .stype = ZE_STRUCTURE_TYPE_DEVICE_COMPUTE_PROPERTIES };
        CHECK_EXIT(zeDeviceGetComputeProperties(ze_handle, &compute_prop));
        info->compute_properties = std::move(compute_prop);

        info++;
    }
    assert(info == cend);

    cached_topology() = build_topology();
}

/// Called after apply_deviceset_param(). Means we have smaller thread_count and a new range of devices.
/// Changes pointer of device_info, as sApp->shmem has moved. Must also rebuild topology (built upon device_info).
/// TODO: It's very similar to the CPU version. Should we abstract build_topology(), rather than restrict_topology()?
void restrict_topology(DeviceRange range)
{
    assert(range.starting_device + range.device_count <= sApp->thread_count);
    auto old_gpu_info = std::exchange(device_info, sApp->shmem->device_info + range.starting_device);
    int old_thread_count = std::exchange(sApp->thread_count, range.device_count);

    Topology &topo = cached_topology();
    if (old_gpu_info != device_info || old_thread_count != sApp->thread_count /*|| topo.devices.size() == 0  TODO: why would we check that? */) {
        topo = build_topology();
    }
}

void analyze_test_failures_for_topology(const struct test *test, const PerThreadFailures &per_thread_failures)
{

}

void slice_plan_init(int max_cores_per_slice)
{
    std::vector plan = { DeviceRange{ 0, thread_count() } };
    sApp->slice_plans.plans.fill(plan);
}
