/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "topology.h"
#include "sandstone_p.h"
#include "idxd_device.h"
#include "topology_idxd.hpp"

#include <accel-config/libaccel_config.h>

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <map>
#include <set>
#include <span>
#include <string>
#include <system_error>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

#include <cpuid.h>

#ifdef __linux__
#  include <asm/prctl.h>
#  include <sys/syscall.h>
#  include <unistd.h>
#endif

struct wq_info_t* device_info = nullptr;

namespace {
constexpr unsigned IDXD_OPCODE_NOOP              = 0x00;
constexpr unsigned IDXD_OPCODE_BATCH             = 0x01;
constexpr unsigned IDXD_OPCODE_DRAIN             = 0x02;
constexpr unsigned IDXD_OPCODE_MEMMOVE           = 0x03;
constexpr unsigned IDXD_OPCODE_FILL              = 0x04;
constexpr unsigned IDXD_OPCODE_COMPARE           = 0x05;
constexpr unsigned IDXD_OPCODE_COMPARE_PAT       = 0x06;
constexpr unsigned IDXD_OPCODE_CREATE_DELTA_REC  = 0x07;
constexpr unsigned IDXD_OPCODE_APPLY_DELTA_REC   = 0x08;
constexpr unsigned IDXD_OPCODE_DUAL_CAST         = 0x09;
constexpr unsigned IDXD_OPCODE_CRC_GEN           = 0x10;
constexpr unsigned IDXD_OPCODE_COPY_WITH_CRC_GEN = 0x11;
constexpr unsigned IDXD_OPCODE_DIF_CHECK         = 0x12;
constexpr unsigned IDXD_OPCODE_DIF_INSERT        = 0x13;
constexpr unsigned IDXD_OPCODE_DIF_STRIP         = 0x14;
constexpr unsigned IDXD_OPCODE_DIF_UPDATE        = 0x15;
constexpr unsigned IDXD_OPCODE_CACHE_FLUSH       = 0x20;
constexpr unsigned IDXD_OPCODE_DECOMPRESS        = 0x42;
constexpr unsigned IDXD_OPCODE_COMPRESS          = 0x43;
constexpr unsigned IDXD_OPCODE_CRC64             = 0x44;
constexpr unsigned IDXD_OPCODE_SCAN              = 0x50;
constexpr unsigned IDXD_OPCODE_EXTRACT           = 0x52;
constexpr unsigned IDXD_OPCODE_SELECT            = 0x53;
constexpr unsigned IDXD_OPCODE_EXPAND            = 0x56;

unsigned feature_to_opcode(device_features_t feature)
{
    switch (feature) {
    case device_feature_dsa_op_noop:
    case device_feature_iax_op_noop:
        return IDXD_OPCODE_NOOP;
    case device_feature_dsa_op_batch:
    case device_feature_iax_op_batch:
        return IDXD_OPCODE_BATCH;
    case device_feature_dsa_op_drain:
    case device_feature_iax_op_drain:
        return IDXD_OPCODE_DRAIN;

    case device_feature_op_memmove:
        return IDXD_OPCODE_MEMMOVE;
    case device_feature_op_fill:
        return IDXD_OPCODE_FILL;
    case device_feature_op_compare:
        return IDXD_OPCODE_COMPARE;
    case device_feature_op_compare_pat:
        return IDXD_OPCODE_COMPARE_PAT;
    case device_feature_op_crc_gen:
        return IDXD_OPCODE_CRC_GEN;
    case device_feature_op_copy_with_crc_gen:
        return IDXD_OPCODE_COPY_WITH_CRC_GEN;
    case device_feature_op_dif_check:
        return IDXD_OPCODE_DIF_CHECK;
    case device_feature_op_dif_insert:
        return IDXD_OPCODE_DIF_INSERT;
    case device_feature_op_dif_strip:
        return IDXD_OPCODE_DIF_STRIP;
    case device_feature_op_dif_update:
        return IDXD_OPCODE_DIF_UPDATE;
    case device_feature_op_cache_flush:
        return IDXD_OPCODE_CACHE_FLUSH;
    case device_feature_op_crc64:
        return IDXD_OPCODE_CRC64;

    case device_feature_op_dual_cast:
        return IDXD_OPCODE_DUAL_CAST;
    case device_feature_op_create_delta:
        return IDXD_OPCODE_CREATE_DELTA_REC;
    case device_feature_op_apply_delta:
        return IDXD_OPCODE_APPLY_DELTA_REC;
    case device_feature_op_scan:
        return IDXD_OPCODE_SCAN;
    case device_feature_op_extract:
        return IDXD_OPCODE_EXTRACT;
    case device_feature_op_select:
        return IDXD_OPCODE_SELECT;
    case device_feature_op_expand:
        return IDXD_OPCODE_EXPAND;
    case device_feature_op_compress:
        return IDXD_OPCODE_COMPRESS;
    case device_feature_op_decompress:
        return IDXD_OPCODE_DECOMPRESS;
    default:
        return ~0u;
    }
}
} // end anonymous namespace

int num_packages()
{
    return 1;
}

void make_rescheduler(RescheduleMode mode)
{
}

namespace {
Topology& cached_topology()
{
    static Topology cached_topology = Topology();
    return cached_topology;
}
}

const Topology& Topology::topology()
{
    return cached_topology();
}

namespace {
int parse_int(char*& arg, const char* orig_arg)
{
    errno = 0;
    char *endptr = nullptr;
    long n = strtol(arg, &endptr, 0);
    if (endptr == arg) {
        fprintf(stderr, "%s: error: Invalid device set parameter: %s (expected integer)\n",
                program_invocation_name, orig_arg);
        exit(EX_USAGE);
    }
    if (errno == ERANGE || n < std::numeric_limits<int>::min() || n > std::numeric_limits<int>::max()) {
        fprintf(stderr, "%s: error: Invalid device set parameter: %s (out of range)\n",
                program_invocation_name, orig_arg);
        exit(EX_USAGE);
    }
    arg = endptr; // advance
    return static_cast<int>(n);
}

/// Updates device_info and topology based on new_wq_info.
void update_topology(std::span<const wq_info_t> new_wq_info)
{
    wq_info_t* end = std::copy(new_wq_info.begin(), new_wq_info.end(), device_info);
    int new_device_count = new_wq_info.size();
    if (int excess = sApp->device_count - new_device_count; excess > 0) {
        // reset excess entries
        std::fill_n(end, excess, wq_info_t{});
    }

    sApp->device_count = new_device_count;
    cached_topology() = build_topology();
}
} // end anonymous namespace

/// Supported modes:
/// --deviceset=dsa0,iax2       -> target all WQ of specified devices
/// --deviceset=wq0.1,wq1.2     -> target specific WQs, cpus are auto attached
/// --deviceset=wq0.1c0,wq1.2c5 -> target specific WQs, with manually specified cpus
void apply_deviceset_param(const char *param)
{
    if (SandstoneConfig::RestrictedCommandLine)
        return;

    struct WQMatch {
        int device_id;
        int wq_id;
        bool operator()(const wq_info_t &wq)
        { return wq.device_id == device_id && wq.wq_id == wq_id; }
    };

    std::span<wq_info_t> old_wq_info(device_info, sApp->device_count);
    std::vector<wq_info_t> new_wq_info;
    int total_matches = 0;

    std::set<std::pair<uint32_t, uint32_t>> result; // set of unique wqs to disallow duplicate entries
    new_wq_info.reserve(old_wq_info.size());

    bool add = true;
    if (*param == '!') {
        // we're removing from the existing set
        new_wq_info = { old_wq_info.begin(), old_wq_info.end() };
        add = false;
        ++param;
    }

    const auto apply_to_set = [&](const wq_info_t &wq) {
        if (result.contains({wq.device_id, wq.wq_id})) { // we've got a duplicate
            return;
        }

        if (add) {
            new_wq_info.push_back(wq);
        } else {
            auto it = std::find_if(new_wq_info.begin(), new_wq_info.end(), WQMatch{wq.device_id, wq.wq_id} );
            if (it == new_wq_info.end())
                return;
            new_wq_info.erase(it);
        }
        result.insert({wq.device_id, wq.wq_id});
        ++total_matches;
    };

    LogicalProcessorSet enabled_cpus;
    std::string p = param;
    for (char *arg = strtok(p.data(), ","); arg; arg = strtok(nullptr, ",")) {
        const char *orig_arg = arg;
        if (strncmp(arg, "wq", 2) == 0) {
            arg += 2;
            int device_id = parse_int(arg, orig_arg);

            if (*arg != '.') {
                fprintf(stderr, "%s: error: Invalid device set parameter: %s (expected 'wqX.Y' format)\n",
                        program_invocation_name, orig_arg);
                exit(EX_USAGE);
            }

            ++arg;
            int wq_id = parse_int(arg, orig_arg);

            auto it = std::find_if(old_wq_info.begin(), old_wq_info.end(), WQMatch{device_id, wq_id} );
            if (it == old_wq_info.end()) {
                fprintf(stderr, "%s: error: Invalid device set parameter: %s (no such wq)\n",
                        program_invocation_name, orig_arg);
                exit(EX_USAGE);
            }

            if (*arg == 'c') {
                ++arg;
                int cpu_number = parse_int(arg, orig_arg);

                // check if cpu is enabled in the system
                if (enabled_cpus.size_bytes() == 0) {
                    enabled_cpus = ambient_logical_processor_set();
                }
                if (!enabled_cpus.is_set(LogicalProcessor{cpu_number})) {
                    fprintf(stderr, "%s: error: Invalid device set parameter: %s (no such cpu)\n",
                            program_invocation_name, orig_arg);
                    exit(EX_USAGE);
                }

                it->cpu_number = cpu_number;
            }

            if (*arg != '\0') {
                fprintf(stderr, "%s: error: Invalid device set parameter: %s (could not parse)\n",
                        program_invocation_name, orig_arg);
                exit(EX_USAGE);
            }

            apply_to_set(*it);
        } else if (strncmp(arg, "dsa", 3) == 0 || strncmp(arg, "iax", 3) == 0) {
            accfg_device_type dev_type = strncmp(arg, "dsa", 3) == 0 ? ACCFG_DEVICE_DSA : ACCFG_DEVICE_IAX;
            arg += 3;
            int device_id = parse_int(arg, orig_arg);
            if (*arg != '\0') {
                fprintf(stderr, "%s: error: Invalid device set parameter: %s (could not parse)\n",
                        program_invocation_name, orig_arg);
                exit(EX_USAGE);
            }

            int matches_before = total_matches;
            for (auto const &wq : old_wq_info) {
                if (wq.dev_type == dev_type && wq.device_id == device_id) { // check for dev_type is most probably redundant
                    apply_to_set(wq);
                }
            }

            if (total_matches == matches_before) {
                fprintf(stderr, "%s: error: Invalid device set parameter: %s (no such device)\n",
                        program_invocation_name, orig_arg);
                exit(EX_USAGE);
            }
        } else {
            fprintf(stderr, "%s: error: Invalid device set parameter: %s (could not parse)\n",
                    program_invocation_name, orig_arg);
            exit(EX_USAGE);
        }
    }

    if (total_matches == 0) {
        fprintf(stderr, "%s: error: --deviceset matched nothing, this is probably not what you wanted.\n",
                program_invocation_name);
        exit(EX_USAGE);
    }
    if (!add && new_wq_info.size() == 0) {
        fprintf(stderr, "%s: error: negated --deviceset matched everything, this is probably not "
                        "what you wanted.\n", program_invocation_name);
        exit(EX_USAGE);
    }

    assert(total_matches == result.size());
    if (add)
        assert(total_matches == int(new_wq_info.size()));
    else
        assert(total_matches == int(old_wq_info.size() - new_wq_info.size()));

    update_topology(new_wq_info);
}

/// Build a per-device failure mask for IDXD topology.
/// Mask format:
/// - one character per WQ in topology iteration order;
/// - ':' separates devices.
/// Example: "X.:..X" means device 0 has two WQs (first failed),
/// and device 1 has three WQs (only the last failed).
/// Returns an empty string if there are no failures in any WQ.
std::string build_failure_mask_for_topology(const struct test* test)
{
    UNUSED_ARGS(test);

    std::string mask;
    int total_fail_count = 0;

    for (const auto& device : Topology::topology().devices) {
        std::string device_mask;

        for (const auto& group : device.groups) {
            for (const auto& wq : group.wqs) {
                assert(wq.wq);
                const int thread = wq.wq->wq();
                assert((thread >= 0 && thread < thread_count()));

                if (sApp->thread_data(thread)->has_failed()) {
                    ++total_fail_count;
                    device_mask += 'X';
                } else {
                    device_mask += '.';
                }
            }
        }

        if (!mask.empty())
            mask += ':';

        mask += device_mask;
    }

    if (total_fail_count == 0)
        return {};
    return mask;
}

/// TODO: think about using the pattern from CPU, for legacy reasons?
uint32_t mixin_from_device_info(int thread_num)
{
    const auto& info = device_info[thread_num];
    return scramble(
        static_cast<uint32_t>(info.bdf.domain), static_cast<uint32_t>(info.bdf.bus),
        static_cast<uint32_t>(info.bdf.device), static_cast<uint32_t>(info.bdf.function),
        static_cast<uint32_t>(info.dev_type),   static_cast<uint32_t>(info.wq_id)
    );
}

void print_temperature_of_device()
{
    // TODO: could we use hwmon?
}

int AccfgCtx::init()
{
    static constexpr int MAX_RETRIES = 3;
    int attempt = 0;
    int ret = 0;
    while (ret = accfg_new(&ctx), ret < 0 && ++attempt < MAX_RETRIES) {
        usleep(100);
    }
    if (ret < 0) {
        return log_skip_or_print(RuntimeSkipCategory, "Failed to initialize accfg_ctx");
    }
    return EXIT_SUCCESS;
}

bool has_opcode(const wq_info_t& info, unsigned opcode)
{
    return has_opcode(Topology::topology().devices[info.path.device].op_cap, opcode);
}

bool has_feature(const wq_info_t& info, device_features_t feature)
{
    return has_opcode(Topology::topology().devices[info.path.device].op_cap, feature_to_opcode(feature));
}

// Parse only a fraction required for IDXD tests.
static device_features_t detect_cpu_features()
{
    uint32_t eax, ebx, ecx, edx;
    uint32_t max_level = 0;
    device_features_t features = 0;

    __cpuid(0, max_level, ebx, ecx, edx);
    if (max_level < 7)
        return features;

    __cpuid_count(7, 0, eax, ebx, ecx, edx);

    if (ebx & (UINT32_C(1) << 3))
        features |= cpu_feature_bmi;
    if (ecx & (UINT32_C(1) << 5))
        features |= cpu_feature_waitpkg;
    if (ecx & (UINT32_C(1) << 29))
        features |= cpu_feature_enqcmd;

    constexpr uint32_t AmxTile = UINT32_C(1) << 24;
    constexpr uint32_t AmxInt8 = UINT32_C(1) << 25;
    if ((edx & (AmxTile | AmxInt8)) != (AmxTile | AmxInt8))
        return features;

    __cpuid(1, eax, ebx, ecx, edx);
    constexpr uint32_t OsXsave = UINT32_C(1) << 27;
    if ((ecx & OsXsave) == 0)
        return features;

    uint32_t xcr0_low, xcr0_high;
    asm("xgetbv" : "=a"(xcr0_low), "=d"(xcr0_high) : "c"(0));
    uint64_t xcr0 = xcr0_low | (uint64_t(xcr0_high) << 32);

    constexpr uint64_t Xtilecfg = UINT64_C(1) << 17;
    constexpr uint64_t Xtiledata = UINT64_C(1) << 18;
    constexpr uint64_t AmxState = Xtilecfg | Xtiledata;

#ifdef __linux__
    if ((xcr0 & Xtiledata) == 0 &&
        syscall(SYS_arch_prctl, ARCH_REQ_XCOMP_PERM, 18) == 0)
        xcr0 |= Xtiledata;
#endif

    if ((xcr0 & AmxState) == AmxState)
        features |= cpu_feature_amx_int8;

    return features;
}

static device_features_t detect_features(accfg_device* device)
{
    device_features_t features = 0;

    unsigned int ver = accfg_device_get_version(device);
    accfg_device_type dev_type = accfg_device_get_type(device);
    if (dev_type == ACCFG_DEVICE_DSA) {
        features |= device_feature_dsa;
        if (ver >= ACCFG_DEVICE_VERSION_1)
            features |= device_feature_dsa_v1;
        if (ver >= ACCFG_DEVICE_VERSION_2)
            features |= device_feature_dsa_v2;
        if (ver > ACCFG_DEVICE_VERSION_2)
            features |= device_feature_dsa_v3;
    } else if (dev_type == ACCFG_DEVICE_IAX) {
        features |= device_feature_iax;
        if (ver >= ACCFG_DEVICE_VERSION_1)
            features |= device_feature_iax_v1;
        if (ver >= ACCFG_DEVICE_VERSION_2)
            features |= device_feature_iax_v2;
        if (ver > ACCFG_DEVICE_VERSION_2)
            features |= device_feature_iax_v3;
    }

    accfg_op_cap op_cap = {};
    if (accfg_device_get_op_cap(device, &op_cap) == 0) {
        if (dev_type == ACCFG_DEVICE_DSA) {
            if (has_opcode(op_cap, IDXD_OPCODE_NOOP))
                features |= device_feature_dsa_op_noop;
            if (has_opcode(op_cap, IDXD_OPCODE_BATCH))
                features |= device_feature_dsa_op_batch;
            if (has_opcode(op_cap, IDXD_OPCODE_DRAIN))
                features |= device_feature_dsa_op_drain;
            if (has_opcode(op_cap, IDXD_OPCODE_MEMMOVE))
                features |= device_feature_op_memmove;
            if (has_opcode(op_cap, IDXD_OPCODE_FILL))
                features |= device_feature_op_fill;
            if (has_opcode(op_cap, IDXD_OPCODE_COMPARE))
                features |= device_feature_op_compare;
            if (has_opcode(op_cap, IDXD_OPCODE_COMPARE_PAT))
                features |= device_feature_op_compare_pat;
            if (has_opcode(op_cap, IDXD_OPCODE_CRC_GEN))
                features |= device_feature_op_crc_gen;
            if (has_opcode(op_cap, IDXD_OPCODE_COPY_WITH_CRC_GEN))
                features |= device_feature_op_copy_with_crc_gen;
            if (has_opcode(op_cap, IDXD_OPCODE_DIF_CHECK))
                features |= device_feature_op_dif_check;
            if (has_opcode(op_cap, IDXD_OPCODE_DIF_INSERT))
                features |= device_feature_op_dif_insert;
            if (has_opcode(op_cap, IDXD_OPCODE_DIF_STRIP))
                features |= device_feature_op_dif_strip;
            if (has_opcode(op_cap, IDXD_OPCODE_DIF_UPDATE))
                features |= device_feature_op_dif_update;
            if (has_opcode(op_cap, IDXD_OPCODE_CACHE_FLUSH))
                features |= device_feature_op_cache_flush;
            if (has_opcode(op_cap, IDXD_OPCODE_CRC64))
                features |= device_feature_op_crc64;
        } else if (dev_type == ACCFG_DEVICE_IAX) {
            if (has_opcode(op_cap, IDXD_OPCODE_NOOP))
                features |= device_feature_iax_op_noop;
            if (has_opcode(op_cap, IDXD_OPCODE_BATCH))
                features |= device_feature_iax_op_batch;
            if (has_opcode(op_cap, IDXD_OPCODE_DRAIN))
                features |= device_feature_iax_op_drain;
            if (has_opcode(op_cap, IDXD_OPCODE_DUAL_CAST))
                features |= device_feature_op_dual_cast;
            if (has_opcode(op_cap, IDXD_OPCODE_CREATE_DELTA_REC))
                features |= device_feature_op_create_delta;
            if (has_opcode(op_cap, IDXD_OPCODE_APPLY_DELTA_REC))
                features |= device_feature_op_apply_delta;
            if (has_opcode(op_cap, IDXD_OPCODE_SCAN))
                features |= device_feature_op_scan;
            if (has_opcode(op_cap, IDXD_OPCODE_EXTRACT))
                features |= device_feature_op_extract;
            if (has_opcode(op_cap, IDXD_OPCODE_SELECT))
                features |= device_feature_op_select;
            if (has_opcode(op_cap, IDXD_OPCODE_EXPAND))
                features |= device_feature_op_expand;
            if (has_opcode(op_cap, IDXD_OPCODE_COMPRESS))
                features |= device_feature_op_compress;
            if (has_opcode(op_cap, IDXD_OPCODE_DECOMPRESS))
                features |= device_feature_op_decompress;
        }
    }

    return features;
}

device_features_t detect_features()
{
    AccfgCtx ctx;
    if (auto ret = ctx.init(); ret)
        return 0;

    device_features_t features = detect_cpu_features();

    accfg_device* device;
    accfg_device_foreach(ctx.get(), device) {
        features |= detect_features(device);
    }

    return features;
}

/// Collect all WQs visible in the system. Do not create any hierarchy of them at this point.
/// It also populates device_features.
template <>
WorkQueueSet detect_devices<WorkQueueSet>()
{
    WorkQueueSet res;

    if (auto ret = res.ctx.init(); ret) {
        return res;
    }

    device_features = detect_cpu_features(); // reset

    accfg_device* device;
    accfg_device_foreach(res.ctx.get(), device) {
        device_features |= detect_features(device);
        auto device_type = accfg_device_get_type(device);
        auto device_id   = accfg_device_get_id(device);

        accfg_wq* wq;
        accfg_wq_foreach(device, wq) {
            auto& v = res.visible_wqs.emplace_back();
            v.device_handle = device;
            v.device_type = device_type;
            v.device_id   = device_id;
            v.wq_id       = accfg_wq_get_id(wq);
        }
    }

    sApp->device_count = res.visible_wqs.size();
    sApp->user_thread_data.resize(sApp->device_count);

    return res;
}

void create_mock_topology(const char *topo)
{
}

namespace {
/// TODO: copied from GPU
int16_t detect_package_id_via_os(int cpu)
{
    int16_t res = -1;
    if (cpu < 0) { [[unlikely]]
        return res;
    }
    auto file = std::format("/sys/devices/system/cpu/cpu{}/topology/physical_package_id", cpu);

    FILE* fp = fopen(file.c_str(), "r");
    if (!fp) { [[unlikely]]
        fprintf(stderr, "%s: internal error: unable to find physical_package_id file: %m\n",
                program_invocation_name);
        return res;
    }
    int val;
    if (std::fscanf(fp, "%d", &val) == 1) {
        res = static_cast<int16_t>(val);
    }
    fclose(fp);

    return res;
}

int16_t detect_core_id_via_os(int cpu)
{
    int16_t res = -1;
    if (cpu < 0) { [[unlikely]]
        return res;
    }
    auto file = std::format("/sys/devices/system/cpu/cpu{}/topology/core_id", cpu);

    FILE* fp = fopen(file.c_str(), "r");
    if (!fp) { [[unlikely]]
        fprintf(stderr, "%s: internal error: unable to find core_id file: %m\n",
                program_invocation_name);
        return res;
    }
    int val;
    if (std::fscanf(fp, "%d", &val) == 1) {
        res = static_cast<int16_t>(val);
    }
    fclose(fp);

    return res;
}

bdf_t detect_bdf_via_os(accfg_device *device)
{
    bdf_t bdf = {};

    const char* devname = accfg_device_get_devname(device);
    if (!devname) [[unlikely]] {
        return bdf;
    }

    const auto link_path = std::filesystem::path(std::format("/sys/bus/dsa/devices/{}", devname));
    std::error_code ec;
    const auto target_path = std::filesystem::canonical(link_path, ec);
    if (ec) [[unlikely]] {
        return bdf;
    }

    unsigned domain = 0;
    unsigned bus = 0;
    unsigned dev = 0;
    unsigned fn = 0;
    if (std::sscanf(target_path.parent_path().filename().c_str(), "%x:%x:%x.%x", &domain, &bus, &dev, &fn) != 4) {
        return {};
    }

    bdf.domain   = static_cast<uint16_t>(domain);
    bdf.bus      = static_cast<uint8_t>(bus);
    bdf.device   = static_cast<uint8_t>(dev);
    bdf.function = static_cast<uint8_t>(fn);

    return bdf;
}
} // end anonymous namespace

/// Update device_info and initial topology based on current config of the WQs in the system.
template <>
void setup_devices<WorkQueueSet>(const WorkQueueSet& enabled_devices)
{
    device_info = sApp->shmem->device_info;

    if (SandstoneConfig::Debug) {
        if (const char* mock_topo = getenv("SANDSTONE_MOCK_TOPOLOGY"); mock_topo && *mock_topo) {
            // create_mock_topology(mock_topo); // TODO: implement me
            return;
        }
    }

    assert(enabled_devices.visible_wqs.size() == device_count());

    auto enabled_cpus = ambient_logical_processor_set().to_vector();
    if (enabled_cpus.size() < enabled_devices.visible_wqs.size()) {
        fprintf(stderr, "%s: error: not enough CPUs available (%zu CPUs vs %zu WQs)\n",
                program_invocation_name, enabled_cpus.size(), enabled_devices.visible_wqs.size());
        exit(EX_USAGE);
    }

    wq_info_t* info = device_info;
    [[maybe_unused]] const wq_info_t* cend = device_info + device_count();

    std::map<int, bdf_t> bdf_cache; // bdfs are unique per device

    int cpu_ind = 0;
    for (const auto &enabled : enabled_devices.visible_wqs) {
        info->cpu_number = enabled_cpus[cpu_ind++];
        info->package_id = detect_package_id_via_os(info->cpu_number);
        info->core_id = detect_core_id_via_os(info->cpu_number);

        auto it = bdf_cache.find(enabled.device_id);
        if (it == bdf_cache.end()) {
            it = bdf_cache.emplace(enabled.device_id, detect_bdf_via_os(enabled.device_handle)).first;
        }
        info->bdf = it->second;

        info->device_id = enabled.device_id;
        info->wq_id = enabled.wq_id;
        info->dev_type = enabled.device_type;
        info->dev_version = static_cast<accfg_device_version>(accfg_device_get_version(enabled.device_handle));
        info->path = { -1, -1 };

        info++;
    }
    assert(info == cend);

    cached_topology() = build_topology(enabled_devices.ctx);
}

void restrict_topology(DeviceRange range)
{
    assert(range.starting_device + range.device_count <= sApp->device_count);
    auto old_wq_info = std::exchange(device_info, sApp->shmem->device_info + range.starting_device);
    int old_device_count = std::exchange(sApp->device_count, range.device_count);

    Topology &topo = cached_topology();
    if (old_wq_info != device_info || old_device_count != sApp->device_count || topo.devices.empty()) {
        topo = build_topology();
    }
}

void rebuild_topology()
{
}

void analyze_test_failures_for_topology(const struct test *test, const PerThreadFailures &per_thread_failures)
{
    auto pattern_for_wq = [&per_thread_failures](const Topology::WorkQueue& wq) -> PerThreadFailures::value_type {
        assert(wq.wq);
        const int thread = wq.wq->wq();
        assert(thread < 0 || size_t(thread) >= per_thread_failures.size());
        return per_thread_failures[size_t(thread)];
    };

    const auto& topology = Topology::topology();

    logging_printf(LOG_LEVEL_VERBOSE(1), "# Topology analysis:\n");

    bool all_devices_failed_once = true;
    bool all_devices_failed_equally = true;
    int failed_devices = 0;
    PerThreadFailures::value_type last_device_pattern = 0;

    for (const auto& device : topology.devices) {
        int total_wqs = 0;
        int failed_wqs = 0;
        bool all_wqs_failed_once = true;
        bool all_wqs_failed_equally = true;
        PerThreadFailures::value_type first_nonzero_pattern = 0;

        for (const auto& group : device.groups) {
            for (const auto& wq : group.wqs) {
                ++total_wqs;
                auto pattern = pattern_for_wq(wq);
                if (pattern == 0) {
                    all_wqs_failed_once = false;
                    all_devices_failed_once = false;
                    continue;
                }

                ++failed_wqs;
                if (first_nonzero_pattern && pattern != first_nonzero_pattern) {
                    all_wqs_failed_equally = false;
                    all_devices_failed_equally = false;
                }
                if (!first_nonzero_pattern)
                    first_nonzero_pattern = pattern;
            }
        }

        if (failed_wqs == 0)
            continue;

        ++failed_devices;
        if (last_device_pattern && first_nonzero_pattern != last_device_pattern)
            all_devices_failed_equally = false;
        last_device_pattern = first_nonzero_pattern;

        if (failed_wqs == 1) {
            logging_printf(LOG_LEVEL_VERBOSE(1), "#   - Device %s: only one WQ failed\n", device.name.c_str());
        } else if (all_wqs_failed_equally) {
            logging_printf(LOG_LEVEL_VERBOSE(1), "#   - Device %s: all WQs failed exactly the same way\n", device.name.c_str());
        } else if (all_wqs_failed_once) {
            logging_printf(LOG_LEVEL_VERBOSE(1), "#   - Device %s: all WQs failed at least once\n", device.name.c_str());
        } else if (failed_wqs < total_wqs) {
            logging_printf(LOG_LEVEL_VERBOSE(1), "#   - Device %s: some WQs failed but some others succeeded\n", device.name.c_str());
        }
    }

    if (failed_devices == 0)
        return;
    if (failed_devices == 1) {
        logging_printf(LOG_LEVEL_VERBOSE(1), "# - Only one IDXD device failed\n");
    } else if (all_devices_failed_equally) {
        logging_printf(LOG_LEVEL_VERBOSE(1), "# - All IDXD devices failed exactly the same way\n");
    } else if (all_devices_failed_once) {
        logging_printf(LOG_LEVEL_VERBOSE(1), "# - All IDXD devices failed at least once\n");
    } else {
        logging_printf(LOG_LEVEL_VERBOSE(1), "# - Some IDXD devices failed but some others succeeded\n");
    }
}

std::vector<const Topology::WorkQueue*> Topology::targetable_wqs(
        std::optional<accfg_device_type> device_type,
        std::optional<accfg_wq_mode> mode,
        std::optional<unsigned int> op) const
{
    std::vector<const WorkQueue*> result;
    for (const Device &device : devices) {
        if (device_type && device.dev_type != *device_type)
            continue;
        if (op && !has_opcode(device.op_cap, *op))
            continue;
        for (const Group &group : device.groups) {
            for (const WorkQueue &wq : group.wqs) {
                if (wq.targetable && (!mode || wq.mode == *mode))
                    result.push_back(&wq);
            }
        }
    }

    return result;
}

void slice_plan_init_for_device(SlicePlans::SlicesArray& plans, int max_cores_per_slice)
{
    SlicePlans::Slices plan = { SlicePlans::Slice{ DeviceRange{ 0, device_count() }, {} } };
    plans.fill(plan);
}

int slice_plan_init_for_threads(SlicePlans::SlicesArray& plans, ThreadRatio ratio_type)
{
    for (auto &plan : plans) {
        for (auto &slice : plan)
            slice.thread_range = { slice.device_range.starting_device, slice.device_range.device_count }; // 1:1 for now...
    }
    return device_count();
}
