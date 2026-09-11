/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * Changes from Qualcomm Technologies, Inc. are provided under the following license:
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "sandstone_p.h"
#include "cpu_device.h"

#include <cinttypes>

extern constexpr const device_features_t minimum_cpu_features = device_compiler_features;

std::string device_features_to_string(device_features_t f)
{
    std::string result;
    const char *comma = "";
#ifndef __aarch64__
    for (size_t i = 0; i < std::size(x86_locators); ++i) {
        if (f & CPU_FEATURE_CONSTANT(i)) {
            result += comma;
            result += features_string + features_indices[i] + 1;
            comma = ",";
        }
    }
#else
    for (size_t i = 0; i < std::size(aarch64_locators); ++i) {
        if (f & CPU_FEATURE_CONSTANT(i)) {
            uint16_t idx = features_indices[i];
            if (idx == FEATURE_INDEX_UNUSED) continue;  // Skip unused/reserved feature slots
            result += comma;
            result += features_string + idx + 1;
            comma = ",";
        }
    }
#endif
    return result;
}

#ifdef __aarch64__
static const char* detect_aarch64_architecture(device_features_t features)
{
    for (const auto &arch : aarch64_architectures) {
        if ((arch.features & features) == arch.features) {
            return arch.name;
        }
        if (sApp->shmem->cfg.verbosity > 1) {
            printf("CPU is not %s: missing %s\n", arch.name,
                   device_features_to_string(arch.features & ~features).c_str());
        }
    }
    return "<unknown>";
}
#endif

void dump_device_info()
{
    int i;

#ifndef __aarch64__
    // find the best matching CPU
    const char *detected = "<unknown>";
    for (const auto &arch : x86_architectures) {
        if ((arch.features & device_features) == arch.features) {
            detected = arch.name;
            break;
        }
        if (sApp->shmem->cfg.verbosity > 1)
            printf("CPU is not %s: missing %s\n", arch.name,
                   device_features_to_string(arch.features & ~device_features).c_str());
    }
    printf("Detected CPU: %s; family-model-stepping (hex): %02x-%02x-%02x; CPU features: %s\n",
           detected, sApp->hwinfo.family, sApp->hwinfo.model, sApp->hwinfo.stepping,
           device_features_to_string(device_features).c_str());
#else
    const char *vendor = "<unknown>";
    const char *detected_cpu = "<unknown>";
    const char *detected_arch = "<unknown>";

#ifdef __linux__
    // Reading MIDR_EL1 from EL0 is emulated by the Linux kernel. Other OSes
    // (e.g. XNU on Apple Silicon) do not guarantee this, so restrict the
    // read to Linux, matching detect_cpu() in cpuid_internal.h.
    uint64_t midr_el1 = 0;
    uint8_t implementer = 0;
    uint16_t part_num = 0;

    asm("mrs %0, MIDR_EL1" : "=r"(midr_el1));

    // Parse MIDR_EL1 fields
    implementer = MIDR_EL1_IMPLEMENTER(midr_el1);
    part_num = MIDR_EL1_PART_NUM(midr_el1);

    // Find best matching architecture baseline
    detected_arch = detect_aarch64_architecture(device_features);

    // Find vendor and part
    for (const auto &curr_vendor : aarch64_vendors) {
        if (curr_vendor.id == implementer) {
            vendor = curr_vendor.name;
            for (size_t i = 0; i < curr_vendor.num_parts; ++i) {
                if (part_num == curr_vendor.parts[i].part_num) {
                    detected_cpu = curr_vendor.parts[i].name;
                    break;
                }
            }
            break;
        }
    }
#endif

    printf("CPU Vendor    : %s\n", vendor);
    printf("Detected CPU  : %s\n", detected_cpu);
    printf("Detected Arch : %s\n", detected_arch);
    printf("CPU features  : %s\n", device_features_to_string(device_features).c_str());
#endif
    printf("# CPU\tPkgID\tCoreID\tThrdID\tModId\tDieId\tNUMAId\tApicId\tMicrocode\tPPIN\n");
    for (i = 0; i < device_count(); ++i) {
        printf("%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t0x%" PRIx64, device_info[i].cpu_number,
               device_info[i].package_id, device_info[i].core_id, device_info[i].thread_id,
               device_info[i].module_id, device_info[i].die_id, device_info[i].numa_id, device_info[i].hwid,
               device_info[i].microcode);
        const HardwareInfo::PackageInfo *pkg = sApp->hwinfo.find_package_id(device_info[i].package_id);
        if (pkg && pkg->ppin)
            printf("\t%016" PRIx64, pkg->ppin);
        puts("");
    }
}

TestResult prepare_test_for_device(struct test *test)
{
    auto has_smt = []() -> bool {
        for(int idx = 0; idx < device_count() - 1; idx++) {
            if (device_info[idx].package_id == device_info[idx + 1].package_id &&
                device_info[idx].core_id == device_info[idx + 1].core_id)
                return true;
        }
        return false;
    };

    if (test->flags & test_requires_smt) {
        if (!Topology::topology().isValid()) {
            log_skip(CpuTopologyIssueSkipCategory, "Test requires topology information");
            return TestResult::Skipped;
        }
        if (!has_smt()) {
            log_skip(CpuTopologyIssueSkipCategory, "Test requires SMT (hyperthreading)");
            return TestResult::Skipped;
        }
    }
    return TestResult::Passed;
}

void finish_test_for_device(struct test *test)
{}

// Currently empty
std::vector<struct test*> special_tests_for_device()
{
    return {};
}
