/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_p.h"
#include "cpu_device.h"

#include <cinttypes>

extern constexpr const device_features_t minimum_cpu_features = device_compiler_features;

std::string device_features_to_string(device_features_t f)
{
    std::string result;
    const char *comma = "";
    for (size_t i = 0; i < std::size(x86_locators); ++i) {
        if (f & CPU_FEATURE_CONSTANT(i)) {
            result += comma;
            result += features_string + features_indices[i] + 1;
            comma = ",";
        }
    }
    return result;
}

void dump_device_info()
{
    int i;

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
    printf("# CPU\tPkgID\tCoreID\tThrdID\tModId\tNUMAId\tApicId\tMicrocode\tPPIN\n");
    for (i = 0; i < num_cpus(); ++i) {
        printf("%d\t%d\t%d\t%d\t%d\t%d\t%d\t0x%" PRIx64, cpu_info[i].cpu_number,
               cpu_info[i].package_id, cpu_info[i].core_id, cpu_info[i].thread_id,
               cpu_info[i].module_id, cpu_info[i].numa_id, cpu_info[i].hwid,
               cpu_info[i].microcode);
        const HardwareInfo::PackageInfo *pkg = sApp->hwinfo.find_package_id(cpu_info[i].package_id);
        if (pkg && pkg->ppin)
            printf("\t%016" PRIx64, pkg->ppin);
        puts("");
    }
}

TestResult prepare_test_for_device(struct test *test)
{
    auto has_smt = []() -> bool {
        for(int idx = 0; idx < thread_count() - 1; idx++) {
            if (cpu_info[idx].core_id == cpu_info[idx + 1].core_id)
                return true;
        }
        return false;
    };

    if (test->flags & test_requires_smt && !has_smt()) {
        log_skip(CpuTopologyIssueSkipCategory, "Test requires SMT (hyperthreading)");
        return TestResult::Skipped;
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
