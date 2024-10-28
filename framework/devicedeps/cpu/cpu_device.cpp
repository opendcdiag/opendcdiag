/*
 * Copyright 2024 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "devicedeps/cpu/cpu_features.h"
#include "devicedeps/devices.h"
#include "devicedeps/cpu/cpu_device.h"
#include "devicedeps/cpu/topology.h"
#ifdef SANDSTONE_DEVICE_CPU

#include <stdio.h>
#include <inttypes.h>

uint64_t cpu_features;

/// CPU devices are directly initialized in the framework's main() function.
/// Once CPU initialization is untied from shmem initialization, this function
/// will be called from the framework's main() function.
__attribute__((unused)) void device_init() {
    return;
}

#ifdef __llvm__
thread_local int thread_num __attribute__((tls_model("initial-exec")));
#else
thread_local int thread_num = 0;
#endif

std::string cpu_features_to_string(uint64_t f)
{
    std::string result;
    const char *comma = "";
    for (size_t i = 0; i < std::size(x86_locators); ++i) {
        if (f & (UINT64_C(1) << i)) {
            result += comma;
            result += features_string + features_indices[i] + 1;
            comma = ",";
        }
    }
    return result;
}

void dump_cpu_info(int verbosity)
{
    int i;

    // find the best matching CPU
    const char *detected = "<unknown>";
    for (const auto &arch : x86_architectures) {
        if ((arch.features & cpu_features) == arch.features) {
            detected = arch.name;
            break;
        }
        if (verbosity > 1)
            printf("CPU is not %s: missing %s\n", arch.name,
                   cpu_features_to_string(arch.features & ~cpu_features).c_str());
    }
    printf("Detected CPU: %s; family-model-stepping (hex): %02x-%02x-%02x; CPU features: %s\n",
           detected, cpu_info[0].family, cpu_info[0].model, cpu_info[0].stepping,
           cpu_features_to_string(cpu_features).c_str());
    printf("# CPU\tPkgID\tCoreID\tThrdID\tMicrocode\tPPIN\n");
    for (i = 0; i < num_cpus(); ++i) {
        printf("%d\t%d\t%d\t%d\t0x%" PRIx64, cpu_info[i].cpu_number,
               cpu_info[i].package_id, cpu_info[i].core_id, cpu_info[i].thread_id,
               cpu_info[i].microcode);
        if (cpu_info[i].ppin)
            printf("\t%016" PRIx64, cpu_info[i].ppin);
        puts("");
    }
}
#endif
