/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <sandstone_virt.h>

std::string detect_running_container() {
    return "";
}

std::string detect_running_vm() {

#if SANDSTONE_DEVICE_CPU
    // failed to detect the vm with systemd-detect-virt
    // but hypervisor is present so we report it as 'unknown'?
    if (cpu_has_feature(cpu_feature_hypervisor)) {
        return "unknown";
    }
#endif

    return "";
}
