/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_virt.h"
#include "sandstone_utils.h"

#include <unistd.h>
#include <cstring>

static std::string readfile(const char *filename)
{
    static constexpr size_t max_line_len = 256;
    AutoClosingFile fp = { fopen(filename, "r") };

    if (fp == NULL) {
        return {};
    }

    std::string line(max_line_len, '\0');
    if (!fgets(line.data(), line.size(), fp))
        return {};

    line.resize(strlen(line.data()));

    if (line.size() && line.back() == '\n') {
        line.pop_back(); // remove the newline character read
    }

    return line;
}

std::string detect_running_container()
{
    return readfile("/run/host/container-manager");
}

std::string detect_running_vm()
{
    if (std::string vm = readfile("/sys/hypervisor/type"); vm.size())
        return vm;
#if SANDSTONE_DEVICE_CPU
    // failed to detect the vm with systemd-detect-virt
    // but hypervisor is present so we report it as 'unknown'?
    if (cpu_has_feature(cpu_feature_hypervisor)) {
        return "unknown";
    }
#endif

    return {};
}
