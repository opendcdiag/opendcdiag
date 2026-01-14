/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sandstone_virt.h"
#include <unistd.h>
#include <cstring>

static std::string popen_and_readline(const char* cmd) {
    static constexpr size_t max_line_len = 256;

    FILE* fp = popen(cmd, "r");

    if (fp == NULL) {
        return "";
    }

    std::string line;
    line.resize_and_overwrite(max_line_len, [&](char* buf, size_t len) {
        return fgets(buf, len, fp) ? strlen(buf) : 0;
    });

    pclose(fp);

    if(line.back() == '\n') {
        line.pop_back(); // remove the newline character read
                         // from stdout of systemd-detect-virt
    }

    return line;
}

static constexpr const char* detect_virt_container_cmd =
    "systemd-detect-virt --container";

static constexpr const char* detect_virt_vm_cmd =
    "systemd-detect-virt --vm";

std::string detect_running_container() {
    std::string detected =
        popen_and_readline(detect_virt_container_cmd);

    if (detected.compare("none") == 0) {
        return "";
    } else if (!detected.empty()) {
        return detected;
    }

    /* either failed to detect or not
     * running inside of a container */
    return "";
}

std::string detect_running_vm() {
    std::string detected =
        popen_and_readline(detect_virt_vm_cmd);

    if (detected.compare("none") == 0) {
        return "";
    } else if (!detected.empty()) {
        return detected;
    }

#if SANDSTONE_DEVICE_CPU
    // failed to detect the vm with systemd-detect-virt
    // but hypervisor is present so we report it as 'unknown'?
    if (cpu_has_feature(cpu_feature_hypervisor)) {
        return "unknown";
    }
#endif

    return "";
}
