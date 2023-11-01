/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <interrupt_monitor.hpp>
#include <sandstone_p.h>

#include <ctype.h>

constexpr const char * const proc_interrupts_file = "/proc/interrupts";

// this function reads the interrupts file and returns a list of integers corresponding
// to the contents of the line that matches the input header prefix, for example "MCE:"
std::vector<uint32_t> InterruptMonitor::get_interrupt_counts(InterruptType type)
{
    static_assert(InterruptMonitorWorks);
    static AutoClosingFile f = { fopen(proc_interrupts_file, "r") };

    const char *hdr = [type] {
        switch (type) {
        case MCE:
            return "MCE:";
        case Thermal:
            return "TRM:";
        }
        assert(false && "Should not have reached here");
        __builtin_unreachable();
        return static_cast<const char *>(nullptr);
    }();

    std::vector<uint32_t> result;
    if (!f)
        return result;

    char *line = nullptr;
    size_t len = 0;
    auto free_line = scopeExit([&] { free(line); });

    while (f && (nread = getline(&line, &len, f)) != -1) {
        // Skip any blanks at the start of the line
        char *ptr = line;
        while (*ptr && isblank(*ptr))
            ptr++;
        if (strncmp(ptr, hdr, strlen(hdr)) != 0)
            continue;

        ptr = ptr + strlen(hdr);
        while (*ptr != '\0') {
            char *endptr;
            errno = 0;
            uint64_t n = strtoull(ptr, &endptr, 10);
            if (n == 0 && ptr == endptr)
                break;
            result.push_back(n);
            ptr = endptr;
        }
        break;
    }

    // reset the file pointer for the next time we get called
    fseek(f, 0, SEEK_SET);
    return result;
}

#include "../../../tests/mce_check/mce_check.cpp"
#include "../../../tests/smi_count/smi_count.cpp"
