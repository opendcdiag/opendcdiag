/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <interrupt_monitor.hpp>
#include <sandstone_p.h>

constexpr const char * const proc_interrupts_file = "/proc/interrupts";

static bool is_kernel_blank(char c)
{
    // kernel only uses spaces for the /proc/interrupts file but we accept tabs
    return c == ' ' || c == '\t';
}

static char *skip_to_non_blank(char *ptr)
{
    char c;
    for ( ; (c = *ptr); ++ptr) {
        if (!is_kernel_blank(c))
            break;
    }
    return ptr;
}

static const std::vector<int> &parse_header(char *line, ssize_t nread)
{
    static struct {
        std::string header_line;
        std::vector<int> result;
    } cache;

    if (nread <= 0) {
        cache = {};
        return cache.result;
    }

    std::string_view header_line(line, nread);
    if (cache.header_line == header_line)
        return cache.result;

    // cache this result for later
    cache.header_line = header_line;

    // read every CPU number to create the mapping
    static const char cpu[] = "CPU";
    char *ptr = skip_to_non_blank(line);
    while (strncmp(ptr, cpu, strlen(cpu)) == 0) {
        char *endptr;
        ptr += strlen(cpu);
        unsigned long n = strtoul(ptr, &endptr, 10);
        if (n == 0 && ptr == endptr)
            break;

        cache.result.push_back(n);
        ptr = skip_to_non_blank(endptr);
    }

    return cache.result;
}

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

    // read the header and create the CPU mapping
    ssize_t nread = getline(&line, &len, f);
    const std::vector<int> &cpu_mapping = parse_header(line, nread);
    if (cpu_mapping.size() == 0) {
        // failed to parse the header!
        fclose(f);
        f.f = nullptr;
        return result;
    }

    // static code analyzers: we trust the kernel
    result.resize(cpu_mapping.back() + 1);

    while (getline(&line, &len, f) != -1) {
        // Skip any blanks at the start of the line
        char *ptr = skip_to_non_blank(line);
        if (strncmp(ptr, hdr, strlen(hdr)) != 0)
            continue;

        ptr = ptr + strlen(hdr);
        for (int i = 0; *ptr != '\0'; ++i) {
            char *endptr;
            errno = 0;
            uint64_t n = strtoull(ptr, &endptr, 10);
            if (n == 0 && ptr == endptr)
                break;
            // static code analyzers: we trust the kernel
            result[cpu_mapping[i]] = n;
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
