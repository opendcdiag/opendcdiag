/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"
#include "sandstone_p.h"
#include "logging.h"

#include <cinttypes>

namespace {
auto thread_core_spacing()
{
    // calculate the spacing so things align
    // Note: this assumes the topology won't change after the first time this
    // function is called.
    static const auto spacing = []() {
        struct { int logical, core; } result = { 1, 1 };
        int max_core_id = 0;
        int max_logical_id = 0;
        for (int i = 0; i < thread_count(); ++i) {
            if (cpu_info[i].cpu_number > max_logical_id)
                max_logical_id = cpu_info[i].cpu_number;
            if (cpu_info[i].core_id > max_core_id)
                max_core_id = cpu_info[i].core_id;
        }
        if (max_logical_id > 9)
            ++result.logical;
        if (max_logical_id > 99)
            ++result.logical;
        if (max_logical_id > 999)
            ++result.logical;
        if (max_core_id > 9)
            ++result.core;
        if (max_core_id > 99)
            ++result.core;
        return result;
    }();
    return spacing;
}
} // end anonymous namespace

std::string thread_id_header_for_device(int cpu, int verbosity)
{
    struct cpu_info *info = cpu_info + cpu;
    std::string line;
#ifdef _WIN32
    line = stdprintf("{ logical-group: %2u, logical: %2u, ",
                     // see win32/cpu_affinity.cpp
                     info->cpu_number / 64u, info->cpu_number % 64u);
#else
    line = stdprintf("{ logical: %*d, ", thread_core_spacing().logical, info->cpu_number);
#endif
    line += stdprintf("package: %d, numa_node: %d, module: %*d, core: %*d, thread: %d",
                      info->package_id, info->numa_id, thread_core_spacing().core, info->module_id,
                      thread_core_spacing().core, info->core_id, info->thread_id);
    if (verbosity > 1) {
        auto add_value_or_null = [&line](const char *fmt, uint64_t value) {
            if (value)
                line += stdprintf(fmt, value);
            else
                line += "null";
        };
        const HardwareInfo::PackageInfo *pkg = sApp->hwinfo.find_package_id(info->package_id);
        line += stdprintf(", family: %d, model: %#02x, stepping: %d, microcode: ",
                          sApp->hwinfo.family, sApp->hwinfo.model, sApp->hwinfo.stepping);
        add_value_or_null("%#" PRIx64, info->microcode);
        line += ", ppin: ";
        add_value_or_null("\"%016" PRIx64 "\"", pkg ? pkg->ppin : 0);   // string to prevent loss of precision
    }
    line += " }";
    return line;
}

void print_thread_header_kv_for_device(int fd, int cpu, const char *prefix)
{
    struct cpu_info *info = cpu_info + cpu;
    const HardwareInfo::PackageInfo *pkg = sApp->hwinfo.find_package_id(info->package_id);
    PerThreadData::Test *thr = sApp->test_thread_data(cpu);
    if (std::string time = format_duration(thr->fail_time); time.size()) {
        dprintf(fd, "%s_thread_%d_fail_time = %s\n", prefix, cpu, time.c_str());
        dprintf(fd, "%s_thread_%d_loop_count = %" PRIu64 "\n", prefix, cpu,
                thr->inner_loop_count_at_fail);
    } else {
        dprintf(fd, "%s_thread_%d_loop_count = %" PRIu64 "\n", prefix, cpu,
                thr->inner_loop_count);
    }
    dprintf(fd, "%s_messages_thread_%d_cpu = %d\n", prefix, cpu, info->cpu_number);
    dprintf(fd, "%s_messages_thread_%d_family_model_stepping = %02x-%02x-%02x\n", prefix, cpu,
            sApp->hwinfo.family, sApp->hwinfo.model, sApp->hwinfo.stepping);
    dprintf(fd, "%s_messages_thread_%d_topology = phys %d, core %d, thr %d\n",
            prefix, cpu, info->package_id, info->core_id, info->thread_id);
    dprintf(fd, "%s_messages_thread_%d_microcode =", prefix, cpu);
    if (info->microcode)
        dprintf(fd, " 0x%" PRIx64, info->microcode);
    dprintf(fd, "\n%s_messages_thread_%d_ppin =",
            prefix, cpu);
    if (pkg && pkg->ppin)
        dprintf(fd, " 0x%" PRIx64, pkg->ppin);
    dprintf(fd, "\n%s_messages_thread_%d = \\\n", prefix, cpu);
}

void print_thread_header_tap_for_device(int fd, int cpu, int verbosity)
{
    struct cpu_info *info = cpu_info + cpu;
    std::string line = stdprintf("  Thread %d on CPU %d (pkg %d, core %d, thr %d", cpu,
            info->cpu_number, info->package_id, info->core_id, info->thread_id);

    const HardwareInfo::PackageInfo *pkg = sApp->hwinfo.find_package_id(info->package_id);
    line += stdprintf(", family/model/stepping %02x-%02x-%02x, microcode ", sApp->hwinfo.family, sApp->hwinfo.model,
                      sApp->hwinfo.stepping);
    if (info->microcode)
        line += stdprintf("%#" PRIx64, info->microcode);
    else
        line += "N/A";
    if (pkg && pkg->ppin)
        line += stdprintf(", PPIN %016" PRIx64 "):", pkg->ppin);
    else
        line += ", PPIN N/A):";

    writeln(fd, line);

    if (verbosity > 1) {
        PerThreadData::Test *thr = sApp->test_thread_data(cpu);
        if (std::string time = format_duration(thr->fail_time); time.size())
            writeln(fd, "  - failed: { time: ", time,
                    ", loop-count: ", std::to_string(thr->inner_loop_count_at_fail),
                    " }");
        else if (verbosity > 2)
            writeln(fd, "  - loop-count: ", std::to_string(thr->inner_loop_count));
    }
}
