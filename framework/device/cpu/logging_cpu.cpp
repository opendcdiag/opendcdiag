/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"
#include "sandstone_p.h"
#include "logging_cpu.h"

#include <cinttypes>

void KeyValuePairLogger::prepare_line_prefix()
{
    timestamp_prefix = log_timestamp();
    timestamp_prefix += test->id;
}

void KeyValuePairLogger::print(int tc)
{
    logging_printf(LOG_LEVEL_QUIET, "%s_result = %s\n", test->id,
                   testResult == TestResult::Skipped ? "skip" :
                   testResult == TestResult::Passed ? "pass" : "fail");

    if (testResult == TestResult::Skipped && !skipInMainThread) {
        logging_printf(LOG_LEVEL_QUIET, "%s_skip_category = %s\n", test->id, "Runtime");
        logging_printf(LOG_LEVEL_QUIET, "%s_skip_reason = %s\n", test->id,
                       "All CPUs skipped while executing 'test_run()' function, check log for details");
    } else if (testResult == TestResult::Skipped) {
        // skipped in the test_init()
        // FIXME: multiple main threads
        std::string init_skip_message = get_skip_message(-1);
        if (init_skip_message.size() > 0) {
            logging_printf(LOG_LEVEL_QUIET, "%s_skip_category = %s\n", test->id, char_to_skip_category(init_skip_message[0]));
            logging_printf(LOG_LEVEL_QUIET, "%s_skip_reason = ", test->id);
            std::string_view message(&init_skip_message[1], init_skip_message.size()-1);
            AbstractLogger::format_and_print_message(real_stdout_fd, message, false);
            if (file_log_fd != real_stdout_fd)
                AbstractLogger::format_and_print_message(file_log_fd, message, false);
        } else {
            logging_printf(LOG_LEVEL_QUIET, "%s_skip_category = %s\n", test->id, "Unknown");
            logging_printf(LOG_LEVEL_QUIET, "%s_skip_reason = %s\n", test->id,
                           "Unknown, check main thread message for details or use -vv option for more info");
        }
    }

    logging_printf(LOG_LEVEL_VERBOSE(1), "%s_seq = %d\n", test->id, tc);
    logging_printf(LOG_LEVEL_VERBOSE(1), "%s_quality = %s\n", test->id, quality_string(test));
    logging_printf(LOG_LEVEL_VERBOSE(1), "%s_description = %s\n", test->id, test->description);
    logging_printf(LOG_LEVEL_VERBOSE(1), "%s_pass_count = %d\n", test->id, pc);
    logging_printf(LOG_LEVEL_VERBOSE(2), "%s_virtualized = %s\n", test->id,
                   cpu_has_feature(cpu_feature_hypervisor) ? "yes" : "no");
    if (should_print_fail_info()) {
        logging_printf(LOG_LEVEL_VERBOSE(1), "%s_fail_percent = %.1f\n", test->id,
                       100. * (thread_count() - pc) / thread_count());
        logging_printf(LOG_LEVEL_VERBOSE(1), "%s_random_generator_state = %s\n", test->id,
                       random_format_seed().c_str());
        logging_printf(LOG_LEVEL_VERBOSE(1), "%s_fail_mask = %s\n", test->id,
                       build_failure_mask_for_topology(test).c_str());
        if (std::string time = format_duration(earliest_fail); time.size())
            logging_printf(LOG_LEVEL_VERBOSE(1), "%s_earliest_fail_time = %s\n", test->id, time.c_str());
    }

    print_thread_messages();
    print_child_stderr();
    logging_flush();
}

void KeyValuePairLogger::print_thread_header(int fd, int device, const char *prefix)
{
    if (device < 0) {
        device = ~device;
        if (device == 0)
            writeln(file_log_fd, timestamp_prefix, "_messages_mainthread = \\");
        else
            dprintf(file_log_fd, "%s_messages_mainthread_%d = \\\n",
                    timestamp_prefix.c_str(), device);
        return;
    }

    struct cpu_info *info = cpu_info + device;
    const HardwareInfo::PackageInfo *pkg = sApp->hwinfo.find_package_id(info->package_id);
    PerThreadData::Test *thr = sApp->test_thread_data(device);
    if (std::string time = format_duration(thr->fail_time); time.size()) {
        dprintf(fd, "%s_thread_%d_fail_time = %s\n", prefix, device, time.c_str());
        dprintf(fd, "%s_thread_%d_loop_count = %" PRIu64 "\n", prefix, device,
                thr->inner_loop_count_at_fail);
    } else {
        dprintf(fd, "%s_thread_%d_loop_count = %" PRIu64 "\n", prefix, device,
                thr->inner_loop_count);
    }
    dprintf(fd, "%s_messages_thread_%d_cpu = %d\n", prefix, device, info->cpu_number);
    dprintf(fd, "%s_messages_thread_%d_family_model_stepping = %02x-%02x-%02x\n", prefix, device,
            sApp->hwinfo.family, sApp->hwinfo.model, sApp->hwinfo.stepping);
    dprintf(fd, "%s_messages_thread_%d_topology = phys %d, core %d, thr %d\n",
            prefix, device, info->package_id, info->core_id, info->thread_id);
    dprintf(fd, "%s_messages_thread_%d_microcode =", prefix, device);
    if (info->microcode)
        dprintf(fd, " 0x%" PRIx64, info->microcode);
    dprintf(fd, "\n%s_messages_thread_%d_ppin =",
            prefix, device);
    if (pkg && pkg->ppin)
        dprintf(fd, " 0x%" PRIx64, pkg->ppin);
    dprintf(fd, "\n%s_messages_thread_%d = \\\n", prefix, device);
}

void KeyValuePairLogger::print_thread_messages()
{
    auto doprint = [this](PerThreadData::Common *data, int i) {
        struct mmap_region r = maybe_mmap_log(data);

        if (r.size == 0 && !data->has_failed() && sApp->shmem->verbosity < 3)
            return;           /* nothing to be printed, on any level */

        print_thread_header(file_log_fd, i, timestamp_prefix.c_str());
        int lowest_level = print_one_thread_messages_tdata(file_log_fd, data, r, INT_MAX);

        if (lowest_level <= sApp->shmem->verbosity && file_log_fd != real_stdout_fd) {
            print_thread_header(real_stdout_fd, i, test->id);
            print_one_thread_messages_tdata(real_stdout_fd, data, r, sApp->shmem->verbosity);
        }

        munmap_and_truncate_log(data, r);
    };
    for_each_main_thread(doprint, slices.size());
    for_each_test_thread(doprint);
}

void KeyValuePairLogger::print_child_stderr()
{
    print_child_stderr_common([this](int fd) {
        std::string_view prefix = test->id;
        if (fd == file_log_fd)
            prefix = timestamp_prefix.c_str();
        writeln(fd, prefix, "_strerr = \\");
    });
}

void TapFormatLogger::print(int tc)
{
    // build the ok / not ok line
    std::string extra;
    if (const char *qual = quality_string(test))
        extra = qual;

    const char *okstring = "not ok";
    switch (testResult) {
    case TestResult::Skipped:
        extra += "SKIP";
        if (skipInMainThread) {
            // FIXME: multiple main threads
            std::string init_skip_message = get_skip_message(-1);
            if (init_skip_message.size() != 0)
                extra += "(" + std::string(char_to_skip_category(init_skip_message[0])) +
                        " : " + init_skip_message.substr(1,init_skip_message.size()) + ")";
            else
                extra += "(Unknown: check main thread message for details or "
                            "use -vv option for more info)";
        } else {
            extra += "(Runtime: All CPUs skipped while executing 'test_run()' "
                     "function, check log for details)";
        }
        [[fallthrough]];
    case TestResult::Passed:
        okstring = "ok";
        break;
    case TestResult::Failed:
        break;          // no suffix necessary
    case TestResult::TimedOut:
        extra += "timed out";
        break;
    case TestResult::CoreDumped:
        extra += "Core Dumped: ";
        extra += format_status_code();
        break;
    case TestResult::OutOfMemory:
    case TestResult::Killed:
        extra += "Killed: ";
        extra += format_status_code();
        break;
    case TestResult::Interrupted:
        extra += "Interrupted";
        break;
    case TestResult::OperatingSystemError:
        extra += "Operating system error: ";
        extra += format_status_code();
        break;
    }

    std::string tap_line = stdprintf("%s %3i %s", okstring, tc, test->id);
    if (extra.size()) {
        static constexpr std::string_view separator = " # ";
        size_t newsize = std::max(tap_line.size(), size_t(31)) + separator.size() + extra.size();
        tap_line.reserve(newsize);
        if (tap_line.size() < 32)
            tap_line.resize(32, ' ');
        tap_line += separator;
        tap_line += extra;
        extra.clear();
    }

    logging_printf(loglevel(), "%s\n", tap_line.c_str());

    print_thread_messages();
    if (sApp->shmem->verbosity >= 1)
        print_child_stderr();

    if (file_terminator)
        writeln(file_log_fd, file_terminator);
    if (stdout_terminator)
        writeln(real_stdout_fd, stdout_terminator);

    logging_flush();
}

std::string TapFormatLogger::format_status_code()
{
    if (childExitStatus.result == TestResult::OperatingSystemError)
        return sysexit_reason(childExitStatus);
    std::string msg = crash_reason(childExitStatus);
    if (msg.empty()) {
        // format the number
#ifdef _WIN32
        msg = stdprintf("Child process caused error %#08x", childExitStatus.extra);
#else
        // probably a real-time signal
        msg = stdprintf("Child process died with signal %d", childExitStatus.extra);
#endif
    }
    return msg;
}

void TapFormatLogger::maybe_print_yaml_marker(int fd)
{
    static const char yamlseparator[] = " ---";
    auto &terminator = (fd == file_log_fd ? file_terminator : stdout_terminator);
    if (terminator)
        return;

    std::string_view nothing;
    terminator = yamlseparator;
    writeln(fd, yamlseparator,
            "\n  info: {version: ", program_version,
            ", timestamp: ", iso8601_time_now(Iso8601Format::WithoutMs),
            cpu_has_feature(cpu_feature_hypervisor) ? ", virtualized: true" : nothing,
            "}");
    if (std::string fail_info = fail_info_details(); !fail_info.empty())
        IGNORE_RETVAL(write(fd, fail_info.c_str(), fail_info.size()));
}

void TapFormatLogger::print_thread_header(int fd, int device, int verbosity)
{
    maybe_print_yaml_marker(fd);
    if (device < 0) {
        device = ~device;
        if (device == 0)
            writeln(fd, "  Main thread:");
        else
            dprintf(fd, "  Main thread %d:", device);
        return;
    }

    struct cpu_info *info = cpu_info + device;
    std::string line = stdprintf("  Thread %d on CPU %d (pkg %d, core %d, thr %d", device,
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
        PerThreadData::Test *thr = sApp->test_thread_data(device);
        if (std::string time = format_duration(thr->fail_time); time.size())
            writeln(fd, "  - failed: { time: ", time,
                    ", loop-count: ", std::to_string(thr->inner_loop_count_at_fail),
                    " }");
        else if (verbosity > 2)
            writeln(fd, "  - loop-count: ", std::to_string(thr->inner_loop_count));
    }
}

void TapFormatLogger::print_thread_messages()
{
    auto doprint = [this](PerThreadData::Common *data, int i) {
        struct mmap_region r = maybe_mmap_log(data);

        if (r.size == 0 && !data->has_failed() && sApp->shmem->verbosity < 3)
            return;             /* nothing to be printed, on any level */

        print_thread_header(file_log_fd, i, INT_MAX);
        int lowest_level = print_one_thread_messages_tdata(file_log_fd, data, r, INT_MAX);

        if (lowest_level <= sApp->shmem->verbosity && file_log_fd != real_stdout_fd) {
            print_thread_header(real_stdout_fd, i, sApp->shmem->verbosity);
            print_one_thread_messages_tdata(real_stdout_fd, data, r, sApp->shmem->verbosity);
        }

        munmap_and_truncate_log(data, r);
    };
    for_each_main_thread(doprint, slices.size());
    for_each_test_thread(doprint);
}

void TapFormatLogger::print_child_stderr()
{
    print_child_stderr_common([this](int fd) {
        maybe_print_yaml_marker(fd);
        writeln(fd, "  stderr messages: |");
    });
}

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
