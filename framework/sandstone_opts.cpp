/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_p.h"
#include "sandstone_opts.hpp"

#include <barrier>
#include <cinttypes>
#include <functional>
#include <iostream>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

using namespace std::chrono;

using namespace std::chrono_literals;

namespace {
enum {
    invalid_option = 128,         /* not used, here just so the next option is non-zero */

    one_sec_option,
    thirty_sec_option,
    two_min_option,
    five_min_option,

    cpuset_option,
    disable_option,
    dump_cpu_info_option,
    fatal_skips_option,
    gdb_server_option,
    ignore_mce_errors_option,
    ignore_os_errors_option,
    ignore_unknown_tests_option,
    include_optional_option,
    inject_idle_option,
    is_asan_option,
    is_debug_option,
    force_test_time_option,
    test_knob_option,
    longer_runtime_option,
    max_concurrent_threads_option,
    max_cores_per_slice_option,
    max_test_count_option,
    max_test_loop_count_option,
    max_messages_option,
    max_logdata_option,
    mce_check_period_option,
    mem_sample_time_option,
    mem_samples_per_log_option,
    no_mem_sampling_option,
    no_slicing_option,
    no_triage_option,
    on_crash_option,
    on_hang_option,
    output_format_option,
    quality_option,
    quick_run_option,
    raw_list_tests,
    raw_list_group_members,
    raw_list_groups,
    retest_on_failure_option,
    reschedule_option,
    schedule_by_option,
#ifndef NO_SELF_TESTS
    selftest_option,
#endif
    service_option,
    shortened_runtime_option,
    strict_runtime_option,
    syslog_runtime_option,
    temperature_threshold_option,
    test_delay_option,
    test_list_file_option,
    test_list_randomize_option,
    test_tests_option,
    timeout_option,
    total_retest_on_failure,
    triage_option,
    ud_on_failure_option,
    use_builtin_test_list_option,
    vary_frequency,
    vary_uncore_frequency,
    version_option,
    weighted_testrun_option,
    alpha_option,
    beta_option,

    // syntethic values to track which of conflicting opts is currently active
    _duration_option,
    _max_cores_option,
    _max_loop_count_option,
    _action_option,
    _verbosity_option,
    _format_option,
};

static struct option long_options[]  = {
    { "1sec", no_argument, nullptr, one_sec_option },
    { "30sec", no_argument, nullptr, thirty_sec_option },
    { "2min", no_argument, nullptr, two_min_option },
    { "5min", no_argument, nullptr, five_min_option },
    { "alpha", no_argument, &sApp->requested_quality, int(TEST_QUALITY_SKIP) },
    { "beta", no_argument,  &sApp->requested_quality, int(TEST_QUALITY_BETA) },
    { "cpuset", required_argument, nullptr, cpuset_option },
    { "disable", required_argument, nullptr, disable_option },
    { "dump-cpu-info", no_argument, nullptr, dump_cpu_info_option },
    { "enable", required_argument, nullptr, 'e' },
    { "fatal-errors", no_argument, nullptr, 'F'},
    { "fatal-skips", no_argument, nullptr, fatal_skips_option },
    { "fork-mode", required_argument, nullptr, 'f' },
    { "help", no_argument, nullptr, 'h' },
    { "ignore-mce-errors", no_argument, nullptr, ignore_mce_errors_option },
    { "ignore-os-errors", no_argument, nullptr, ignore_os_errors_option },
    { "ignore-timeout", no_argument, nullptr, ignore_os_errors_option },
    { "ignore-unknown-tests", no_argument, nullptr, ignore_unknown_tests_option },
    { "inject-idle", required_argument, nullptr, inject_idle_option },
    { "include-optional", no_argument, nullptr, include_optional_option },
    { "list", no_argument, nullptr, 'l' },
    { "list-tests", no_argument, nullptr, raw_list_tests },
    { "list-group-members", required_argument, nullptr, raw_list_group_members },
    { "list-groups", no_argument, nullptr, raw_list_groups },
    { "longer-runtime", required_argument, nullptr, longer_runtime_option },
    { "max-concurrent-threads", required_argument, nullptr, max_concurrent_threads_option },
    { "max-cores-per-slice", required_argument, nullptr, max_cores_per_slice_option },
    { "max-logdata", required_argument, nullptr, max_logdata_option },
    { "max-messages", required_argument, nullptr, max_messages_option },
    { "max-test-count", required_argument, nullptr, max_test_count_option },
    { "max-test-loop-count", required_argument, nullptr, max_test_loop_count_option },
    { "mce-check-every", required_argument, nullptr, mce_check_period_option },
    { "mem-sample-time", required_argument, nullptr, mem_sample_time_option },
    { "mem-samples-per-log", required_argument, nullptr, mem_samples_per_log_option},
    { "no-memory-sampling", no_argument, nullptr, no_mem_sampling_option },
    { "no-slicing", no_argument, nullptr, no_slicing_option },
    { "triage", no_argument, nullptr, triage_option },
    { "no-triage", no_argument, nullptr, no_triage_option },
    { "on-crash", required_argument, nullptr, on_crash_option },
    { "on-hang", required_argument, nullptr, on_hang_option },
    { "output-format", required_argument, nullptr, output_format_option},
    { "output-log", required_argument, nullptr, 'o' },
    { "quality", required_argument, nullptr, quality_option },
    { "quick", no_argument, nullptr, quick_run_option },
    { "quiet", no_argument, nullptr, 'q' },
    { "retest-on-failure", required_argument, nullptr, retest_on_failure_option },
    { "reschedule", required_argument, nullptr, reschedule_option },
    { "rng-state", required_argument, nullptr, 's' },
    { "schedule-by", required_argument, nullptr, schedule_by_option },
#ifndef NO_SELF_TESTS
    { "selftests", no_argument, nullptr, selftest_option },
#endif
    { "service", no_argument, nullptr, service_option },
    { "shorten-runtime", required_argument, nullptr, shortened_runtime_option },
    { "strict-runtime", no_argument, nullptr, strict_runtime_option },
    { "syslog", no_argument, nullptr, syslog_runtime_option },
    { "temperature-threshold", required_argument, nullptr, temperature_threshold_option },
    { "test-delay", required_argument, nullptr, test_delay_option },
    { "test-list-file", required_argument, nullptr, test_list_file_option },
    { "test-list-randomize", no_argument, nullptr, test_list_randomize_option },
    { "test-time", required_argument, nullptr, 't' },   // repeated below
    { "force-test-time", no_argument, nullptr, force_test_time_option },
    { "test-option", required_argument, nullptr, 'O'},
    { "threads", required_argument, nullptr, 'n' },
    { "time", required_argument, nullptr, 't' },        // repeated above
    { "timeout", required_argument, nullptr, timeout_option },
    { "total-retest-on-failure", required_argument, nullptr, total_retest_on_failure },
    { "total-time", required_argument, nullptr, 'T' },
    { "ud-on-failure", no_argument, nullptr, ud_on_failure_option },
    { "use-builtin-test-list", optional_argument, nullptr, use_builtin_test_list_option },
    { "vary-frequency", no_argument, nullptr, vary_frequency},
    { "vary-uncore-frequency", no_argument, nullptr, vary_uncore_frequency},
    { "verbose", no_argument, nullptr, 'v' },
    { "version", no_argument, nullptr, version_option },
    { "weighted-testrun-type", required_argument, nullptr, weighted_testrun_option },
    { "yaml", optional_argument, nullptr, 'Y' },

#if defined(__SANITIZE_ADDRESS__)
    { "is-asan-build", no_argument, nullptr, is_asan_option },
#endif
#ifndef NDEBUG
    // debug-mode only options:
    { "gdb-server", required_argument, nullptr, gdb_server_option },
    { "is-debug-build", no_argument, nullptr, is_debug_option },
    { "test-tests", no_argument, nullptr, test_tests_option },
#endif
    { nullptr, 0, nullptr, 0 }
};

void suggest_help(char **argv) {
    printf("Try '%s --help' for more information.\n", argv[0]);
}

void usage(char **argv)
{
    static const char usageText[] = R"(%s [options]
Common command-line options are:
 -F, --fatal-errors
     Stop execution after first failure; do not continue to run tests.
 -T <time>, --total-time=<time>
     Specify the minimum run time for the program.  A special value for <time>
     of "forever" causes the program to loop indefinitely.  The defaults for <time>
     is milliseconds, with s, m, and h available for seconds, minutes or hours.
     Example: sandstone -T 60s     # run for at least 60 seconds.
     Example: sandstone -T 5000    # run for at least 5,000 milliseconds
 --strict-runtime
     Use in conjunction with -T to force the program to stop execution after the
     specific time has elapsed.
 -t <test-time>
     Specify the execution time per test for the program in ms.
     Value for this field can also be specified with a label s, m, h for seconds,
     minutes or hours.  Example: 200ms, 2s or 2m
 --max-test-count <NUMBER>
     Specify the maximum number of tests you want to execute.  Allows you
     to run at most <NUMBER> tests in a program execution.
 --max-test-loop-count <NUMBER>
     When this option is present, test execution will be limited by the number
     of times the test executes its main execution loop. This option augments
     the time-based options in that the test will end if either the test time
     condition is exceeded, or the test-max-loop-count is exhausted.  The use
     of --max-test-loop-count disables test fracturing, the default mode of
     test execution in which individual tests are run multiple times with
     different random number seeds during the same invocation of opendcdiag.
     A value of 0 for --max-test-loop-count is interpreted as there being no
     limit to the number of loop iterations.  This special value can be
     used to disable test fracturing.  When specified tests will not be
     fractured and their execution will be time limited.
 --cpuset=<set>
     Selects the CPUs to run tests on. The <set> option may be a comma-separated
     list of either plain numbers that select based on the system's logical
     processor number, or a letter  followed by a number to select based on
     topology: p for package, c for core and t for thread.
 --dump-cpu-info
     Prints the CPU information that the tool detects (package ID, core ID,
     thread ID, microcode, and PPIN) then exit.
 -e <test>, --enable=<test>, --disable=<test>
     Selectively enable/disable a given test. Can be given multiple times.
     <test> is a test's ID (see the -l option), a wildcard matching test IDs.
     or a test group (starting with @).
 --ignore-os-error, --ignore-timeout
     Continue execution of Sandstone even if a test encounters an operating
     system error (this includes tests timing out).
 --ignore-unknown-tests
     Ignore unknown tests listed on --enable and --disable.
 -h, --help
     Print help.
 -l, --list
     Lists the tests and groups, with their descriptions, and exits.
 --list-tests
     Lists the test names.
 --list-groups
     Lists the test groups.
 --max-messages <NUMBER>
     Limits the maximum number of log messages that can be output by a single
     thread per test invocation.  A value of less than or equal to 0 means
     that there is no limit.  The default value is 5.
 --max-logdata <NUMBER>
     Limits the maximum number of bytes of binary data that can be logged
     by a single thread per test invocation.  A value of less than or equal
     to 0 means that there is no limit.  The default value is 128.
     Sandstone will not log partial data, so if the binary data would cause
     the thread to exceed this threshold it simply will not be output.
 -n <NUMBER>, --threads=<NUMBER>
     Set the number of threads to be run to <NUMBER>. If not specified or if
     0 is passed, then the test defaults to the number of CPUs in the system.
     Note the --cpuset and this parameter do not behave well together.
 -o, --output-log <FILE>
     Place all logging information in <FILE>.  By default, a file name is
     auto-generated by the program.  Use -o /dev/null to suppress creation of any file.
 -s <STATE>, --rng-state=<STATE>
     Specify the random generator state to reload. The seed is in the form:
       Engine:engine-specific-data
 -v, -q, --verbose, --quiet
     Set logging output verbosity level.  Default is quiet.
 --version
     Display program version information.
 --1sec, --30sec, --2min, --5min
     Run for the specified amount of time in the option. In this mode, the program
     prioritizes test execution based on prior detections.
     These options are intended to drive coverage over multiple runs.
     Test priority is ignored when running in combination with the
     --test-list-file option.
 --test-list-file <file path>
     Specifies the tests to run in a text file.  This will run the tests
     in the order they appear in the file and also allows you to vary the
     individual test durations.  See the User Guide for details.
 --test-list-randomize
     Randomizes the order in which tests are executed.
 --test-delay <time in ms>
     Delay between individual test executions in milliseconds.
  -Y, --yaml [<indentation>]
     Use YAML for logging. The optional argument is the number of spaces to
     indent each line by (defaults to 0).
For more options and information, please see the User Reference
Guide.
)";

    static const char restrictedUsageText[] = R"(%s [options]
Available command-line options are:
 -h, --help         Print help.
 -q, --query        Reports whether a scan service found an issue and exits.
 -s, --service      Run as a slow scan service.
     --version      Display version number.
)";

    printf(SandstoneConfig::RestrictedCommandLine ? restrictedUsageText : usageText, argv[0]);
}

enum class OutOfRangeMode { Exit, Saturate };
template <typename Integer = int> struct ParseIntArgument
{
    static_assert(std::is_signed_v<Integer> || std::is_unsigned_v<Integer>);
    using MaxInteger = std::conditional_t<std::is_signed_v<Integer>, long long, unsigned long long>;

    const char *name = nullptr;
    const char *explanation = nullptr;
    MaxInteger min = 0;
    MaxInteger max = std::numeric_limits<Integer>::max();
    int base = 10;
    OutOfRangeMode range_mode = OutOfRangeMode::Exit;

    void print_explanation() const
    {
        // i18n style guide says to never construct sentences...
        if (explanation)
            fprintf(stderr, "%s: value is %s\n", program_invocation_name, explanation);
    }

    void print_range_error(const char *arg) const
    {
        const char *severity = "warning";
        if (range_mode == OutOfRangeMode::Exit)
            severity = "error";
        if constexpr (std::is_signed_v<Integer>) {
            fprintf(stderr,
                    "%s: %s: value out of range for option '%s': %s (minimum is %lld, maximum %lld)\n",
                    program_invocation_name, severity, name, arg, min, max);
        } else {
            fprintf(stderr,
                    "%s: %s: value out of range for option '%s': %s (minimum is %llu, maximum %llu)\n",
                    program_invocation_name, severity, name, arg, min, max);
        }
        print_explanation();
    }

    Integer operator()(std::string str) const
    {
        assert(name);
        assert(min <= max);
        assert(Integer(min) == min);
        assert(Integer(max) == max);
        assert(str.size());

        char* arg = &str[0];
        char *end = arg;
        errno = 0;
        MaxInteger parsed;
        if constexpr (std::is_signed_v<Integer>)
            parsed = strtoll(arg, &end, base);
        else
            parsed = strtoull(arg, &end, base);

        if (*end != '\0' || *arg == '\0') {
            // strtoll() did not consume the entire string or there wasn't anything to consume,
            // so it can't be valid
            fprintf(stderr, "%s: invalid argument for option '%s': %s\n", program_invocation_name,
                    name, arg);
            print_explanation();
            exit(EX_USAGE);
        }

        // validate range
        Integer v = Integer(parsed);
        bool erange = (errno == ERANGE);
        if (erange || v != parsed || v < min || v > max) {
            print_range_error(arg);
            if (range_mode == OutOfRangeMode::Exit)
                exit(EX_USAGE);

            if (parsed < min || (erange && parsed == std::numeric_limits<long long>::min()))
                v = Integer(min);
            else if (v > max || (erange && parsed == std::numeric_limits<long long>::max()))
                v = Integer(max);
        }
        return v;
    }
};

void warn_deprecated_opt(const char *opt)
{
    fprintf(stderr, "%s: option '%s' is ignored and will be removed in a future version.\n",
            program_invocation_name, opt);
}

class BarrierDeviceSchedule : public DeviceSchedule
{
public:
    void reschedule_to_next_device() override
    {
        auto on_completion = [&]() noexcept {
            std::unique_lock lock(groups_mutex);
            int g_idx = thread_num / members_per_group;
            GroupInfo &group = groups[g_idx];

            // Rotate cpus vector so reschedule group members to a different cpu
            std::rotate(group.next_cpu.begin(), group.next_cpu.begin() + 1, group.next_cpu.end());
            lock.unlock();

            // Reschedule group members
            for (int i=0; i<group.tid.size(); i++) {
                pin_to_next_cpu(cpu_info[group.next_cpu[i]].cpu_number, group.tid[i]);
            }
        };

        std::unique_lock lock(groups_mutex);
        // Initialize groups on first run
        if (groups.empty()) {
            int full_groups = num_cpus() / members_per_group;
            int partial_group_members = num_cpus() % members_per_group;

            groups.reserve(full_groups + (partial_group_members > 0));
            for (int i=0; i<full_groups; i++) {
                groups.emplace_back(members_per_group, on_completion);
            }
            if (partial_group_members > 0) {
                groups.emplace_back(partial_group_members, on_completion);
            }
        }

        // Fill thread info if not done already
        int g_idx = thread_num / members_per_group;
        GroupInfo &group = groups[g_idx];
        int thread_info_idx = thread_num % members_per_group;
        if (group.tid[thread_info_idx] == 0) {
            group.tid[thread_info_idx] = sApp->test_thread_data(thread_num)->tid.load();
            group.next_cpu[thread_info_idx] = thread_num;
        }

        lock.unlock();

        // Wait on proper barrier
        group.barrier->arrive_and_wait();
        return;
    }

    void finish_reschedule() override
    {
        // Don't clean up when test does not support rescheduling
        if (groups.size() == 0) return;

        // When thread finishes, unsubscribe it from barrier
        // this avoid partners deadlocks
        int g_idx = thread_num / members_per_group;
        GroupInfo &group = groups[g_idx];

        // Remove thread info from groups
        std::unique_lock lock(groups_mutex);
        int thread_info_idx = thread_num % members_per_group;
        group.tid.erase(group.tid.begin() + thread_info_idx);

        // Remove CPU information only if the thread failed, as it likely indicates a problematic device;
        // otherwise, keep it for execution.
        if(sApp->test_thread_data(thread_num)->has_failed())
            group.next_cpu.erase(group.next_cpu.begin() + thread_info_idx);
        lock.unlock();

        group.barrier->arrive_and_drop();
    }

private:
    struct GroupInfo {
        std::barrier<std::function<void()>> *barrier;
        std::vector<pid_t> tid;     // Keep track of all members tid
        std::vector<int> next_cpu;  // Keep track of cpus on the group

        GroupInfo(int members_per_group, std::function<void()> on_completion)
        {
            barrier = new std::barrier<std::function<void()>>(members_per_group, std::move(on_completion));
            tid.resize(members_per_group);
            next_cpu.resize(members_per_group);
        }

        ~GroupInfo()
        {
            delete barrier;
        }
    };

    const int members_per_group = 2; // TODO: Make it configurable
    std::vector<GroupInfo> groups;
    std::mutex groups_mutex;
};

class QueueDeviceSchedule : public DeviceSchedule
{
public:
    void reschedule_to_next_device() override
    {
        // Select a cpu from the queue
        std::lock_guard lock(q_mutex);
        if (q_idx == 0)
            shuffle_queue();

        int next_idx = queue[q_idx];
        if (++q_idx == queue.size())
            q_idx = 0;

        pin_to_next_cpu(cpu_info[next_idx].cpu_number);
        return;
    }

    void finish_reschedule() override {}

private:
    int q_idx = 0;
    std::vector<int> queue;
    std::mutex q_mutex;

    void shuffle_queue()
    {
        // Must be called with mutex locked
        if (queue.size() == 0) {
            // First use: populate queue with the indexes available
            for (int i=0; i<num_cpus(); i++)
                queue.push_back(i);
        }

        std::default_random_engine rng(random32());
        std::shuffle(queue.begin(), queue.end(), rng);
    }
};

class RandomDeviceSchedule : public DeviceSchedule
{
public:
    void reschedule_to_next_device() override
    {
        // Select a random cpu index among the ones available
        int next_idx = unsigned(random()) % num_cpus();
        pin_to_next_cpu(cpu_info[next_idx].cpu_number);

        return;
    }

    void finish_reschedule() override {}
};

struct ProgramOptionsParser {

    std::map<int, std::variant<bool, int, const char*, std::vector<const char*>, ShortDuration>> opts_map;

    void add_to_map_as_vec(int opt, const char *arg) {
        auto map = opts_map.find(opt);
        if (map == opts_map.end()) {
            opts_map.emplace(opt, std::vector<const char*>{arg});
        } else {
            std::get<std::vector<const char*>>(map->second).emplace_back(arg);
        }
    };

    // collect args in cmdline, validate only static conditions, perform trivial parsing only, like string_to_millisecs
    int collect_args(int argc, char** argv)
    {
        int opt;
        int coptind = -1;

        while ((opt = simple_getopt(argc, argv, long_options, &coptind)) != -1) {
            switch (opt) {
            case disable_option:
            case 'e':
            case 'O':
                add_to_map_as_vec(opt, optarg);
                break;

            case 't':
            case test_delay_option:
            case timeout_option:
                opts_map.insert_or_assign(opt, string_to_millisecs(optarg));
                break;

            case cpuset_option:
                opts_map.insert_or_assign(cpuset_option, optarg);
                break;

            // boolean options
            case ignore_mce_errors_option:
            case ignore_os_errors_option:
            case strict_runtime_option:
            case fatal_skips_option:
            case force_test_time_option: /* overrides max and min duration specified by the test */
            case 'F':
            case ud_on_failure_option:
            case test_tests_option:
            case test_list_randomize_option:
#ifndef NO_SELF_TESTS
            case selftest_option:
#endif
            case include_optional_option:
            case ignore_unknown_tests_option:
                opts_map.emplace(opt, true);
                break;

            // 1:1
#ifndef NDEBUG
            case gdb_server_option:
#endif
            case 'f':
            case 'n':
            case 'o':
            case 's':
            case inject_idle_option:
            case mce_check_period_option:
            case on_crash_option:
            case on_hang_option:
            case retest_on_failure_option:
            case total_retest_on_failure:
            case test_list_file_option:
            case temperature_threshold_option:
            case max_logdata_option:
            case max_messages_option:
            case reschedule_option:
                opts_map.insert_or_assign(opt, optarg);
                break;

            case syslog_runtime_option:
                opts_map.insert_or_assign(syslog_runtime_option, program_invocation_name);
                break;

            case use_builtin_test_list_option:
                if (!SandstoneConfig::HasBuiltinTestList) {
                    fprintf(stderr, "%s: --use-builtin-test-list specified but this build does not "
                                    "have a built-in test list.\n", argv[0]);
                    return EX_USAGE;
                }
                opts_map.insert_or_assign(use_builtin_test_list_option, optarg ? optarg : "auto");
                break;

            case vary_frequency:
                if (!FrequencyManager::FrequencyManagerWorks) {
                    fprintf(stderr, "%s: --vary-frequency works only on Linux\n", program_invocation_name);
                    return EX_USAGE;
                }
                opts_map.emplace(vary_frequency, true);
                break;

            case vary_uncore_frequency:
                if (!FrequencyManager::FrequencyManagerWorks) {
                    fprintf(stderr, "%s: --vary-uncore-frequency works only on Linux\n", program_invocation_name);
                    return EX_USAGE;
                }
                opts_map.emplace(vary_uncore_frequency, true);
                break;

            case max_test_count_option:
                opts_map.insert_or_assign(max_test_count_option, optarg);
                break;

            // XXX For compatibility reasons, we allow those conflicting opts and take only the last specified one
            case alpha_option:
                opts_map.insert_or_assign(quality_option, INT_MIN);
                break;
            case beta_option:
                opts_map.insert_or_assign(quality_option, TEST_QUALITY_BETA);
                break;
            case quality_option:
                opts_map.insert_or_assign(quality_option, optarg);
                break;

            case 'l':
            case raw_list_tests:
            case raw_list_groups:
            case dump_cpu_info_option:
            case version_option:
            case is_asan_option:
                // these options are only accessible in the command-line if the
                // corresponding functionality is active
            case is_debug_option:
                // these options are only accessible in the command-line if the
                // corresponding functionality is active
            case 'h':
                opts_map.insert_or_assign(_action_option, opt);
                opts_map.emplace(opt, true);
                break;
            case raw_list_group_members:
                opts_map.insert_or_assign(_action_option, raw_list_group_members);
                opts_map.insert_or_assign(raw_list_group_members, optarg);
                break;

            case service_option:
            case one_sec_option:
            case thirty_sec_option:
            case two_min_option:
            case five_min_option:
                opts_map.insert_or_assign(_duration_option, opt);
                opts_map.emplace(opt, true);
                break;
            case 'T':
                opts_map.insert_or_assign(_duration_option, 'T');
                opts_map.emplace('T', optarg);
                break;

            case max_cores_per_slice_option:
                opts_map.insert_or_assign(_max_cores_option, max_cores_per_slice_option);
                opts_map.insert_or_assign(max_cores_per_slice_option, optarg);
                break;
            case no_slicing_option:
                opts_map.insert_or_assign(_max_cores_option, no_slicing_option);
                opts_map.emplace(no_slicing_option, true);
                break;

            case quick_run_option:
                opts_map.insert_or_assign(_max_loop_count_option, quick_run_option);
                opts_map.emplace(quick_run_option, true);
                break;
            case max_test_loop_count_option:
                opts_map.insert_or_assign(_max_loop_count_option, max_test_loop_count_option);
                opts_map.insert_or_assign(max_test_loop_count_option, optarg);
                break;

            case 'q':
                opts_map.insert_or_assign(_verbosity_option, 'q');
                opts_map.emplace('q', true);
                break;
            case 'v':
                opts_map.insert_or_assign(_verbosity_option, 'v');
                if (auto it = opts_map.find('v'); it != opts_map.end()) {
                    std::get<int>(it->second)++;
                } else {
                    opts_map.emplace('v', 1);
                }
                break;

            case output_format_option:
                opts_map.insert_or_assign(_format_option, output_format_option);
                opts_map.insert_or_assign(output_format_option, optarg);
                break;
            case 'Y':
                opts_map.insert_or_assign(_format_option, 'Y');
                if (auto it = opts_map.find('Y'); it != opts_map.end()) {
                    if (optarg) // do not allow single '-Y' to reset previously set indent
                        it->second = optarg;
                } else {
                    opts_map.emplace('Y', optarg);
                }
                break;

                /* deprecated options */
            case longer_runtime_option:
            case max_concurrent_threads_option:
            case mem_sample_time_option:
            case mem_samples_per_log_option:
            case no_mem_sampling_option:
            case no_triage_option:
            case schedule_by_option:
            case shortened_runtime_option:
            case triage_option:
            case weighted_testrun_option:
                warn_deprecated_opt(long_options[coptind].name);
                break;

            case 0:
                /* long option setting a value */
                continue;
            default:
                suggest_help(argv);
                return EX_USAGE;
            }
        }
        return EXIT_SUCCESS;
    }

    // validate dynamic conditions, like other conflicting arguments' presence.
    int validate_args() const
    {
        return EXIT_SUCCESS;
    }

    template <typename StringType = const char*>
    StringType string_opt_for(int opt) {
        auto it = opts_map.find(opt);
        if (it != opts_map.end())
            return std::get<const char*>(it->second);
        return {};
    };

    // assign values to app and opts, perform more complicated parsing, parse in correct order
    int parse_args(SandstoneApplication* app, ProgramOptions& opts, char** argv)
    {
        // verbosity (before endpoints)
        auto it_verbosity = opts_map.find('v');
        auto verbosity = it_verbosity != opts_map.end() ? std::get<int>(it_verbosity->second) : -1;
        if (opts_map.contains('q')) {
            verbosity = 0;
        }
        app->shmem->verbosity = verbosity;

        // quality (before tests listing)
        if (auto it = opts_map.find(quality_option); it != opts_map.end()) {
            if (const int* value = std::get_if<int>(&it->second)) {
                app->requested_quality = *value;
            } else {
                app->requested_quality = ParseIntArgument<>{
                        .name = "--quality",
                        .min = int(TEST_QUALITY_SKIP),
                        .max = int(TEST_QUALITY_PROD),
                        .range_mode = OutOfRangeMode::Saturate
                }(std::get<const char*>(it->second));
            }
        }
        if (auto it = opts_map.find(include_optional_option); it != opts_map.end()) {
            /* do not override lower quality levels if they were requested */
            app->requested_quality = std::min<int>(app->requested_quality, TEST_QUALITY_OPTIONAL);
        }

        // cpuset (before dump_cpu_info)
        opts.cpuset = string_opt_for<std::string>(cpuset_option);

        // selftest (before test listing)
#ifndef NO_SELF_TESTS
        if (opts_map.contains(selftest_option)) {
            app->shmem->selftest = true;
            opts.test_set_config.is_selftest = true;
        }
#endif

        // endpoints
        if (auto it = opts_map.find(_action_option); it != opts_map.end()) {
            switch (std::get<int>(it->second)) {
            case is_asan_option:
            case is_debug_option:
                opts.action = Action::exit;
                return EXIT_SUCCESS;
            case 'l':
                opts.list_tests_include_descriptions = true;
                opts.list_tests_include_tests = true;
                opts.list_tests_include_groups = true;
                opts.action = Action::list_tests;
                return EXIT_SUCCESS;
            case raw_list_tests:
                opts.list_tests_include_tests = true;
                opts.action = Action::list_tests;
                return EXIT_SUCCESS;
            case raw_list_groups:
                opts.list_tests_include_groups = true;
                opts.action = Action::list_tests;
                return EXIT_SUCCESS;
            case raw_list_group_members: {
                opts.action = Action::list_group;
                auto name = std::get<const char*>(opts_map.at(raw_list_group_members));
                assert(name); // TODO fail instead of assert
                opts.list_group_name = name;
                return EXIT_SUCCESS;
            }
            case dump_cpu_info_option:
                opts.action = Action::dump_cpu_info;
                return EXIT_SUCCESS;
            case version_option:
                opts.action = Action::version;
                return EXIT_SUCCESS;
            case 'h':
                usage(argv);
                opts.action = Action::exit;
                return EXIT_SUCCESS;
            }
        }

        // test selection
        if (auto it = opts_map.find('e'); it != opts_map.end()) {
            opts.enabled_tests = std::move(std::get<std::vector<const char*>>(it->second));
        }
        if (auto it = opts_map.find(disable_option); it != opts_map.end()) {
            opts.disabled_tests = std::move(std::get<std::vector<const char*>>(it->second));
        }

        // times
        if (auto it = opts_map.find('t'); it != opts_map.end()) {
            app->test_time = std::get<ShortDuration>(it->second);
        }

        if (auto it = opts_map.find(timeout_option); it != opts_map.end()) {
            app->max_test_time = std::get<ShortDuration>(it->second);
        }

        if (auto it = opts_map.find(_duration_option); it != opts_map.end()) {
            switch (std::get<int>(it->second)) {
            case 'T': {
                auto endtime = std::get<const char*>(opts_map.at('T'));
                if (strcmp(endtime, "forever") == 0) {
                    app->endtime = MonotonicTimePoint::max();
                } else {
                    app->endtime = app->starttime + string_to_millisecs(endtime);
                }
                opts.test_set_config.cycle_through = true; /* Time controls when the execution stops as
                                                            opposed to the number of tests. */
                break;
            }
            case one_sec_option:
                opts.test_set_config.randomize = true;
                opts.test_set_config.cycle_through = true;
                app->shmem->use_strict_runtime = true;
                app->endtime = app->starttime + 1s;
                break;
            case thirty_sec_option:
                opts.test_set_config.randomize = true;
                opts.test_set_config.cycle_through = true;
                app->shmem->use_strict_runtime = true;
                app->endtime = app->starttime + 30s;
                break;
            case two_min_option:
                opts.test_set_config.randomize = true;
                opts.test_set_config.cycle_through = true;
                app->shmem->use_strict_runtime = true;
                app->endtime = app->starttime + 2min;
                break;
            case five_min_option:
                opts.test_set_config.randomize = true;
                opts.test_set_config.cycle_through = true;
                app->shmem->use_strict_runtime = true;
                app->endtime = app->starttime + 5min;
                break;
            case service_option:
                // keep in sync with RestrictedCommandLine below
                opts.fatal_errors = true;
                app->endtime = MonotonicTimePoint::max();
                app->service_background_scan = true;
                break;
            }
        }

        // boolean flags
        opts.fatal_errors = opts_map.contains('F');

        opts.test_set_config.ignore_unknown_tests = opts_map.contains(ignore_unknown_tests_option);
        opts.test_set_config.randomize = opts_map.contains(test_list_randomize_option);

        app->force_test_time = opts_map.contains(force_test_time_option);
        app->fatal_skips = opts_map.contains(fatal_skips_option);
        app->ignore_mce_errors = opts_map.contains(ignore_mce_errors_option);
        app->ignore_os_errors = opts_map.contains(ignore_os_errors_option);
        app->vary_frequency_mode = opts_map.contains(vary_frequency);
        app->vary_uncore_frequency_mode = opts_map.contains(vary_uncore_frequency);

        app->shmem->use_strict_runtime = opts_map.contains(strict_runtime_option);
        app->shmem->ud_on_failure = opts_map.contains(ud_on_failure_option);

        // assign 1:1
        opts.seed = string_opt_for('s');
#ifndef NDEBUG
        app->gdb_server_comm = string_opt_for<std::string>(gdb_server_option);
#endif
        opts.on_crash_arg = string_opt_for(on_crash_option);
        opts.on_hang_arg = string_opt_for(on_hang_option);
        opts.test_list_file_path = string_opt_for(test_list_file_option);
        app->file_log_path = string_opt_for<std::string>('o');
        app->syslog_ident = string_opt_for(syslog_runtime_option);
        opts.builtin_test_list_name = string_opt_for(use_builtin_test_list_option);

        // the rest
        if (auto value = string_opt_for('f')) {
            std::string_view mode = value;
            if (mode == "no" || mode == "no-fork") {
                app->fork_mode = SandstoneApplication::no_fork;
            } else if (mode == "exec") {
                app->fork_mode = SandstoneApplication::exec_each_test;
#ifndef _WIN32
            } else if (mode == "yes" || mode == "each-test") {
                app->fork_mode = SandstoneApplication::fork_each_test;
#endif
            } else {
                fprintf(stderr, "unknown value to -f\n");
                return EX_USAGE;
            }
        }
        if (auto value = string_opt_for('n')) {
            opts.thread_count = ParseIntArgument<>{
                    .name = "-n / --threads",
                    .min = 1,
                    .max = app->thread_count,
                    .range_mode = OutOfRangeMode::Saturate
            }(value);
        }
        if (auto value = string_opt_for(reschedule_option)) {
            if (opts.thread_count < 2) {
                fprintf(stderr, "%s: --reschedule is only useful with at least 2 threads\n", argv[0]);
                return EX_USAGE;
            }

            std::string_view mode = value;
            if (mode == "none") {
                // Default option, so do nothing
            } else if (mode =="barrier") {
                app->device_schedule = std::make_unique<BarrierDeviceSchedule>();
            } else if (mode == "queue") {
                app->device_schedule = std::make_unique<QueueDeviceSchedule>();
            } else if (mode == "random") {
                app->device_schedule = std::make_unique<RandomDeviceSchedule>();
            } else {
                fprintf(stderr, "%s: unknown reschedule option: %s. Available options: queue, random and none(default)\n", argv[0], value);
                return EX_USAGE;
            }
        }
        if (auto it = opts_map.find('O'); it != opts_map.end()) {
            app->shmem->log_test_knobs = true;
            for (auto knob : std::get<std::vector<const char*>>(it->second)) {
                if (!set_knob_from_key_value_string(knob)) {
                    fprintf(stderr, "Malformed test knob: %s (should be in the form KNOB=VALUE)\n", optarg);
                    return EX_USAGE;
                }
            }
        }

        if (auto it = opts_map.find(_format_option); it != opts_map.end()) {
            switch (std::get<int>(it->second)) {
            case 'Y': {
                app->shmem->output_format = SandstoneApplication::OutputFormat::yaml;
                auto value = std::get<const char*>(opts_map.at('Y'));
                if (value) {
                    app->shmem->output_yaml_indent = ParseIntArgument<>{
                            .name = "-Y / --yaml",
                            .max = 160,     // arbitrary
                    }(value);
                }
                break;
            }
            case output_format_option:
                auto value = std::get<const char*>(opts_map.at(output_format_option));
                std::string_view fmt = value;
                if (fmt == "key-value") {
                    app->shmem->output_format = SandstoneApplication::OutputFormat::key_value;
                } else if (fmt == "tap") {
                    app->shmem->output_format = SandstoneApplication::OutputFormat::tap;
                } else if (fmt == "yaml") {
                    app->shmem->output_format = SandstoneApplication::OutputFormat::yaml;
                } else if (SandstoneConfig::Debug && fmt == "none") {
                    // for testing only
                    app->shmem->output_format = SandstoneApplication::OutputFormat::no_output;
                    app->shmem->verbosity = -1;
                } else {
                    fprintf(stderr, "%s: unknown output format: %s\n", argv[0], value);
                    return EX_USAGE;
                }
                break;
            }
        }

        if (auto it = opts_map.find(_max_cores_option); it != opts_map.end()) {
            switch (std::get<int>(it->second)) {
            case max_cores_per_slice_option:
                opts.max_cores_per_slice = ParseIntArgument<>{
                    .name = "--max-cores-per-slice",
                    .min = -1,
                }(std::get<const char*>(opts_map.at(max_cores_per_slice_option)));
                break;
            case no_slicing_option:
                opts.max_cores_per_slice = -1;
                break;
            }
        }

        if (auto value = string_opt_for(mce_check_period_option)) {
            app->mce_check_period = ParseIntArgument<>{"--mce-check-every"}(value);
        }

        if (auto value = string_opt_for(retest_on_failure_option)) {
            app->retest_count = ParseIntArgument<>{
                    .name = "--retest-on-failure",
                    .max = SandstoneApplication::MaxRetestCount,
                    .range_mode = OutOfRangeMode::Saturate
            }(value);
        }
        if (auto value = string_opt_for(temperature_threshold_option)) {
            if (std::string_view{value} == "disable") {
                app->thermal_throttle_temp = -1;
            } else {
                app->thermal_throttle_temp = ParseIntArgument<>{
                        .name = "--temperature-threshold",
                        .explanation = "value should be specified in thousandths of degrees Celsius "
                                        "(for example, 85000 is 85 degrees Celsius), or \"disable\" "
                                        "to disable monitoring",
                        .max = 160000,      // 160 C is WAAAY too high anyway
                        .range_mode = OutOfRangeMode::Saturate
                }(value);
            }
        }
        if (opts_map.contains(test_tests_option)) {
            app->enable_test_tests();
            if (app->test_tests_enabled()) {
                // disable other options that don't make sense in this mode
                app->retest_count = 0;
            }
        }
        if (auto value = string_opt_for(total_retest_on_failure)) {
            app->total_retest_count = ParseIntArgument<>{
                    .name = "--total-retest-on-failure",
                    .min = -1
            }(value);
        }
        if (auto value = string_opt_for(max_logdata_option)) {
            app->shmem->max_logdata_per_thread = ParseIntArgument<unsigned>{
                    .name = "--max-logdata",
                    .explanation = "maximum number of bytes of test's data to log per thread (0 is unlimited))",
                    .base = 0,      // accept hex
                    .range_mode = OutOfRangeMode::Saturate
            }(value);
            if (app->shmem->max_logdata_per_thread == 0)
                app->shmem->max_logdata_per_thread = UINT_MAX;
        }
        if (auto value = string_opt_for(max_messages_option)) {
            app->shmem->max_messages_per_thread = ParseIntArgument<>{
                    .name = "--max-messages",
                    .explanation = "maximum number of messages (per thread) to log in each test (0 is unlimited)",
                    .min = -1,
                    .range_mode = OutOfRangeMode::Saturate
            }(value);
            if (app->shmem->max_messages_per_thread <= 0)
                app->shmem->max_messages_per_thread = INT_MAX;
        }
        if (auto value = string_opt_for(max_test_count_option)) {
            app->max_test_count = ParseIntArgument<>{"--max-test-count"}(value);
        }

        if (auto it = opts_map.find(_max_loop_count_option); it != opts_map.end()) {
            switch (std::get<int>(it->second)) {
            case max_test_loop_count_option:
                app->max_test_loop_count = ParseIntArgument<>{"--max-test-loop-count"}(std::get<const char*>(opts_map.at(max_test_loop_count_option)));
                    if (app->max_test_loop_count == 0)
                        app->max_test_loop_count = std::numeric_limits<int>::max();
                break;
            case quick_run_option:
                app->max_test_loop_count = 1;
                app->delay_between_tests = 0ms;
                break;
            }
        }

        if (auto it = opts_map.find(test_delay_option); it != opts_map.end()) {
            app->delay_between_tests = std::get<ShortDuration>(it->second);
        }

        if (auto value = string_opt_for(inject_idle_option)) {
            app->inject_idle = ParseIntArgument<>{
                .name = "--inject-idle",
                .min = 0,
                .max = 50,
                .range_mode = OutOfRangeMode::Saturate
            }(value);
        }

        return EXIT_SUCCESS;
    }

    // here we play it simple
    int parse_restricted_command_line(int argc, char** argv, SandstoneApplication* app, ProgramOptions& opts) {
        // Default options for the simplified OpenDCDiag cmdline
        static struct option restricted_long_options[] = {
            { "help", no_argument, nullptr, 'h' },
            { "query", no_argument, nullptr, 'q' },
            { "service", no_argument, nullptr, 's' },
            { "version", no_argument, nullptr, version_option },
            { nullptr, 0, nullptr, 0 }
        };

        int opt;

        while ((opt = simple_getopt(argc, argv, restricted_long_options)) != -1) {
            switch (opt) {
            case 'q':
                // ### FIXME
                fprintf(stderr, "%s: --query not implemented yet\n", argv[0]);
                abort();
            case 's':
                // keep in sync above
                app->endtime = MonotonicTimePoint::max();
                app->service_background_scan = true;
                break;
            case version_option:
                opts.action = Action::version;
                return EXIT_SUCCESS;
            case 'h':
                usage(argv);
                opts.action = Action::exit;
                return opt == 'h' ? EXIT_SUCCESS : EX_USAGE;
            default:
                suggest_help(argv);
                opts.action = Action::exit;
                return EX_USAGE;
            }
        }

        if (SandstoneConfig::NoLogging) {
            app->shmem->output_format = SandstoneApplication::OutputFormat::no_output;
        } else  {
            app->shmem->verbosity = 1;
        }

        app->delay_between_tests = 50ms;
        app->thermal_throttle_temp = INT_MIN;

        static_assert(!SandstoneConfig::RestrictedCommandLine || SandstoneConfig::HasBuiltinTestList,
                "Restricted command-line build must have a built-in test list");
        return EXIT_SUCCESS;
    }
};
} /* anonymous namespace */

int ProgramOptions::parse(int argc, char** argv, SandstoneApplication* app, ProgramOptions& opts) {
    ProgramOptionsParser parser;
    if constexpr (SandstoneConfig::RestrictedCommandLine) {
        return parser.parse_restricted_command_line(argc, argv, app, opts);
    }
    auto ret = parser.collect_args(argc, argv);
    if (ret != EXIT_SUCCESS) {
        return ret;
    }
    ret = parser.validate_args();
    if (ret != EXIT_SUCCESS) {
        return ret;
    }
    return parser.parse_args(app, opts, argv);
}
