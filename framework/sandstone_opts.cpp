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

#ifdef SANDSTONE_UNITTESTS
extern FILE* test_stream;
#define OUT_STREAM test_stream
#define ERR_STREAM test_stream
#else
#define OUT_STREAM stdout
#define ERR_STREAM stderr
#endif

using namespace std::chrono;

using namespace std::chrono_literals;

namespace {
enum {
    invalid_option = 128,         /* not used, here just so the next option is non-zero */

    one_sec_option,
    thirty_sec_option,
    two_min_option,
    five_min_option,

    deviceset_option,
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
    timeout_kill_option,
    total_retest_on_failure,
    triage_option,
    ud_on_failure_option,
    use_builtin_test_list_option,
#if SANDSTONE_FREQUENCY_MANAGER
    vary_frequency,
    vary_uncore_frequency,
#endif
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
    { "alpha", no_argument, nullptr, alpha_option },
    { "beta", no_argument,  nullptr, beta_option },
    { "cpuset", required_argument, nullptr, deviceset_option },
    { "deviceset", required_argument, nullptr, deviceset_option },
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
    { "timeout-kill", required_argument, nullptr, timeout_kill_option },
    { "total-retest-on-failure", required_argument, nullptr, total_retest_on_failure },
    { "total-time", required_argument, nullptr, 'T' },
    { "ud-on-failure", no_argument, nullptr, ud_on_failure_option },
    { "use-builtin-test-list", optional_argument, nullptr, use_builtin_test_list_option },
#if SANDSTONE_FREQUENCY_MANAGER
    { "vary-frequency", no_argument, nullptr, vary_frequency},
    { "vary-uncore-frequency", no_argument, nullptr, vary_uncore_frequency},
#endif
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
    fprintf(OUT_STREAM, "Try '%s --help' for more information.\n", argv[0]);
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
 --cpuset=<set>, --deviceset=<set>
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

    fprintf(OUT_STREAM, SandstoneConfig::RestrictedCommandLine ? restrictedUsageText : usageText, argv[0]);
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
            fprintf(ERR_STREAM, "%s: value is %s\n", program_invocation_name, explanation);
    }

    void print_range_error(const char *arg) const
    {
        const char *severity = "warning";
        if (range_mode == OutOfRangeMode::Exit)
            severity = "error";
        if constexpr (std::is_signed_v<Integer>) {
            fprintf(ERR_STREAM,
                    "%s: %s: value out of range for option '%s': %s (minimum is %lld, maximum %lld)\n",
                    program_invocation_name, severity, name, arg, min, max);
        } else {
            fprintf(ERR_STREAM,
                    "%s: %s: value out of range for option '%s': %s (minimum is %llu, maximum %llu)\n",
                    program_invocation_name, severity, name, arg, min, max);
        }
        print_explanation();
    }

    std::optional<Integer> operator()(std::string str) const
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
            fprintf(ERR_STREAM, "%s: invalid argument for option '%s': %s\n", program_invocation_name,
                    name, arg);
            print_explanation();
            return std::nullopt;
        }

        // validate range
        Integer v = Integer(parsed);
        bool erange = (errno == ERANGE);
        if (erange || v != parsed || v < min || v > max) {
            print_range_error(arg);
            if (range_mode == OutOfRangeMode::Exit)
                return std::nullopt;

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
    fprintf(ERR_STREAM, "%s: option '%s' is ignored and will be removed in a future version.\n",
            program_invocation_name, opt);
}

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
        optind = 1; // reset before starting scanning

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
            case timeout_kill_option:
                opts_map.insert_or_assign(opt, string_to_millisecs(optarg));
                break;

            case deviceset_option:
                opts_map.insert_or_assign(deviceset_option, optarg);
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
                    fprintf(ERR_STREAM, "%s: --use-builtin-test-list specified but this build does not "
                                    "have a built-in test list.\n", argv[0]);
                    return EX_USAGE;
                }
                opts_map.insert_or_assign(use_builtin_test_list_option, optarg ? optarg : "auto");
                break;

#if SANDSTONE_FREQUENCY_MANAGER
            case vary_frequency:
                if (!FrequencyManager::FrequencyManagerWorks) {
                    fprintf(ERR_STREAM, "%s: --vary-frequency works only on Linux\n", program_invocation_name);
                    return EX_USAGE;
                }
                opts_map.emplace(vary_frequency, true);
                break;

            case vary_uncore_frequency:
                if (!FrequencyManager::FrequencyManagerWorks) {
                    fprintf(ERR_STREAM, "%s: --vary-uncore-frequency works only on Linux\n", program_invocation_name);
                    return EX_USAGE;
                }
                opts_map.emplace(vary_uncore_frequency, true);
                break;
#endif

            case max_test_count_option:
                opts_map.insert_or_assign(max_test_count_option, optarg);
                break;

            case alpha_option:
                opts_map.insert_or_assign(quality_option, (int)TEST_QUALITY_SKIP);
                break;
            case beta_option:
                opts_map.insert_or_assign(quality_option, (int)TEST_QUALITY_BETA);
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
    int parse_args(SandstoneApplicationConfig* app_cfg, ProgramOptions& opts, char** argv)
    {
        // verbosity (before endpoints)
        auto it_verbosity = opts_map.find('v');
        auto verbosity = it_verbosity != opts_map.end() ? std::get<int>(it_verbosity->second) : -1;
        if (opts_map.contains('q')) {
            verbosity = 0;
        }
        opts.shmem_cfg.verbosity = verbosity;

        // quality (before tests listing)
        if (auto it = opts_map.find(quality_option); it != opts_map.end()) {
            if (const int* value = std::get_if<int>(&it->second)) {
                app_cfg->requested_quality = *value;
            } else {
                auto maybe_int = ParseIntArgument<>{
                        .name = "--quality",
                        .min = int(TEST_QUALITY_SKIP),
                        .max = int(TEST_QUALITY_PROD),
                        .range_mode = OutOfRangeMode::Saturate
                }(std::get<const char*>(it->second));
                if (maybe_int) {
                    app_cfg->requested_quality = maybe_int.value();
                } else {
                    return EX_USAGE;
                }
            }
        }
        if (auto it = opts_map.find(include_optional_option); it != opts_map.end()) {
            /* do not override lower quality levels if they were requested */
            app_cfg->include_optional = true;
        }

        // deviceset (before dump_cpu_info)
        opts.deviceset = string_opt_for<std::string>(deviceset_option);

        // selftest (before test listing)
#ifndef NO_SELF_TESTS
        if (opts_map.contains(selftest_option)) {
            opts.shmem_cfg.selftest = true;
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
            app_cfg->test_time = std::get<ShortDuration>(it->second);
        }

        if (auto it = opts_map.find(timeout_option); it != opts_map.end()) {
            app_cfg->max_test_time = std::get<ShortDuration>(it->second);
        }

        if (auto it = opts_map.find(timeout_kill_option); it != opts_map.end()) {
            app_cfg->timeout_to_kill = std::get<ShortDuration>(it->second);
        }

        if (auto it = opts_map.find(_duration_option); it != opts_map.end()) {
            switch (std::get<int>(it->second)) {
            case 'T': {
                auto endtime = std::get<const char*>(opts_map.at('T'));
                if (strcmp(endtime, "forever") == 0) {
                    app_cfg->endtime = MonotonicTimePoint::max();
                } else {
                    app_cfg->endtime = app_cfg->starttime + string_to_millisecs(endtime);
                }
                opts.test_set_config.cycle_through = true; /* Time controls when the execution stops as
                                                            opposed to the number of tests. */
                break;
            }
            case one_sec_option:
                opts.test_set_config.randomize = true;
                opts.test_set_config.cycle_through = true;
                opts.shmem_cfg.use_strict_runtime = true;
                app_cfg->endtime = app_cfg->starttime + 1s;
                break;
            case thirty_sec_option:
                opts.test_set_config.randomize = true;
                opts.test_set_config.cycle_through = true;
                opts.shmem_cfg.use_strict_runtime = true;
                app_cfg->endtime = app_cfg->starttime + 30s;
                break;
            case two_min_option:
                opts.test_set_config.randomize = true;
                opts.test_set_config.cycle_through = true;
                opts.shmem_cfg.use_strict_runtime = true;
                app_cfg->endtime = app_cfg->starttime + 2min;
                break;
            case five_min_option:
                opts.test_set_config.randomize = true;
                opts.test_set_config.cycle_through = true;
                opts.shmem_cfg.use_strict_runtime = true;
                app_cfg->endtime = app_cfg->starttime + 5min;
                break;
            case service_option:
                // keep in sync with RestrictedCommandLine below
                opts.fatal_errors = true;
                app_cfg->endtime = MonotonicTimePoint::max();
                app_cfg->service_background_scan = true;
                break;
            }
        }

        // boolean flags
        opts.fatal_errors = opts_map.contains('F');

        opts.test_set_config.ignore_unknown_tests = opts_map.contains(ignore_unknown_tests_option);
        opts.test_set_config.randomize = opts_map.contains(test_list_randomize_option);

        app_cfg->force_test_time = opts_map.contains(force_test_time_option);
        app_cfg->fatal_skips = opts_map.contains(fatal_skips_option);
        app_cfg->ignore_mce_errors = opts_map.contains(ignore_mce_errors_option);
        app_cfg->ignore_os_errors = opts_map.contains(ignore_os_errors_option);
#if SANDSTONE_FREQUENCY_MANAGER
        app_cfg->vary_frequency_mode = opts_map.contains(vary_frequency);
        app_cfg->vary_uncore_frequency_mode = opts_map.contains(vary_uncore_frequency);
#endif

        opts.shmem_cfg.use_strict_runtime = opts_map.contains(strict_runtime_option);
        opts.shmem_cfg.ud_on_failure = opts_map.contains(ud_on_failure_option);

        // assign 1:1
        opts.seed = string_opt_for('s');
#ifndef NDEBUG
        app_cfg->gdb_server_comm = string_opt_for<std::string>(gdb_server_option);
#endif
        opts.on_crash_arg = string_opt_for(on_crash_option);
        opts.on_hang_arg = string_opt_for(on_hang_option);
        opts.test_list_file_path = string_opt_for(test_list_file_option);
        app_cfg->file_log_path = string_opt_for<std::string>('o');
        app_cfg->syslog_ident = string_opt_for(syslog_runtime_option);
        opts.builtin_test_list_name = string_opt_for(use_builtin_test_list_option);

        // the rest
        if (auto value = string_opt_for('f')) {
            std::string_view mode = value;
            if (mode == "no" || mode == "no-fork") {
                app_cfg->fork_mode = SandstoneApplication::ForkMode::no_fork;
            } else if (mode == "exec") {
                app_cfg->fork_mode = SandstoneApplication::ForkMode::exec_each_test;
#ifndef _WIN32
            } else if (mode == "yes" || mode == "each-test") {
                app_cfg->fork_mode = SandstoneApplication::ForkMode::fork_each_test;
#endif
            } else {
                fprintf(ERR_STREAM, "unknown value to -f\n");
                return EX_USAGE;
            }
        }
        if (auto value = string_opt_for('n')) {
            auto maybe_int = ParseIntArgument<>{
                    .name = "-n / --threads",
                    .min = 1,
                    .max = app_cfg->thread_count,
                    .range_mode = OutOfRangeMode::Saturate
            }(value);
            if (maybe_int) {
                opts.thread_count = maybe_int.value();
            } else {
                return EX_USAGE;
            }
        }

        if (auto value = string_opt_for(reschedule_option)) {
            app_cfg->device_scheduler = make_rescheduler(value);
            if (!app_cfg->device_scheduler) {
                fprintf(ERR_STREAM, "%s: unknown reschedule option: %s\n", argv[0], value);
                return EX_USAGE;
            }
        }

        if (auto it = opts_map.find('O'); it != opts_map.end()) {
            opts.shmem_cfg.log_test_knobs = true;
            for (auto knob : std::get<std::vector<const char*>>(it->second)) {
                if (!set_knob_from_key_value_string(knob)) {
                    fprintf(ERR_STREAM, "%s: Malformed test knob: \"%s\" (should be in the form KNOB=VALUE)\n",
                            argv[0], knob);
                    return EX_USAGE;
                }
            }
        }

        if (auto it = opts_map.find(_format_option); it != opts_map.end()) {
            switch (std::get<int>(it->second)) {
            case 'Y': {
                opts.shmem_cfg.output_format = SandstoneApplication::OutputFormat::yaml;
                auto value = std::get<const char*>(opts_map.at('Y'));
                if (value) {
                    auto maybe_int = ParseIntArgument<>{
                            .name = "-Y / --yaml",
                            .max = 160,     // arbitrary
                    }(value);
                    if (maybe_int) {
                        opts.shmem_cfg.output_yaml_indent = maybe_int.value();
                    } else {
                        return EX_USAGE;
                    }
                }
                break;
            }
            case output_format_option:
                auto value = std::get<const char*>(opts_map.at(output_format_option));
                std::string_view fmt = value;
                if (fmt == "key-value") {
                    opts.shmem_cfg.output_format = SandstoneApplication::OutputFormat::key_value;
                } else if (fmt == "tap") {
                    opts.shmem_cfg.output_format = SandstoneApplication::OutputFormat::tap;
                } else if (fmt == "yaml") {
                    opts.shmem_cfg.output_format = SandstoneApplication::OutputFormat::yaml;
                } else if (SandstoneConfig::Debug && fmt == "none") {
                    // for testing only
                    opts.shmem_cfg.output_format = SandstoneApplication::OutputFormat::no_output;
                    opts.shmem_cfg.verbosity = -1;
                } else {
                    fprintf(ERR_STREAM, "%s: unknown output format: %s\n", argv[0], value);
                    return EX_USAGE;
                }
                break;
            }
        }

        if (auto it = opts_map.find(_max_cores_option); it != opts_map.end()) {
            switch (std::get<int>(it->second)) {
            case max_cores_per_slice_option:
            {
                auto maybe_int = ParseIntArgument<>{
                    .name = "--max-cores-per-slice",
                    .min = -1,
                }(std::get<const char*>(opts_map.at(max_cores_per_slice_option)));
                if (maybe_int) {
                    opts.max_cores_per_slice = maybe_int.value();
                } else {
                    return EX_USAGE;
                }
                break;
            }
            case no_slicing_option:
                opts.max_cores_per_slice = -1;
                break;
            }
        }

        if (auto value = string_opt_for(retest_on_failure_option)) {
            auto maybe_int = ParseIntArgument<>{
                    .name = "--retest-on-failure",
                    .max = SandstoneApplication::MaxRetestCount,
                    .range_mode = OutOfRangeMode::Saturate
            }(value);
            if (maybe_int) {
                app_cfg->retest_count = maybe_int.value();
            } else {
                return EX_USAGE;
            }
        }
        if (auto value = string_opt_for(temperature_threshold_option)) {
            if (std::string_view{value} == "disable") {
                app_cfg->thermal_throttle_temp = -1;
            } else {
                auto maybe_int = ParseIntArgument<>{
                        .name = "--temperature-threshold",
                        .explanation = "value should be specified in thousandths of degrees Celsius "
                                        "(for example, 85000 is 85 degrees Celsius), or \"disable\" "
                                        "to disable monitoring",
                        .max = 160000,      // 160 C is WAAAY too high anyway
                        .range_mode = OutOfRangeMode::Saturate
                }(value);
                if (maybe_int) {
                    app_cfg->thermal_throttle_temp = maybe_int.value();
                } else {
                    return EX_USAGE;
                }
            }
        }
        if (opts_map.contains(test_tests_option)) {
            opts.test_tests = true;
        }
        if (auto value = string_opt_for(total_retest_on_failure)) {
            auto maybe_int = ParseIntArgument<>{
                    .name = "--total-retest-on-failure",
                    .min = -1
            }(value);
            if (maybe_int) {
                app_cfg->total_retest_count = maybe_int.value();
            } else {
                return EX_USAGE;
            }
        }
        if (auto value = string_opt_for(max_logdata_option)) {
            auto maybe_int = ParseIntArgument<unsigned>{
                    .name = "--max-logdata",
                    .explanation = "maximum number of bytes of test's data to log per thread (0 is unlimited))",
                    .base = 0,      // accept hex
                    .range_mode = OutOfRangeMode::Saturate
            }(value);
            if (maybe_int) {
                opts.shmem_cfg.max_logdata_per_thread = maybe_int.value();
            } else {
                return EX_USAGE;
            }
            if (opts.shmem_cfg.max_logdata_per_thread == 0)
                opts.shmem_cfg.max_logdata_per_thread = UINT_MAX;
        }
        if (auto value = string_opt_for(max_messages_option)) {
            auto maybe_int = ParseIntArgument<>{
                    .name = "--max-messages",
                    .explanation = "maximum number of messages (per thread) to log in each test (0 is unlimited)",
                    .min = -1,
                    .range_mode = OutOfRangeMode::Saturate
            }(value);
            if (maybe_int) {
                opts.shmem_cfg.max_messages_per_thread = maybe_int.value();
            } else {
                return EX_USAGE;
            }
            if (opts.shmem_cfg.max_messages_per_thread <= 0)
                opts.shmem_cfg.max_messages_per_thread = INT_MAX;
        }
        if (auto value = string_opt_for(max_test_count_option)) {
            auto maybe_int = ParseIntArgument<>{"--max-test-count"}(value);
            if (maybe_int) {
                app_cfg->max_test_count = maybe_int.value();
            } else {
                return EX_USAGE;
            }
        }

        if (auto it = opts_map.find(_max_loop_count_option); it != opts_map.end()) {
            switch (std::get<int>(it->second)) {
            case max_test_loop_count_option:
            {
                auto maybe_int = ParseIntArgument<>{"--max-test-loop-count"}(std::get<const char*>(opts_map.at(max_test_loop_count_option)));
                if (maybe_int) {
                    app_cfg->max_test_loop_count = maybe_int.value();
                } else {
                    return EX_USAGE;
                }
                if (app_cfg->max_test_loop_count == 0) {
                    app_cfg->max_test_loop_count = std::numeric_limits<int>::max();
                }
                break;
            }
            case quick_run_option:
                app_cfg->max_test_loop_count = 1;
                app_cfg->delay_between_tests = 0ms;
                break;
            }
        }

        if (auto it = opts_map.find(test_delay_option); it != opts_map.end()) {
            app_cfg->delay_between_tests = std::get<ShortDuration>(it->second);
        }

        if (auto value = string_opt_for(inject_idle_option)) {
            auto maybe_int = ParseIntArgument<>{
                .name = "--inject-idle",
                .min = 0,
                .max = 50,
                .range_mode = OutOfRangeMode::Saturate
            }(value);
            if (maybe_int) {
                app_cfg->inject_idle = maybe_int.value();
            } else {
                return EX_USAGE;
            }
        }

        return EXIT_SUCCESS;
    }

    // here we play it simple
    int parse_restricted_command_line(int argc, char** argv, SandstoneApplicationConfig* app_cfg, ProgramOptions& opts) {
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
                fprintf(ERR_STREAM, "%s: --query not implemented yet\n", argv[0]);
                abort();
            case 's':
                // keep in sync above
                app_cfg->endtime = MonotonicTimePoint::max();
                app_cfg->service_background_scan = true;
                break;
            case version_option:
                opts.action = Action::version;
                return EXIT_SUCCESS;
            case 'h':
                usage(argv);
                opts.action = Action::exit;
                return EXIT_SUCCESS;
            default:
                suggest_help(argv);
                opts.action = Action::exit;
                return EX_USAGE;
            }
        }

        if (SandstoneConfig::NoLogging) {
            opts.shmem_cfg.output_format = SandstoneApplication::OutputFormat::no_output;
        } else  {
            opts.shmem_cfg.verbosity = 1;
        }

        app_cfg->delay_between_tests = 50ms;
        app_cfg->thermal_throttle_temp = INT_MIN;

        static_assert(!SandstoneConfig::RestrictedCommandLine || SandstoneConfig::HasBuiltinTestList,
                "Restricted command-line build must have a built-in test list");
        return EXIT_SUCCESS;
    }
};
} /* anonymous namespace */

int ProgramOptions::parse(int argc, char** argv, SandstoneApplicationConfig* app_cfg) {
    ProgramOptionsParser parser;
    if constexpr (SandstoneConfig::RestrictedCommandLine) {
        return parser.parse_restricted_command_line(argc, argv, app_cfg, *this);
    }
    auto ret = parser.collect_args(argc, argv);
    if (ret != EXIT_SUCCESS) {
        return ret;
    }
    ret = parser.validate_args();
    if (ret != EXIT_SUCCESS) {
        return ret;
    }
    return parser.parse_args(app_cfg, *this, argv);
}
