/*
 * Copyright 2024 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_p.h"
#include "sandstone_opts.hpp"

#include <cinttypes>
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
    ignore_os_errors_option,
    ignore_unknown_tests_option,
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
    test_index_range_option,
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
};

static struct option long_options[]  = {
    { "1sec", no_argument, nullptr, one_sec_option },
    { "30sec", no_argument, nullptr, thirty_sec_option },
    { "2min", no_argument, nullptr, two_min_option },
    { "5min", no_argument, nullptr, five_min_option },
    { "alpha", no_argument, nullptr, alpha_option },
    { "beta", no_argument, nullptr, beta_option},
    { "cpuset", required_argument, nullptr, cpuset_option },
    { "disable", required_argument, nullptr, disable_option },
    { "dump-cpu-info", no_argument, nullptr, dump_cpu_info_option },
    { "enable", required_argument, nullptr, 'e' },
    { "fatal-errors", no_argument, nullptr, 'F'},
    { "fatal-skips", no_argument, nullptr, fatal_skips_option },
    { "fork-mode", required_argument, nullptr, 'f' },
    { "help", no_argument, nullptr, 'h' },
    { "ignore-os-errors", no_argument, nullptr, ignore_os_errors_option },
    { "ignore-timeout", no_argument, nullptr, ignore_os_errors_option },
    { "ignore-unknown-tests", no_argument, nullptr, ignore_unknown_tests_option },
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
    { "test-range", required_argument, nullptr, test_index_range_option },
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
 --test-range A-B
     Run tests from test number A to test number B based on their list location
     in an input file specified using --test-list-file <inputfile>.
     For example: --test-list-file mytests.list -test-range 6-10
                  runs tests 6 through 10 from the file mytests.list.
     See User Guide for more details.
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

    // non-const because this usually comes from optarg anyway
    Integer operator()(char *arg = optarg) const
    {
        assert(name);
        assert(arg);
        assert(min <= max);
        assert(Integer(min) == min);
        assert(Integer(max) == max);

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

auto parse_testrun_range(const char *arg)
{
    int starting_test_number = 1; // One based count for user interface, not zero based
    int ending_test_number = INT_MAX;

    char *end;
    errno = 0;
    starting_test_number = strtoul(arg, &end, 10);
    if (errno == 0) {
        if (*end == '-')
            ending_test_number = strtoul(end + 1, &end, 10);
        else
            errno = EINVAL;
    }
    if (errno != 0) {
        fprintf(stderr, "%s: error: --test-range requires two dash separated integer args like --test-range 1-10\n",
                program_invocation_name);
        return EXIT_FAILURE;
    }
    if (starting_test_number > ending_test_number)
        std::swap(starting_test_number, ending_test_number);
    if (starting_test_number < 1) {
        fprintf(stderr, "%s: error: The lower bound of the test range must be >= 1, %d specified\n",
                program_invocation_name, starting_test_number);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

void warn_deprecated_opt(const char *opt)
{
    fprintf(stderr, "%s: option '%s' is ignored and will be removed in a future version.\n",
            program_invocation_name, opt);
}

struct CmdlineParser {
    struct ArgsPresent {
        // endpoints
        bool list = false;
        bool list_tests = false;
        bool list_groups = false;
        bool list_group_members = false;
        std::optional<std::string> list_group_members_name;
        bool dump_cpu_info = false;
        bool print_version = false;
        bool help = false;

        // quality
        std::optional<std::string> quality;
        bool alpha = false;
        bool beta = false;

        bool fatal_errors = false;
        bool quiet = false;
        bool fatal_skips = false;
        bool force_test_time = false;
        bool output_yaml_format = false;
        bool ignore_unknown_tests = false;
        bool ignore_os_errors = false;
        bool no_slicing = false;
        bool quick_run = false;
        bool use_strict_runtime = false;
        bool selftest = false;
        bool service = false;
        bool ud_on_failure = false;
        bool randomize = false;
        bool is_asan = false;
        bool is_debug = false;
        bool test_tests = false;
        bool test_index_range = false;

        bool one_sec = false;
        bool thirty_sec = false;
        bool two_min = false;
        bool five_min = false;

        bool vary_frequency_mode = false;
        bool vary_uncore_frequency_mode = false;

        std::optional<const char*> fork_mode;
        std::optional<const char*> seed;
        std::optional<std::string> threads;
        std::optional<ShortDuration> test_time;
        std::optional<ShortDuration> delay_between_tests;
        std::optional<ShortDuration> max_test_time;
        std::optional<std::string> cpuset;
        std::optional<std::string> gdb_server_comm;
        std::optional<const char*> file_log_path;
        std::optional<const char*> total_time;
        std::optional<std::vector<const char*>> log_test_knobs;
        std::optional<std::string> output_yaml_indent;
        std::optional<std::string> max_cores_per_slice;
        std::optional<std::string> mce_check_period;
        std::optional<const char*> on_crash;
        std::optional<const char*> on_hang;
        std::optional<const char*> output_format;
        std::optional<std::string> retest_count;
        std::optional<const char*> syslog_ident;
        std::optional<std::string> max_logdata_per_thread;
        std::optional<std::string> max_messages_per_thread;
        std::optional<std::string> max_test_count;
        std::optional<std::string> max_test_loop_count;
        std::optional<const char*> builtin_test_list_name;
        std::optional<std::string> thermal_throttle_temp;
        std::optional<std::string> total_retest_count;
        std::optional<const char*> test_list_file_path;

        std::optional<std::vector<const char*>> enabled_tests;
        std::optional<std::vector<const char*>> disabled_tests;
    };

    // collect args in cmdline, validate only static conditions, perform trivial parsing only, like string_to_millisecs
    int collect_args(int argc, char** argv)
    {
        int opt;
        int coptind = -1;

        while ((opt = simple_getopt(argc, argv, long_options, &coptind)) != -1) {
            switch (opt) {
            case 'h':
                args_present.help = true;
                break;
            case disable_option:
                if (!args_present.disabled_tests) {
                    args_present.disabled_tests.emplace();
                }
                args_present.disabled_tests->emplace_back(optarg);
                break;
            case 'e':
                if (!args_present.enabled_tests) {
                    args_present.enabled_tests.emplace();
                }
                args_present.enabled_tests->emplace_back(optarg);
                break;
            case 'f':
                args_present.fork_mode = optarg;
                break;
            case 'F':
                args_present.fatal_errors = true;
                break;
            case 'l':
                args_present.list = true;
                break;
            case raw_list_tests:
                args_present.list_tests = true;
                break;
            case raw_list_groups:
                args_present.list_groups = true;
                break;
            case raw_list_group_members:
                args_present.list_group_members = true;
                args_present.list_group_members_name = optarg;
                break;
            case 'n':
                args_present.threads = optarg;
                break;
            case 'o':
                args_present.file_log_path = optarg;
                break;
            case 'O':
                if (!args_present.log_test_knobs) {
                    args_present.log_test_knobs.emplace();
                }
                args_present.log_test_knobs->emplace_back(optarg);
                break;
            case 'q':
                args_present.quiet = true;
                break;
            case 's':
                args_present.seed = optarg;
                break;
            case alpha_option:
                args_present.alpha = true;
                break;
            case beta_option:
                args_present.beta = true;
                break;
            case 't':
                args_present.test_time = string_to_millisecs(optarg);
                break;
            case force_test_time_option: /* overrides max and min duration specified by the test */
                args_present.force_test_time = true;
                break;
            case 'T':
                args_present.total_time = optarg;
                break;
            case 'v':
                if (verbosity < 0)
                    verbosity = 1;
                else
                    ++verbosity;
                break;
            case 'Y':
                args_present.output_yaml_format = true;
                if (optarg) {
                    args_present.output_yaml_indent = optarg;
                }
                break;
            case cpuset_option:
                if (args_present.cpuset) {
                    fprintf(stderr, "cpuset defined more than once\n");
                    return EX_USAGE;
                }
                args_present.cpuset = optarg;
                break;
            case dump_cpu_info_option:
                args_present.dump_cpu_info = true;
                break;
            case fatal_skips_option:
                args_present.fatal_skips = true;
                break;
#ifndef NDEBUG
            case gdb_server_option:
                args_present.gdb_server_comm = optarg;
                break;
#endif
            case ignore_os_errors_option:
                args_present.ignore_os_errors = true;
                break;
            case ignore_unknown_tests_option:
                args_present.ignore_unknown_tests = true;
                break;
            case is_asan_option:
                // these options are only accessible in the command-line if the
                // corresponding functionality is active
                args_present.is_asan = true;
                break;
            case is_debug_option:
                // these options are only accessible in the command-line if the
                // corresponding functionality is active
                args_present.is_debug = true;
                break;
            case max_cores_per_slice_option:
                args_present.max_cores_per_slice = optarg;
                break;
            case mce_check_period_option:
                args_present.mce_check_period = optarg;
                break;
            case no_slicing_option:
                args_present.no_slicing = true;
                break;
            case on_crash_option:
                args_present.on_crash = optarg;
                break;
            case on_hang_option:
                args_present.on_hang = optarg;
                break;
            case output_format_option:
                args_present.output_format = optarg;
                break;

            case quality_option:
                args_present.quality = optarg;
                break;

            case quick_run_option:
                args_present.quick_run = true;
                break;
            case retest_on_failure_option:
                args_present.retest_count = optarg;
                break;
            case strict_runtime_option:
                args_present.use_strict_runtime = true;
                break;
            case syslog_runtime_option:
                args_present.syslog_ident = program_invocation_name;
                break;
#ifndef NO_SELF_TESTS
            case selftest_option:
                args_present.selftest = true;
                break;
#endif
            case service_option:
                args_present.service = true;
                break;
            case ud_on_failure_option:
                args_present.ud_on_failure = true;
                break;
            case use_builtin_test_list_option:
                if (!SandstoneConfig::HasBuiltinTestList) {
                    fprintf(stderr, "%s: --use-builtin-test-list specified but this build does not "
                                    "have a built-in test list.\n", argv[0]);
                    return EX_USAGE;
                }
                args_present.builtin_test_list_name = optarg ? optarg : "auto";
                break;
            case temperature_threshold_option:
                args_present.thermal_throttle_temp = optarg;
                break;

            case test_delay_option:
                args_present.delay_between_tests = string_to_millisecs(optarg);
                break;

            case test_tests_option:
                args_present.test_tests = true;
                break;

            case timeout_option:
                args_present.max_test_time = string_to_millisecs(optarg);
                break;

            case total_retest_on_failure:
                args_present.total_retest_count = optarg;
                break;

            case test_list_file_option:
                args_present.test_list_file_path = optarg;
                break;

            case test_index_range_option:
                args_present.test_index_range = true;
                break;

            case test_list_randomize_option:
                args_present.randomize = true;
                break;

            case max_logdata_option: {
                args_present.max_logdata_per_thread = optarg;
                break;
            }
            case max_messages_option:
                args_present.max_messages_per_thread = optarg;
                break;

            case vary_frequency:
                if (!FrequencyManager::FrequencyManagerWorks) {
                    fprintf(stderr, "%s: --vary-frequency works only on Linux\n", program_invocation_name);
                    return EX_USAGE;
                }
                args_present.vary_frequency_mode = true;
                break;

            case vary_uncore_frequency:
                if (!FrequencyManager::FrequencyManagerWorks) {
                    fprintf(stderr, "%s: --vary-uncore-frequency works only on Linux\n", program_invocation_name);
                    return EX_USAGE;
                }
                args_present.vary_uncore_frequency_mode = true;
                break;

            case version_option:
                args_present.print_version = true;
                break;
            case one_sec_option:
                args_present.one_sec = true;
                break;
            case thirty_sec_option:
                args_present.thirty_sec = true;
                break;
            case two_min_option:
                args_present.two_min = true;
                break;
            case five_min_option:
                args_present.five_min = true;
                break;

            case max_test_count_option:
                args_present.max_test_count = optarg;
                break;

            case max_test_loop_count_option:
                args_present.max_test_loop_count = optarg;
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

    // validate dynamic conditions, like other conflicting arguments' presence
    int validate_args() const
    {
        if ((int)args_present.one_sec + (int)args_present.thirty_sec + (int)args_present.two_min + (int)args_present.five_min + (int)args_present.total_time.has_value() >= 2) {
            fprintf(stderr, "Options 1sec, 30sec, 2min, 5min, total-time are mutually exclusive\n");
            return EX_USAGE;
        }

        if ((int)args_present.list_tests + (int)args_present.list_groups + (int)args_present.list_group_members + (int)args_present.dump_cpu_info + (int)args_present.print_version >= 2) {
            fprintf(stderr, "Options list-tests, list-groups, list-group-members, dump-cpu-info, version are mutually exclusive\n");
            return EX_USAGE;
        }

        if ((int)args_present.alpha + (int)args_present.beta + (int)args_present.quality.has_value() + (int)args_present.selftest >= 2) {
            fprintf(stderr, "Options alpha, beta, quality, selftests are mutually exclusive\n");
            return EX_USAGE;
        }

        if (args_present.max_cores_per_slice && args_present.no_slicing) {
            fprintf(stderr, "Options no-slicing, max-cores-per-slice are mutually exclusive\n");
            return EX_USAGE;
        }

        if (args_present.output_format && (args_present.output_yaml_format || args_present.output_yaml_indent)) {
            if (strcmp(*args_present.output_format, "yaml") != 0) {
                fprintf(stderr, "Options yaml, output-format are mutually exclusive\n");
                return EX_USAGE;
            }
        }

        if (args_present.quiet && verbosity > -1) {
            fprintf(stderr, "Options quiet, verbose are mutually exclusive\n");
            return EX_USAGE;
        }

        if (args_present.total_time && args_present.service) {
            fprintf(stderr, "Options total-time, service are mutually exclusive\n");
            return EX_USAGE;
        }

        if (args_present.quick_run && args_present.max_test_loop_count) {
            fprintf(stderr, "Options quick, max-test-loop-count are mutually exclusive\n");
            return EX_USAGE;
        }

        if (args_present.quick_run && args_present.delay_between_tests) {
            fprintf(stderr, "Options quick, test-delay are mutually exclusive\n");
            return EX_USAGE;
        }

        return EXIT_SUCCESS;
    }

    // assign values to app and opts, perform more complicated parsing, parse in correct order
    int parse_args(SandstoneApplication* app, ProgramOptions& opts, char** argv)
    {
        // verbosity (before endpoints)
        if (args_present.quiet) {
            verbosity = 0;
        }
        app->shmem->verbosity = verbosity;

        // quality (before tests listing)
        if (args_present.alpha) {
            app->requested_quality = INT_MIN;
        }
        if (args_present.beta) {
            app->requested_quality = 0;
        }
        if (args_present.quality) {
            app->requested_quality = ParseIntArgument<>{
                    .name = "--quality",
                    .min = -1000,
                    .max = +1000,
                    .range_mode = OutOfRangeMode::Saturate
            }(&(*args_present.quality)[0]);
        }

        // cpuset (before dump_cpu_info)
        if (args_present.cpuset) {
            opts.cpuset = *args_present.cpuset;
        }

        // selftest (before test listing)
#ifndef NO_SELF_TESTS
        if (args_present.selftest) {
            app->requested_quality = 0;
            app->shmem->selftest = true;
            opts.test_set_config.is_selftest = true;
        }
#endif

        // endpoints
        if (args_present.is_asan || args_present.is_debug) {
            opts.action = Action::exit;
            return EXIT_SUCCESS;
        }
        if (args_present.list) {
            opts.list_tests_include_descriptions = true;
            opts.list_tests_include_tests = true;
            opts.list_tests_include_groups = true;
            opts.action = Action::list_tests;
            return EXIT_SUCCESS;
        }
        if (args_present.list_tests) {
            opts.list_tests_include_tests = true;
            opts.action = Action::list_tests;
            return EXIT_SUCCESS;
        }
        if (args_present.list_groups) {
            opts.list_tests_include_groups = true;
            opts.action = Action::list_tests;
            return EXIT_SUCCESS;
        }
        if (args_present.list_group_members) {
            opts.action = Action::list_group;
            assert(args_present.list_group_members_name);
            opts.list_group_name = *args_present.list_group_members_name;
            return EXIT_SUCCESS;
        }
        if (args_present.dump_cpu_info) {
            opts.action = Action::dump_cpu_info;
            return EXIT_SUCCESS;
        }
        if (args_present.print_version) {
            opts.action = Action::version;
            return EXIT_SUCCESS;
        }
        if (args_present.help) {
            usage(argv);
            opts.action = Action::exit;
            return EXIT_SUCCESS;
        }

        // test selection
        if (args_present.enabled_tests) {
            opts.enabled_tests = std::move(*args_present.enabled_tests);
        }
        if (args_present.disabled_tests) {
            opts.disabled_tests = std::move(*args_present.disabled_tests);
        }

        // times
        if (args_present.test_time) {
            app->test_time = *args_present.test_time;
        }
        if (args_present.delay_between_tests) {
            app->delay_between_tests = *args_present.delay_between_tests;
        }
        if (args_present.max_test_time) {
            app->max_test_time = *args_present.max_test_time;
        }
        if (args_present.total_time) {
            if (strcmp(*args_present.total_time, "forever") == 0) {
                app->endtime = MonotonicTimePoint::max();
            } else {
                app->endtime = app->starttime + string_to_millisecs(*args_present.total_time);
            }
            opts.test_set_config.cycle_through = true; /* Time controls when the execution stops as
                                                        opposed to the number of tests. */
        }
        if (args_present.one_sec) {
            opts.test_set_config.randomize = true;
            opts.test_set_config.cycle_through = true;
            app->shmem->use_strict_runtime = true;
            app->endtime = app->starttime + 1s;
        }
        if (args_present.thirty_sec) {
            opts.test_set_config.randomize = true;
            opts.test_set_config.cycle_through = true;
            app->shmem->use_strict_runtime = true;
            app->endtime = app->starttime + 30s;
        }
        if (args_present.two_min) {
            opts.test_set_config.randomize = true;
            opts.test_set_config.cycle_through = true;
            app->shmem->use_strict_runtime = true;
            app->endtime = app->starttime + 2min;
        }
        if (args_present.five_min) {
            opts.test_set_config.randomize = true;
            opts.test_set_config.cycle_through = true;
            app->shmem->use_strict_runtime = true;
            app->endtime = app->starttime + 5min;
        }

        // boolean flags
        opts.fatal_errors = args_present.fatal_errors;

        opts.test_set_config.ignore_unknown_tests = args_present.ignore_unknown_tests;
        opts.test_set_config.randomize = args_present.randomize;

        app->force_test_time = args_present.force_test_time;
        app->fatal_skips = args_present.fatal_skips;
        app->ignore_os_errors = args_present.ignore_os_errors;
        app->vary_frequency_mode = args_present.vary_frequency_mode;
        app->vary_uncore_frequency_mode = args_present.vary_uncore_frequency_mode;

        app->shmem->use_strict_runtime = args_present.use_strict_runtime;
        app->shmem->ud_on_failure = args_present.ud_on_failure;

        // assign 1:1
        if (args_present.seed) {
            opts.seed = *args_present.seed;
        }
#ifndef NDEBUG
        if (args_present.gdb_server_comm) {
            app->gdb_server_comm = *args_present.gdb_server_comm;
        }
#endif
        if (args_present.on_crash) {
            opts.on_crash_arg = *args_present.on_crash;
        }
        if (args_present.on_hang) {
            opts.on_hang_arg = *args_present.on_hang;
        }
        if (args_present.test_list_file_path) {
            opts.test_list_file_path = *args_present.test_list_file_path;
        }
        if (args_present.file_log_path) {
            app->file_log_path = *args_present.file_log_path;
        }
        if (args_present.syslog_ident) {
            app->syslog_ident = *args_present.syslog_ident;
        }
        if (args_present.builtin_test_list_name) {
            opts.builtin_test_list_name = *args_present.builtin_test_list_name;
        }

        // the rest
        if (args_present.fork_mode) {
            auto value = args_present.fork_mode.value();
            if (strcmp(value, "no") == 0 || strcmp(value, "no-fork") == 0) {
                app->fork_mode = SandstoneApplication::no_fork;
            } else if (!strcmp(value, "exec")) {
                app->fork_mode = SandstoneApplication::exec_each_test;
#ifndef _WIN32
            } else if (strcmp(value, "yes") == 0 || strcmp(value, "each-test") == 0) {
                app->fork_mode = SandstoneApplication::fork_each_test;
#endif
            } else {
                fprintf(stderr, "unknown value to -f\n");
                return EX_USAGE;
            }
        }
        if (args_present.service) {
            // keep in sync with RestrictedCommandLine below
            opts.fatal_errors = true;
            app->endtime = MonotonicTimePoint::max();
            app->service_background_scan = true;
        }
        if (args_present.threads) {
            opts.thread_count = ParseIntArgument<>{
                    .name = "-n / --threads",
                    .min = 1,
                    .max = app->thread_count,
                    .range_mode = OutOfRangeMode::Saturate
            }(&(*args_present.threads)[0]);
        }
        if (args_present.log_test_knobs) {
            app->shmem->log_test_knobs = true;
            for (auto&& knob : *args_present.log_test_knobs) {
                if (!set_knob_from_key_value_string(knob)) {
                    fprintf(stderr, "Malformed test knob: %s (should be in the form KNOB=VALUE)\n", optarg);
                    return EX_USAGE;
                }
            }
        }
        if (args_present.output_yaml_format) {
            app->shmem->output_format = SandstoneApplication::OutputFormat::yaml;
        }
        if (args_present.output_yaml_indent) {
            app->shmem->output_format = SandstoneApplication::OutputFormat::yaml;
            app->shmem->output_yaml_indent = ParseIntArgument<>{
                    .name = "-Y / --yaml",
                    .max = 160,     // arbitrary
            }(&(*args_present.output_yaml_indent)[0]);
        }
        if (args_present.max_cores_per_slice) {
            opts.max_cores_per_slice = ParseIntArgument<>{
                .name = "--max-cores-per-slice",
                .min = -1,
            }(&(*args_present.max_cores_per_slice)[0]);
        }
        if (args_present.no_slicing) {
            opts.max_cores_per_slice = -1;
        }
        if (args_present.mce_check_period) {
            app->mce_check_period = ParseIntArgument<>{"--mce-check-every"}(&(*args_present.mce_check_period)[0]);
        }
        if (args_present.output_format) {
            auto value = *args_present.output_format;
            if (strcmp(value, "key-value") == 0) {
                app->shmem->output_format = SandstoneApplication::OutputFormat::key_value;
            } else if (strcmp(value, "tap") == 0) {
                app->shmem->output_format = SandstoneApplication::OutputFormat::tap;
            } else if (strcmp(value, "yaml") == 0) {
                app->shmem->output_format = SandstoneApplication::OutputFormat::yaml;
            } else if (SandstoneConfig::Debug && strcmp(value, "none") == 0) {
                // for testing only
                app->shmem->output_format = SandstoneApplication::OutputFormat::no_output;
                app->shmem->verbosity = -1;
            } else {
                fprintf(stderr, "%s: unknown output format: %s\n", argv[0], value);
                return EX_USAGE;
            }
        }
        if (args_present.quick_run) {
            app->max_test_loop_count = 1;
            app->delay_between_tests = 0ms;
        }
        if (args_present.retest_count) {
            app->retest_count = ParseIntArgument<>{
                    .name = "--retest-on-failure",
                    .max = SandstoneApplication::MaxRetestCount,
                    .range_mode = OutOfRangeMode::Saturate
            }(&(*args_present.retest_count)[0]);
        }
        if (args_present.thermal_throttle_temp) {
            if (*args_present.thermal_throttle_temp == "disable") {
                app->thermal_throttle_temp = -1;
            } else {
                app->thermal_throttle_temp = ParseIntArgument<>{
                        .name = "--temperature-threshold",
                        .explanation = "value should be specified in thousandths of degrees Celsius "
                                        "(for example, 85000 is 85 degrees Celsius), or \"disable\" "
                                        "to disable monitoring",
                        .max = 160000,      // 160 C is WAAAY too high anyway
                        .range_mode = OutOfRangeMode::Saturate
                }(&(*args_present.thermal_throttle_temp)[0]);
            }
        }
        if (args_present.test_tests) {
            app->enable_test_tests();
            if (app->test_tests_enabled()) {
                // disable other options that don't make sense in this mode
                app->retest_count = 0;
            }
        }
        if (args_present.total_retest_count) {
            app->total_retest_count = ParseIntArgument<>{
                    .name = "--total-retest-on-failure",
                    .min = -1
            }(&(*args_present.total_retest_count)[0]);
        }
        if (args_present.test_index_range) {
            if (parse_testrun_range(optarg) == EXIT_FAILURE)
                return EX_USAGE;
        }
        if (args_present.max_logdata_per_thread) {
            app->shmem->max_logdata_per_thread = ParseIntArgument<unsigned>{
                    .name = "--max-logdata",
                    .explanation = "maximum number of bytes of test's data to log per thread (0 is unlimited))",
                    .base = 0,      // accept hex
                    .range_mode = OutOfRangeMode::Saturate
            }(&(*args_present.max_logdata_per_thread)[0]);
            if (app->shmem->max_logdata_per_thread == 0)
                app->shmem->max_logdata_per_thread = UINT_MAX;
        }
        if (args_present.max_messages_per_thread) {
            app->shmem->max_messages_per_thread = ParseIntArgument<>{
                    .name = "--max-messages",
                    .explanation = "maximum number of messages (per thread) to log in each test (0 is unlimited)",
                    .min = -1,
                    .range_mode = OutOfRangeMode::Saturate
            }(&(*args_present.max_messages_per_thread)[0]);
            if (app->shmem->max_messages_per_thread <= 0)
                app->shmem->max_messages_per_thread = INT_MAX;
        }
        if (args_present.max_test_count) {
            app->max_test_count = ParseIntArgument<>{"--max-test-count"}(&(*args_present.max_test_count)[0]);
        }
        if (args_present.max_test_loop_count) {
            app->max_test_loop_count = ParseIntArgument<>{"--max-test-loop-count"}(&(*args_present.max_test_loop_count)[0]);
            if (app->max_test_loop_count == 0)
                app->max_test_loop_count = std::numeric_limits<int>::max();
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

    ArgsPresent args_present;
    int verbosity = -1;
};
} /* anonymous namespace */

int ProgramOptions::parse(int argc, char** argv, SandstoneApplication* app, ProgramOptions& opts) {
    // isolate CmdlineParser existance so that we create it only for the sake of cmdline parsing
    CmdlineParser parser;
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
