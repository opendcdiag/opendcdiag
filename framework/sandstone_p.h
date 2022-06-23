/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * NOTE: This is a private include file of the sandstone framework and should
 * not be included by any tests.
 */

#ifndef INC_SANDSTONE_P_H
#define INC_SANDSTONE_P_H

#define _DARWIN_C_SOURCE 1

#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <unistd.h>

#include <sandstone.h>

#ifdef __cplusplus
#include <memory>
#include <map>

#include <sandstone_config.h>
#include <sandstone_utils.h>

#include "effective_cpu_freq.hpp"
#include "topology.h"
#include "interrupt_monitor.hpp"
#include "SelectorFactory.h"
#include "TestrunSelectorBase.h"
#include "thermal_monitor.hpp"

#ifndef O_NOSIGPIPE
#  define O_NOSIGPIPE 0
#endif

extern "C" {
#endif

#ifdef _WIN32
#define EINTR_LOOP(ret, stmt)               ret = stmt
#else
#define EINTR_LOOP(ret, stmt)               \
    do {                                    \
        ret = stmt;                         \
    } while (ret == -1 && errno == EINTR)
#endif

/* align to a power of 2 */
#define ROUND_UP_TO(value, n)       (((value) + (n) - 1) & (~((n) - 1)))
#define ROUND_UP_TO_PAGE(value)     ROUND_UP_TO(value, 4096U)

#define LOG_LEVEL_ERROR         -1
#define LOG_LEVEL_QUIET         0
#define LOG_LEVEL_VERBOSE(n)    (n)

extern char *program_invocation_name;       // also in glibc's <errno.h>

struct per_thread_data;
struct test;

struct mmap_region
{
    void *base;
    size_t size;        /* actual size, not rounded up to page */
};

/* child_debug.cpp */
void debug_init_child(void);
void debug_init_global(const char *on_hang_arg, const char *on_crash_arg);
intptr_t debug_child_watch(void);
void debug_crashed_child(pid_t child);
void debug_hung_child(pid_t child);

/* splitlock_detect.c */
bool splitlock_enforcement_enabled(void);

/* mmap_region.c */
struct mmap_region mmap_file(int fd);
void munmap_file(struct mmap_region r);

/* memfpt.c / cpp */
size_t memfpt_current_high_water_mark(void);

/* tmpfile.c */
enum MemfdCloexecFlag { MemfdInheritOnExec, MemfdCloseOnExec };
int open_memfd(enum MemfdCloexecFlag);

#ifdef __cplusplus
}
using Duration = std::chrono::steady_clock::duration;
using MonotonicTimePoint = std::chrono::steady_clock::time_point;
struct RandomEngineWrapper;
struct RandomEngineDeleter { void operator()(RandomEngineWrapper *) const; };

enum TestResult : int8_t {
    TestPassed = EXIT_SUCCESS,
    TestFailed = EXIT_FAILURE,
    TestTimedOut,
    TestCoreDumped,
    TestKilled,
    TestOutOfMemory,
    TestInterrupted,
    TestOperatingSystemError,
    TestSkipped = -1,
};

enum ThreadState : int_least8_t {
    thread_not_started = 0,
    thread_running = 1,
    thread_failed = 2,
    thread_succeeded = -1,
    thread_skipped = -2,
};

struct ChildExitStatus
{
    TestResult result;

    // for TestKilled and TestCoreDumped, on Unix it's the signal number;
    // on Windows it's an NTSTATUS
    unsigned extra = 0;
};

struct test_group
{
   const char *id;
   const char *description;
   initfunc (*group_init)() noexcept;       // returns a replacement init function (or not)
};

inline int simple_getopt(int argc, char **argv, struct option *options, int *optind = nullptr)
{
    // cache the result
    static std::string cached_short_opts = [=]() {
        std::string result;
        for (struct option *o = options; o->name; ++o) {
            if (o->flag || o->val < ' ' || o->val > '\x7f')
                continue;
            result += char(o->val);
            if (o->has_arg != no_argument)
                result += ':';
            if (o->has_arg == optional_argument)
                result += ':';
        }
        return result;
    }();
    return getopt_long(argc, argv, cached_short_opts.c_str(), options, optind);
}

struct alignas(64) per_thread_data
{
    std::atomic<ThreadState> thread_state;

    /* Records number of messages logged per thread of each test */
    int messages_logged;

    /* Records the number of bytes log_data'ed per thread */
    size_t data_bytes_logged;

    /* Number of iterations of the inner loop (aka #times test_time_condition called) */
    uint64_t inner_loop_count;
    uint64_t inner_loop_count_at_fail;
    uint64_t fail_time;

    /* Thread's effective CPU frequency during execution */
    double effective_freq_mhz;

    bool has_failed() const
    {
        return fail_time > 0;
    }
};

template <bool IsDebug> struct test_the_test_data
{
    bool test_tests_enabled() const             { return false; }
    void enable_test_tests()                    {}
    void test_tests_init(const struct test *)   {}
    void test_tests_iteration(const struct test *)  {}
    void test_tests_finish(const struct test *) {}
};

template <> struct test_the_test_data<true>
{
    static constexpr Duration OverallTestTimeIgnore = std::chrono::milliseconds(100);
    static constexpr Duration MaximumLoopDuration = std::chrono::milliseconds(300);
    static constexpr Duration TargetLoopDuration = std::chrono::milliseconds(10);
    static constexpr Duration MinimumLoopDuration = std::chrono::milliseconds(1);
    static constexpr size_t MaxAcceptableMemoryUseKB = 64 * 1024;    // per thread
    static constexpr int DesiredIterations = 4;
    struct PerThread {
        std::array<MonotonicTimePoint, DesiredIterations> iteration_times;
    };

    std::vector<PerThread> per_thread;
    size_t hwm_at_start;
    bool test_tests = false;

    bool test_tests_enabled() const { return test_tests; }
    void enable_test_tests()        { test_tests = true; }

    void test_tests_init(const struct test *);
    void test_tests_iteration(const struct test *);
    void test_tests_finish(const struct test *);
};

struct SandstoneApplication : public InterruptMonitor, public test_the_test_data<SandstoneConfig::Debug>
{
    enum class ScheduleBy : int8_t {
        Thread,
        Core
    };

    enum class OutputFormat : int8_t {
        no_output   = 0,
        tap,
        key_value,
        yaml,
    };

    enum ForkMode : int8_t {
        no_fork,
        fork_each_test,
        exec_each_test,
        child_exec_each_test,       // when parent is exec_each_test
    };

    using PerCpuFailures = std::vector<uint64_t>;

    struct ExecState;

    struct SharedMemory {
        per_thread_data main_thread_data;
        per_thread_data per_thread[MAX_THREADS];
    };
    std::vector<test_data_per_thread> user_thread_data;
    SharedMemory *shmem = nullptr;
    int shmemfd = -1;

    std::string file_log_path;
    static constexpr int DefaultQualityLevel = 50;
    int requested_quality = DefaultQualityLevel;
    int verbosity = -1;
    int max_messages_per_thread = 5;
    unsigned max_logdata_per_thread = 128;
    const char *syslog_ident = nullptr;
#if SANDSTONE_NO_LOGGING
    static constexpr auto DefaultOutputFormat = OutputFormat::no_output;
#elif SANDSTONE_TAP_LOGGING
    static constexpr auto DefaultOutputFormat = OutputFormat::tap;
#elif SANDSTONE_YAML_LOGGING
    static constexpr auto DefaultOutputFormat = OutputFormat::yaml;
#else
    // At some point in the near future, change to YAML too
    static constexpr auto DefaultOutputFormat = OutputFormat::tap;
#endif
    OutputFormat output_format = DefaultOutputFormat;
    uint8_t output_yaml_indent = 0;

    bool fatal_skips = false;
    bool use_strict_runtime = false;

    // Weighted testrun selector section ============================================ //
    // see also in sandstone.cpp:
    //static TestrunSelector *test_selector;
    int starting_test_number = 1;  // One based count for user interface, not zero based
    int ending_test_number = INT_MAX;
    WeightedTestScheme test_selection_strategy = Alphabetical;
    WeightedTestLength weighted_testrunner_runtimes = NormalTestrunTimes;

    bool test_list_randomize = false;
    // Weighted testrun selector section ============================================ //

    ScheduleBy schedule_by = ScheduleBy::Thread;
    ForkMode fork_mode =
#ifdef _WIN32
            exec_each_test;
#else
            fork_each_test;
#endif
    bool shared_memory_is_shared = false;
#ifdef NDEBUG
    static constexpr
#endif
    bool use_predictable_file_names = false;
    bool log_test_knobs = false;
    bool slicing = true;
    bool ignore_os_errors = false;
    bool force_test_time = false;
    bool ud_on_failure = false;
    static constexpr int MaxRetestCount = 64;
    int retest_count = 10;
    int total_retest_count = -2;
    int max_test_count = INT_MAX;
    int max_test_loop_count = 0;
    int max_concurrent_thread_count = 0;
    int current_max_loop_count;
    int current_max_threads;
    int current_slice_count = 1;
    int current_iteration_count;        // iterations of the same test (positive for fracture; negative for retest)
    MonotonicTimePoint starttime;
    MonotonicTimePoint endtime;
    MonotonicTimePoint current_test_starttime;
    MonotonicTimePoint current_test_endtime;
    Duration current_test_duration;
    Duration test_time = Duration::zero();
    Duration max_test_time = Duration::zero();
    Duration delay_between_tests = std::chrono::milliseconds(5);

    std::unique_ptr<RandomEngineWrapper, RandomEngineDeleter> random_engine;

    LogicalProcessorSet enabled_cpus;
    int thread_count;

#ifndef __linux__
    std::string path_to_self;
#endif

    static constexpr int DefaultTemperatureThreshold = -1;
    int thermal_throttle_temp = DefaultTemperatureThreshold;
    int threshold_time_remaining = 30000;
    int mce_check_period = 0;
    uint64_t last_thermal_event_count;
    uint64_t mce_count_last;
    std::vector<uint32_t> mce_counts_start;
    std::map<int, uint64_t> smi_counts_start;

    std::vector<struct test *>  test_list;
    int thread_offset;

    ForkMode current_fork_mode() const
    {
#ifndef _WIN32
        if (SandstoneConfig::RestrictedCommandLine) {
            return SandstoneApplication::fork_each_test;
        }
#endif
        return fork_mode;
    }

private:
    SandstoneApplication() = default;
    ~SandstoneApplication() = delete;
    SandstoneApplication(const SandstoneApplication &) = delete;
    SandstoneApplication &operator=(const SandstoneApplication &) = delete;
    friend int internal_main(int argc, char **argv);
    friend int main(int argc, char **argv);
    friend SandstoneApplication *_sApp();
};

// state from SandstoneApplication:
#ifdef NDEBUG
#define APP_STATE_VARIABLES_DEBUGONLY(F)
#else
#define APP_STATE_VARIABLES_DEBUGONLY(F)    \
    F(use_predictable_file_names)
#endif
#define APP_STATE_VARIABLES(F)              \
    APP_STATE_VARIABLES_DEBUGONLY(F)        \
    F(shmemfd)                              \
    F(verbosity)                            \
    F(max_messages_per_thread)              \
    F(max_logdata_per_thread)               \
    F(output_format)                        \
    F(output_yaml_indent)                   \
    F(use_strict_runtime)                   \
    F(log_test_knobs)                       \
    F(slicing)                              \
    F(force_test_time)                      \
    F(ud_on_failure)                        \
    F(current_max_loop_count)               \
    F(current_max_threads)                  \
    F(current_slice_count)                  \
    F(current_test_endtime)                 \
    F(current_test_duration)                \
    F(test_time)                            \
    F(max_test_time)

struct SandstoneApplication::ExecState
{
    int thread_log_fds[MAX_THREADS + 1];        // +1 for the main thread's log

#define DECLARE_APP_STATE_VARIABLES(id)     decltype(SandstoneApplication::id) id;
    APP_STATE_VARIABLES(DECLARE_APP_STATE_VARIABLES)
#undef DECLARE_APP_STATE_VARIABLES

    uint8_t cpu_mask[sizeof(LogicalProcessorSet::array)];
    int thread_count;
    bool selftest;
};

inline SandstoneApplication *_sApp()
{
    using App = std::aligned_storage_t<sizeof(SandstoneApplication), alignof(SandstoneApplication)>;
    static App app;
    return reinterpret_cast<SandstoneApplication *>(&app);
}

#define sApp    _sApp()

static inline per_thread_data *cpu_data_for_thread(int thread)
{
    if (thread == -1)
        return &sApp->shmem->main_thread_data;
    return &sApp->shmem->per_thread[thread + sApp->thread_offset];
}

static inline per_thread_data *cpu_data()
{
    return cpu_data_for_thread(thread_num);
}

struct AutoClosingFile
{
    FILE *f = nullptr;
    ~AutoClosingFile() { if (f) fclose(f); }
    operator FILE *() const { return f; }
};

struct Pipe
{
    enum DontCreateFlag { DontCreate };
    int fds[2] =                { -1, -1 };
    int &in()                   { return fds[0]; }
    int &out()                  { return fds[1]; }
    void close_input()          { do_close(in()); }
    void close_output()         { do_close(out()); }
    Pipe()                      { open(); }
    Pipe(DontCreateFlag)        { }
    ~Pipe()                     { close_input(); close_output(); }
    explicit operator bool()    { return in() != -1 || out() != -1; }

    int open(int reserved = PIPE_BUF)
    {
#ifdef _WIN32
        // Windows won't signal any way
        return _pipe(fds, reserved, _O_BINARY | _O_NOINHERIT);
#elif defined(__APPLE__)
        int ret = pipe(fds);
        if (ret < 0)
            return ret;
        fcntl(out(), F_SETNOSIGPIPE, 1);
        return 0;
#else
        // pipe2 is a Linux invention but all modern Unix (not macOS) have it too
        int ret = pipe2(fds, O_CLOEXEC | O_NOSIGPIPE);
        if (ret < 0)
            return ret;
#  ifdef F_SETPIPE_SZ
        if (reserved > PIPE_BUF) {
            int ret = fcntl(out(), F_GETPIPE_SZ);
            if (ret >= 0 && ret < reserved) {
                // increase size, but ignore errors
                fcntl(out(), F_SETPIPE_SZ, reserved);
            }
        }
#  endif
        return 0;
#endif
    }
private:
    void do_close(int &fd)
    {
        if (fd != -1) {
            close(fd);
            fd = -1;
        }
    }
};

static_assert(std::is_trivial_v<SandstoneApplication::SharedMemory>);
static_assert(std::is_trivially_copyable_v<SandstoneApplication::ExecState>);
static_assert(std::is_trivially_destructible_v<SandstoneApplication::ExecState>);

/* logging.cpp */
int get_monotonic_time_now(struct timespec *tv);
int logging_stdout_fd(void);
void logging_init_global(void);
void logging_init_global_child();
int logging_close_global(int exitcode);
void logging_print_log_file_name();
void logging_i18n(int level, const char *fmt, ...);
void logging_printf(int level, const char *msg, ...) ATTRIBUTE_PRINTF(2, 3);
void logging_mark_thread_failed(int thread_num);
void logging_report_mismatched_data(enum DataType type, const uint8_t *actual, const uint8_t *expected,
                                    size_t size, ptrdiff_t offset, const char *fmt, va_list);
void logging_print_header(int argc, char **argv, Duration test_duration, Duration test_timeout);
void logging_print_iteration_start();
void logging_print_footer();
void logging_print_triage_results(const std::vector<int> &sockets);
void logging_flush(void);
void logging_init(const struct test *test);
void logging_init_child_prefork(SandstoneApplication::ExecState *state);
void logging_init_child_preexec();
void logging_init_child_postexec(const SandstoneApplication::ExecState *state);
void logging_finish();
FILE *logging_stream_open(int thread_num, int level);
static inline void logging_stream_close(FILE *log)
{
    fputc(0, log);
}
TestResult logging_print_results(ChildExitStatus status, int *tc, const struct test *test);

/* random.cpp */
void random_global_init(const char *argument);
void random_advance_seed();
std::string random_format_seed();
void random_init();

/* sandstone.cpp */
TestResult run_one_test(int *tc, const struct test *test, SandstoneApplication::PerCpuFailures &per_cpu_fails);

/* stacksize.cpp */
#ifdef _WIN32
static inline void setup_stack_size(int, char **)
{
    // On Windows, we know the OS obeys the -Wl,--stack= argument
}
#else
void setup_stack_size(int argc, char **argv);
#endif

#endif

#if SANDSTONE_NO_LOGGING
#  define logging_printf(...)           __extension__({ if (false) logging_printf(__VA_ARGS__); })
#endif
#if !SANDSTONE_I18N_LOGGING
#  define logging_i18n(...)             (void)0
#endif

#endif /* INC_SANDSTONE_P_H */
