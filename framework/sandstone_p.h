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
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <random>
#include <span>
#include <vector>

#include <sandstone_config.h>
#include <sandstone_chrono.h>
#include <sandstone_iovec.h>
#include <sandstone_utils.h>

#include "effective_cpu_freq.hpp"
#include "gettid.h"
#include "topology.h"
#include "interrupt_monitor.hpp"
#include "thermal_monitor.hpp"
#include "frequency_manager.hpp"

#ifdef _WIN32
struct rusage
{
    struct timeval ru_utime, ru_stime;
    long long ru_maxrss;
    int ru_majflt;
};
#else
#  include <sys/resource.h>     // for struct rusage
#endif

#ifndef O_NOSIGPIPE
#  define O_NOSIGPIPE 0
#endif

extern "C" {
#endif

#define SANDSTONE_UNREACHABLE(msg)          ({ assert(false && msg); __builtin_unreachable(); })

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

struct test;

struct mmap_region
{
    void *base;
    size_t size;        /* actual size, not rounded up to page */
};

/*
 * Called from sandstone_main(). The default weak implementation performs no
 * checks, they just return. Feel free to implement a strong version elsewhere
 * if you prefer the framework to check for system or CPU criteria.
 */
void cpu_specific_init(void);

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
struct RandomEngineWrapper;
struct RandomEngineDeleter { void operator()(RandomEngineWrapper *) const; };

enum class TestResult : int8_t {
    Skipped = -1,
    Passed,
    Failed,
    Killed,
    CoreDumped,
    OperatingSystemError,
    OutOfMemory,
    TimedOut,
    Interrupted,
};

enum ThreadState : int {
    thread_not_started = 0,
    thread_running = 1,
    thread_failed = 2,
    thread_debugged = 3,
    thread_succeeded = -1,
    thread_skipped = -2,
};

struct ChildExitStatus
{
    TestResult result;

    // for TestKilled and TestCoreDumped, on Unix it's the signal number;
    // on Windows it's an NTSTATUS
    unsigned extra = 0;

    MonotonicTimePoint endtime = {};
    struct rusage usage = {};
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

namespace PerThreadData {
struct Common
{
    std::atomic<ThreadState> thread_state;

    /* file descriptor for logging */
    int log_fd;

    /* Records number of messages logged per thread of each test */
    std::atomic<int> messages_logged;

    /* Records the number of bytes log_data'ed per thread */
    std::atomic<unsigned> data_bytes_logged;

    MonotonicTimePoint fail_time;
    bool has_failed() const
    {
        return fail_time < MonotonicTimePoint::max();
    }

    void init()
    {
        thread_state.store(thread_not_started, std::memory_order_relaxed);
        fail_time = MonotonicTimePoint::max();
        messages_logged.store(0, std::memory_order_relaxed);
        data_bytes_logged.store(0, std::memory_order_relaxed);
    }
};

struct alignas(64) Main : Common
{
    CpuRange cpu_range;
};

struct alignas(64) Test : Common
{
    /* Number of iterations of the inner loop (aka #times test_time_condition called) */
    uint64_t inner_loop_count;
    uint64_t inner_loop_count_at_fail;

    /* Thread's effective CPU frequency during execution */
    double effective_freq_mhz;

    /* Thread ID */
    std::atomic<tid_t> tid;

    void init()
    {
        Common::init();
        inner_loop_count = inner_loop_count_at_fail = 0;
        effective_freq_mhz = 0.0;
    }
};
} // namespace PerThreadData

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

namespace SandstoneBackgroundScanConstants {
static constexpr Duration MinimumDelayBetweenTests = std::chrono::minutes(5);
static constexpr Duration DelayBetweenTestBatch = std::chrono::hours(24);
static constexpr Duration MaximumDelayBetweenTests = (DelayBetweenTestBatch / 2);
}

struct SandstoneBackgroundScan
{
    std::span<MonotonicTimePoint> timestamp;
    float load_idle_threshold = 0.0;

#ifdef _WIN32
    static constexpr float load_idle_threshold_init = 0.35;
    static constexpr float load_idle_threshold_inc_val = 0.05;
    static constexpr float load_idle_threshold_max = 1.0;
#else
    static constexpr float load_idle_threshold_init = 0.2;
    static constexpr float load_idle_threshold_inc_val = 0.05;
    static constexpr float load_idle_threshold_max = 0.8;
#endif
};

class DeviceSchedule {
public:
    virtual void reschedule_to_next_device() = 0;
    virtual void finish_reschedule() = 0;
    virtual ~DeviceSchedule() = default;
protected:
    void pin_to_next_cpu(int next_cpu, tid_t thread_id=0)
    {
        if (!pin_thread_to_logical_processor(LogicalProcessor(next_cpu), thread_id)) {
            log_warning("Failed to reschedule %d (%tu) to CPU %d", thread_num, (uintptr_t)pthread_self(), next_cpu);
        }
    }
};

struct SandstoneApplication : public InterruptMonitor, public test_the_test_data<SandstoneConfig::Debug>
{
    enum class OutputFormat : int8_t {
        no_output   = 0,
        tap,
        key_value,
        yaml,
    };
    static constexpr auto DefaultOutputFormat = SANDSTONE_DEFAULT_LOGGING;

    enum ForkMode : int8_t {
        no_fork,
        fork_each_test,
        exec_each_test,
        child_exec_each_test,       // when parent is exec_each_test
    };

    struct SlicePlans {
        static constexpr int MinimumCpusPerSocket = 8;
        static constexpr int DefaultMaxCoresPerSlice = 32;
        static constexpr int SecondaryMaxCoresPerSlice = DefaultMaxCoresPerSlice * 3 / 4;
        enum Type : int8_t {
            FullSystem = -1,
            IsolateSockets,
            Heuristic,
        };
        using Slices = std::vector<CpuRange>;
        std::array<Slices, 2> plans;
    };

    using PerCpuFailures = std::vector<__uint128_t>;
    struct SharedMemory;

    SlicePlans slice_plans;
    std::vector<test_data_per_thread> user_thread_data;
    PerThreadData::Main *main_thread_data_ptr;  // points to somewhere in the shmem
    PerThreadData::Test *test_thread_data_ptr;  // points to somewhere in the shmem
    SharedMemory *shmem = nullptr;
    int shmemfd = -1;

    static constexpr int DefaultQualityLevel = int(TEST_QUALITY_PROD);
    int requested_quality = DefaultQualityLevel;
    std::string file_log_path;
    const char *syslog_ident = nullptr;

    bool fatal_skips = false;

    ForkMode fork_mode =
#ifdef _WIN32
            exec_each_test;
#else
            fork_each_test;
#endif
    bool ignore_mce_errors = false;
    bool ignore_os_errors = false;
    bool force_test_time = false;
    bool service_background_scan = false;
    bool vary_frequency_mode = false;
    bool vary_uncore_frequency_mode = false;
    int inject_idle = 0;
    static constexpr int MaxRetestCount = sizeof(PerCpuFailures::value_type) * 8;
    int retest_count = 10;
    int total_retest_count = -2;
    int max_test_count = INT_MAX;
    int max_test_loop_count = 0;
    int current_iteration_count;        // iterations of the same test (positive for fracture; negative for retest)
    int current_test_count;
    MonotonicTimePoint starttime = MonotonicTimePoint::clock::now();
    MonotonicTimePoint endtime;
    MonotonicTimePoint current_test_starttime;
    static constexpr auto DefaultTestDuration = std::chrono::seconds(1);
    ShortDuration current_test_duration;
    ShortDuration test_time = {};
    ShortDuration max_test_time = {};
    ShortDuration delay_between_tests = std::chrono::milliseconds(5);

    std::unique_ptr<RandomEngineWrapper, RandomEngineDeleter> random_engine;
    std::unique_ptr<FrequencyManager> frequency_manager;

#ifndef __linux__
    std::string path_to_self;
#endif
#ifdef NDEBUG
    static constexpr struct {
        size_t size() const { return 0; }
        char *c_str() const { return nullptr; }
    } gdb_server_comm = {};
#else
    std::string gdb_server_comm;
#endif

    static constexpr int DefaultTemperatureThreshold = -1;
    int thermal_throttle_temp = DefaultTemperatureThreshold;
    int threshold_time_remaining = 30000;
    int mce_check_period = 0;
    uint64_t last_thermal_event_count;
    uint64_t mce_count_last;
    std::vector<uint32_t> mce_counts_start;
    std::vector<uint64_t> smi_counts_start;

    int thread_count;
    ForkMode current_fork_mode() const
    {
#ifndef _WIN32
        if (SandstoneConfig::RestrictedCommandLine) {
            return SandstoneApplication::fork_each_test;
        }
#endif
        return fork_mode;
    }

    bool is_main_process();
    [[maybe_unused]] bool is_child_process() { return !is_main_process(); }

    PerThreadData::Common *thread_data(int thread);
    PerThreadData::Main *main_thread_data(int slice = 0) noexcept;
    PerThreadData::Test *test_thread_data(int thread);
    void select_main_thread(int slice);

    SandstoneBackgroundScan background_scan;

    std::unique_ptr<DeviceSchedule> device_schedule = nullptr;

private:
    SandstoneApplication() = default;
    ~SandstoneApplication() = delete;
    SandstoneApplication(const SandstoneApplication &) = delete;
    SandstoneApplication &operator=(const SandstoneApplication &) = delete;
    friend int internal_main(int argc, char **argv);
    friend int main(int argc, char **argv);
    friend SandstoneApplication *_sApp() noexcept;
};

struct SandstoneApplication::SharedMemory
{
    // state shared with child processes (input only)
    ptrdiff_t thread_data_offset = 0;

    // test execution
    MonotonicTimePoint current_test_endtime = {};
    int current_max_loop_count = 0;
    std::chrono::duration<int, std::micro> current_test_sleep_duration = {};
    bool selftest = false;
    bool ud_on_failure = false;
    bool use_strict_runtime = false;

    // logging parameters
    int verbosity = -1;
    int max_messages_per_thread = 5;
    unsigned max_logdata_per_thread = 128;
    OutputFormat output_format = DefaultOutputFormat;
    uint8_t output_yaml_indent = 0;
    bool log_test_knobs = false;

    // child debugging
#ifdef _WIN32
    intptr_t debug_event = 0;
    intptr_t child_debug_socket = -1;
#else
    int server_debug_socket = -1;
    int child_debug_socket = -1;
#endif

    // general parameters
    pid_t main_process_pid = 0;

    // per-thread & variable length
    int main_thread_count = 0;
    int total_cpu_count = 0;
    alignas(64) struct cpu_info cpu_info[];         // C99 Flexible Array Member

#if 0
    // in/out per-thread data allocated dynamically;
    // layout is:
    alignas(PAGE_SIZE)
    PerThreadData::Main main_thread_data[main_thread_count];
    PerThreadData::Test per_thread[total_cpu_count];
#endif
};

inline SandstoneApplication *_sApp() noexcept
{
    using App = std::aligned_storage_t<sizeof(SandstoneApplication), alignof(SandstoneApplication)>;
    static App app;
    return reinterpret_cast<SandstoneApplication *>(&app);
}

#define sApp    _sApp()

inline bool SandstoneApplication::is_main_process()
{
    return getpid() == shmem->main_process_pid;
}

inline PerThreadData::Common *SandstoneApplication::thread_data(int thread)
{
    if (thread < 0)
        return main_thread_data(-thread - 1);
    return test_thread_data(thread);
}

inline PerThreadData::Main *SandstoneApplication::main_thread_data(int slice) noexcept
{
    assert(slice == 0 || is_main_process());
    return &main_thread_data_ptr[slice];
}

inline PerThreadData::Test *SandstoneApplication::test_thread_data(int thread)
{
    assert(thread >= 0);
    assert(thread < sApp->thread_count);
    return &test_thread_data_ptr[thread];
}

inline void SandstoneApplication::select_main_thread(int slice)
{
    assert(current_fork_mode() != no_fork || slice == 0);
    main_thread_data_ptr += slice;
    test_thread_data_ptr += main_thread_data_ptr->cpu_range.starting_cpu;
}

template <typename Lambda> static void for_each_main_thread(Lambda &&l, int max_slices = INT_MAX)
{
    int count = sApp->is_main_process() ? std::min(sApp->shmem->main_thread_count, max_slices) : 1;
    for (int i = 0; i < count; i++)
        l(sApp->main_thread_data(i), -1 - i);
}

template <typename Lambda> static void for_each_test_thread(Lambda &&l)
{
    for (int i = 0; i < num_cpus(); i++)
        l(sApp->test_thread_data(i), i);
}

struct Pipe
{
    enum DontCreateFlag { DontCreate };
    int fds[2] =                { -1, -1 };
    int &in()                   { return fds[0]; }
    int &out()                  { return fds[1]; }
    void close_input()          { do_close(in()); }
    void close_output()         { do_close(out()); }
    explicit operator bool()    { return in() != -1 || out() != -1; }

    Pipe()                      { open(); }
    Pipe(DontCreateFlag)        { }
    ~Pipe()                     { close_input(); close_output(); }
    Pipe(const Pipe &) = delete;
    Pipe &operator=(const Pipe &) = delete;
    Pipe(Pipe &&other)
    {
        fds[0] = other.fds[0];
        fds[1] = other.fds[1];
        other.fds[0] = other.fds[1] = -1;
    }
    Pipe &operator=(Pipe &&other)
    {
        close_input();
        close_output();
        fds[0] = other.fds[0];
        fds[1] = other.fds[1];
        other.fds[0] = other.fds[1] = -1;
        return *this;
    }

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

template <typename F> inline auto scopeExit(F &&f)
{
    struct Scope {
        F f;
        bool dismissed = false;
        Scope(F &&f) : f(std::move(f)) {}
        Scope(const Scope &) = delete;
        Scope(Scope &&) = default;
        Scope &operator=(const Scope &) = delete;
        Scope &operator=(Scope &&) = delete;
        ~Scope() { if (!dismissed) f(); }
        void dismiss() { dismissed = true; }
        void run_now() { f(); dismiss(); }
    };
    return Scope{ std::forward<F>(f) };
}

static_assert(std::is_trivially_copyable_v<SandstoneApplication::SharedMemory>);
static_assert(std::is_trivially_destructible_v<SandstoneApplication::SharedMemory>);

/* child_debug.cpp */
void debug_init_child(void);
void debug_init_global(const char *on_hang_arg, const char *on_crash_arg);
void debug_crashed_child(std::span<const pid_t> children);
void debug_hung_child(pid_t child, std::span<const pid_t> children);

/* logging.cpp */
void log_message_preformatted(int thread_num, int level, std::string_view msg);
int logging_stdout_fd(void);
void logging_init_global(void);
void logging_init_global_child();
int logging_close_global(int exitcode);
void logging_print_log_file_name();
void logging_restricted(int level, const char *fmt, ...);
void logging_printf(int level, const char *msg, ...) ATTRIBUTE_PRINTF(2, 3);
void logging_mark_thread_failed(int thread_num);
void logging_report_mismatched_data(enum DataType type, const uint8_t *actual, const uint8_t *expected,
                                    size_t size, ptrdiff_t offset, const char *fmt, va_list);
void logging_print_header(int argc, char **argv, ShortDuration test_duration, ShortDuration test_timeout);
void logging_print_iteration_start();
void logging_print_footer();
void logging_print_version(void);
void logging_flush(void);
void logging_init(const struct test *test);
void logging_init_child_preexec();
void logging_finish();
TestResult logging_print_results(std::span<const ChildExitStatus> status, const struct test *test);

/* random.cpp */
void random_init_global(const char *argument);
void random_advance_seed();
std::string random_format_seed();
void random_init_thread(int thread_num);

/* sandstone.cpp */
TestResult run_one_test(int *tc, const struct test *test, SandstoneApplication::PerCpuFailures &per_cpu_fails);

/*
 * Called from sandstone_main() before logging_global_init() and before
 * logging_global_finish(). Feel free to add your own banner or footer. Be
 * careful about corrupting the log output.
 */
void print_application_banner();
int print_application_footer(int exit_code, SandstoneApplication::PerCpuFailures per_cpu_failures);

#endif

#if SANDSTONE_NO_LOGGING
#  define logging_printf(...)           __extension__({ if (false) logging_printf(__VA_ARGS__); })
#else
#  define logging_restricted(...)  (void)0
#endif

#endif /* INC_SANDSTONE_P_H */
