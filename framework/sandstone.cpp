/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Output is in "Test Anything Protocol" format, as per http://testanything.org/tap-specification.html
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <algorithm>
#include <chrono>
#include <iterator>
#include <new>
#include <map>
#include <numeric>
#include <utility>
#include <vector>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#if __has_include(<malloc.h>)
#  include <malloc.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#ifdef __unix__
#  include <poll.h>
#endif
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#if __has_include(<sys/auxv.h>)         // FreeBSD and Linux
#  include <sys/auxv.h>
#endif
#ifdef __linux__
#  include <sys/eventfd.h>
#  include <sys/prctl.h>
#  include <sys/types.h>
#endif
#ifdef __unix__
#  include <sys/resource.h>
#endif
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cpu_features.h"
#include "forkfd.h"
#include "futex.h"

#include "sandstone.h"
#include "sandstone_p.h"
#include "sandstone_iovec.h"
#include "sandstone_kvm.h"
#include "sandstone_system.h"
#include "sandstone_thread.h"
#include "sandstone_tests.h"
#include "sandstone_utils.h"
#include "topology.h"

#if SANDSTONE_SSL_BUILD
#  include "sandstone_ssl.h"
#  include "sandstone_ssl_rand.h"
#endif

#ifdef _WIN32
#  include <ntstatus.h>
#  include <shlwapi.h>
#  include <windows.h>
#  include <psapi.h>
#  include <pdh.h>

#  ifdef ftruncate
// MinGW's ftruncate64 tries to check free disk space and that fails on Wine,
// so use the the 32-bit offset version (which calls _chsize)
#    undef ftruncate
#  endif
#endif

#include "sandstone_test_lists.h"

#ifndef O_PATH
#  define O_PATH        0
#endif
#ifndef O_CLOEXEC
#  define O_CLOEXEC     0
#endif
#ifndef S_IRWXU
#  define S_IRWXU       0700
#endif

#if !defined(__GLIBC__) && !defined(fileno_unlocked)
#  define fileno_unlocked   fileno
#endif

using namespace std;
using namespace std::chrono;

enum {
    invalid_option = 128,         /* not used, here just so the next option is non-zero */

    one_sec_option,
    thirty_sec_option,
    two_min_option,
    five_min_option,

    cpuset_option,
    cpujump_option,
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
    synchronize_threads_option,
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
};

using namespace std::chrono_literals;

#ifndef __GLIBC__
char *program_invocation_name;
#endif

uint64_t cpu_features;
static const struct test *current_test = nullptr;
#ifdef __llvm__
thread_local int thread_num __attribute__((tls_model("initial-exec")));
#else
thread_local int thread_num = 0;
#endif

static SandstoneTestSet *test_set;

static void find_thyself(char *argv0)
{
#ifndef __GLIBC__
    program_invocation_name = argv0;
#endif

#if defined(AT_EXECPATH)          // FreeBSD
    std::string &path = sApp->path_to_self;
    path.resize(PATH_MAX);
    if (elf_aux_info(AT_EXECPATH, &path[0], path.size()) == 0)
        path.resize(strlen(path.c_str()));
    else
        path.clear();
#endif
}

static const char *path_to_exe()
{
#if defined(__linux__)
    return "/proc/self/exe";
#elif defined(_WIN32)
    // see https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamea
    return _pgmptr;
#else
    return sApp->path_to_self.c_str();
#endif
}

static void perror_for_mmap(const char *msg)
{
#ifdef _WIN32
    win32_perror(msg);
#else
    perror(msg);
#endif
}

static int open_runtime_file_internal(const char *name, int flags, int mode)
{
    assert(strchr(name, '/') == nullptr);
#ifdef __unix__
    static int dfd = []() {
        uid_t uid = getuid();
        if (uid != geteuid())
            return -1;              // don't trust the environment if setuid

        // open the directory pointed by $RUNTIME_DIRECTORY (see
        // systemd.exec(5)) and confirm it belongs to us
        const char *runtime_directory = getenv("RUNTIME_DIRECTORY");
        if (!runtime_directory || !runtime_directory[0])
            return -1;
        if (runtime_directory[0] != '/') {
            fprintf(stderr, "%s: $RUNTIME_DIRECTORY is not an absolute path; ignoring.\n",
                    program_invocation_name);
            return -1;
        }

        int dfd = open(runtime_directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd < 0)
            return dfd;

        // confirm its ownership
        struct stat st;
        if (fstat(dfd, &st) == 0) {
            if (st.st_uid == uid && S_ISDIR(st.st_mode) && (st.st_mode & ACCESSPERMS) == S_IRWXU)
                return dfd;
        }
        close(dfd);
        return -1;
    }();
    if (dfd < 0)
        return -1;

    // open the file
    flags|= O_CLOEXEC;
    return openat(dfd, name, flags, mode);
#else
    (void) name;
    (void) flags;
    (void) mode;
    return -1;
#endif
}

static int create_runtime_file(const char *name, int mode = S_IRWXU)
{
    return open_runtime_file_internal(name, O_CREAT | O_RDWR, mode);
}

static int test_result_to_exit_code(TestResult result)
{
    switch (result) {
    case TestResult::Passed:
        break;
    case TestResult::Skipped:
        return -1;
    case TestResult::Failed:
        return EXIT_FAILURE;
    case TestResult::OperatingSystemError:
    case TestResult::Killed:
    case TestResult::CoreDumped:
    case TestResult::OutOfMemory:
    case TestResult::TimedOut:
    case TestResult::Interrupted:
        assert(false && "Tests don't produce these conditions themselves");
        __builtin_unreachable();
    }
    return EXIT_SUCCESS;
}

#ifndef _WIN32
static ChildExitStatus test_result_from_exit_code(forkfd_info info)
{
    ChildExitStatus r = {};
    r.extra = info.status;
    if (info.code == CLD_EXITED) {
        // normal exit
        int8_t status = info.status;    // the cast to int8_t transforms 255 into -1
        switch (status) {
        case -1:
            r.result = TestResult::Skipped;
            r.extra = 0;
            break;
        case EXIT_SUCCESS:
            r.result = TestResult::Passed;
            r.extra = 0;
            break;
        case EXIT_FAILURE:
            r.result = TestResult::Failed;
            r.extra = 0;
            break;
        default:
            // a FW problem getting started
            r.result = TestResult::OperatingSystemError;
            break;
        }
    } else if (info.code == CLD_KILLED || info.code == CLD_DUMPED) {
        r.result = info.code == CLD_KILLED ? TestResult::Killed : TestResult::CoreDumped;
        if (info.status == SIGKILL)
            r.result = TestResult::OutOfMemory;
        else if (info.status == SIGQUIT)
            r.result = TestResult::TimedOut;
    } else {
        assert(false && "Impossible condition; did we get a CLD_STOPPED??");
        __builtin_unreachable();
    }
    return r;
}
#else
static constexpr DWORD EXIT_TIMEOUT = 2;
static ChildExitStatus test_result_from_exit_code(DWORD status)
{
    // Exit code mapping:
    // -1: EXIT_SKIP:       TestResult::Skipped
    // 0: EXIT_SUCCESS:     TestResult::Passed
    // 1: EXIT_FAILURE:     TestResult::Failed
    // 2:                   TestResult::TimedOut
    // 3:                   Special case for abort()
    // 4-255:               exit() code (from sysexits.h)
    // anything else:       an NTSTATUS
    //
    // https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/abort?view=msvc-160
    // says: "If the Windows error reporting handler is not invoked, then abort
    // calls _exit to terminate the process with exit code 3"

    switch (status) {
    case DWORD(-1):
        return { TestResult::Skipped };
    case EXIT_SUCCESS:
        return { TestResult::Passed };
    case EXIT_FAILURE:
        return { TestResult::Failed };
    case EXIT_TIMEOUT:
        return { TestResult::TimedOut };
    case 3:
        return { TestResult::Killed, unsigned(STATUS_FAIL_FAST_EXCEPTION) };
    }
    if (status > 255)
        return { TestResult::Killed, status };

    // must be a FW problem getting started
    return { TestResult::OperatingSystemError, status };
}
#endif // _WIN32

static inline __attribute__((always_inline, noreturn)) void ud2()
{
    __builtin_trap();
    __builtin_unreachable();
}

static void __attribute__((noreturn)) report_fail_common()
{
    logging_mark_thread_failed(thread_num);
#ifdef _WIN32
    /* does not call the cleanup handlers */
    _endthread();
#else
    /* does call the cleanup handalers */
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, nullptr);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, nullptr);
    pthread_cancel(pthread_self());
#endif
    __builtin_unreachable();
}

void _report_fail(const struct test *test, const char *file, int line)
{
    /* Keep this very early */
    if (sApp->shmem->ud_on_failure)
        ud2();

    if (!SandstoneConfig::NoLogging)
        log_error("Failed at %s:%d", file, line);
    report_fail_common();
}

void _report_fail_msg(const char *file, int line, const char *fmt, ...)
{
    /* Keep this very early */
    if (sApp->shmem->ud_on_failure)
        ud2();

    if (!SandstoneConfig::NoLogging)
        log_error("Failed at %s:%d: %s", file, line, va_start_and_stdprintf(fmt).c_str());
    report_fail_common();
}

/* Like memcmp(), but returns the offset of the byte that differed (negative if equal) */
static ptrdiff_t memcmp_offset(const uint8_t *d1, const uint8_t *d2, size_t size)
{
    ptrdiff_t i = 0;

    for (; i < (ptrdiff_t) size; ++i) {
        if (d1[i] != d2[i])
            return i;
    }
    return -1;
}

void _memcmp_fail_report(const void *_actual, const void *_expected, size_t size, DataType type, const char *fmt, ...)
{
    // Execute UD2 early if we've failed
    if (sApp->shmem->ud_on_failure)
        ud2();

    if (!SandstoneConfig::NoLogging) {
        if (fmt)
            assert(strchr(fmt, '\n') == nullptr && "Data descriptions should not include a newline");

        auto actual = static_cast<const uint8_t *>(_actual);
        auto expected = static_cast<const uint8_t *>(_expected);
        ptrdiff_t offset = memcmp_offset(actual, expected, size);

        va_list va;
        va_start(va, fmt);
        logging_report_mismatched_data(type, actual, expected, size, offset, fmt, va);
        va_end(va);
    }

    report_fail_common();
}

static bool shouldTestTheTest(const struct test *the_test)
{
    if (!sApp->test_tests_enabled())
        return false;
    if constexpr (InterruptMonitor::InterruptMonitorWorks)
        if (the_test == &mce_test)
            return false;

    // check some flags in the_test
    return true;
}

inline void test_the_test_data<true>::test_tests_init(const struct test *the_test)
{
    if (!shouldTestTheTest(the_test))
        return;

    hwm_at_start = memfpt_current_high_water_mark();
    per_thread.resize(num_cpus());
    std::fill_n(per_thread.begin(), num_cpus(), PerThread{});
}

inline void test_the_test_data<true>::test_tests_iteration(const struct test *the_test)
{
    if (!shouldTestTheTest(the_test))
        return;

    int cpu = thread_num;
    int n = sApp->test_thread_data(cpu)->inner_loop_count;
    if (n >= DesiredIterations)
        return;

    auto &me = per_thread[cpu];
    me.iteration_times[n] = std::chrono::steady_clock::now();
}

inline void test_the_test_data<true>::test_tests_finish(const struct test *the_test)
{
    // implemented as a macro because GCC can't inline variadic functions
#define maybe_log_error(flag, ...) ({                       \
        std::string msg = stdprintf(__VA_ARGS__);           \
        if (the_test->flags & flag)                         \
            log_message(-1, SANDSTONE_LOG_WARNING "%s", msg.c_str()); \
        else                                                \
            log_message(-1, SANDSTONE_LOG_ERROR "%s", msg.c_str());   \
    })

    using namespace std::chrono;
    if (!shouldTestTheTest(the_test))
        return;

    MonotonicTimePoint now = std::chrono::steady_clock::now();

    size_t current_hwm = memfpt_current_high_water_mark();
    if ((current_hwm == 0) != (hwm_at_start == 0) || current_hwm < hwm_at_start) {
        log_warning("High water mark memory footprinting failed (%zu kB at start, %zu kB now)",
                    hwm_at_start, current_hwm);
    } else if (current_hwm) {
        size_t per_thread_avg = (current_hwm - hwm_at_start) / num_cpus();
        if (per_thread_avg < MaxAcceptableMemoryUseKB)
            log_info("Test memory use: (%zu - %zu) / %d = %zu kB",
                     current_hwm, hwm_at_start, num_cpus(), per_thread_avg);
        else
            maybe_log_error(test_flag_ignore_memory_use,
                            "Test uses too much memory: (%zu - %zu) / %d = %zu kB",
                            current_hwm, hwm_at_start, num_cpus(), per_thread_avg);
    }

    // check if the test has failed
    bool has_failed = false;
    auto failchecker = [&has_failed](PerThreadData::Common *data, int) {
        if (data->has_failed())
            has_failed = true;
    };
    for_each_main_thread(failchecker);
    if (!has_failed)
        for_each_test_thread(failchecker);
    if (has_failed)
        return;                     // no point in reporting timing of failed tests

    // check the overall time
    if (sApp->shmem->current_test_endtime != MonotonicTimePoint::max() && the_test->desired_duration >= 0) {
        Duration expected_runtime = sApp->shmem->current_test_endtime - sApp->current_test_starttime;
        Duration min_expected_runtime = expected_runtime - expected_runtime / 4;
        Duration max_expected_runtime = expected_runtime + expected_runtime / 4;
        Duration actual_runtime = now - sApp->current_test_starttime;
        Duration difference = abs(expected_runtime - actual_runtime);

        if ((actual_runtime > min_expected_runtime && actual_runtime < max_expected_runtime)
                || difference < OverallTestTimeIgnore) {
            // Acceptable timing
            log_info("Overall time: %s", format_duration(actual_runtime).c_str());
        } else if (actual_runtime > max_expected_runtime) {
            maybe_log_error(test_flag_ignore_test_overtime,
                            "Test ran for longer than expected: %s (desired %s, max %s)",
                            format_duration(actual_runtime).c_str(), format_duration(expected_runtime).c_str(),
                            format_duration(max_expected_runtime).c_str());
        } else  {
            maybe_log_error(test_flag_ignore_test_undertime,
                            "Test ran shorter than expected: %s (desired %s, min %s)",
                            format_duration(actual_runtime).c_str(), format_duration(expected_runtime).c_str(),
                            format_duration(min_expected_runtime).c_str());
        }

        // check the timings in each thread
        Duration average = {};
        int average_counts = 0;
        int while_loops = 0;
        for (int cpu = 0; cpu < num_cpus(); ++cpu) {
            PerThread &thr = per_thread[cpu];
            if (thr.iteration_times[0].time_since_epoch().count() == 0)
                continue;

            std::array<Duration, DesiredIterations> iteration_times = {};
            iteration_times[0] = thr.iteration_times[0] - sApp->current_test_starttime;
            int n = 0;
            for (int i = 1; i < DesiredIterations; ++i) {
                if (thr.iteration_times[i].time_since_epoch().count() == 0)
                    break;
                ++n;
                iteration_times[n] = thr.iteration_times[i] - thr.iteration_times[i - 1];
            }

            if (n) {
                Duration this_average = (thr.iteration_times[n] - thr.iteration_times[0]) / n;
                average += this_average;
                if (iteration_times[0] < 1ms && iteration_times[0] * 4 < this_average)
                    ++while_loops;
            } else {
                average += iteration_times[0];
            }
            ++average_counts;

            log_message(cpu, SANDSTONE_LOG_DEBUG "Sampled iteration timings: %s, %s, %s, %s",
                        format_duration(iteration_times[0]).c_str(),
                        format_duration(iteration_times[1]).c_str(),
                        format_duration(iteration_times[2]).c_str(),
                        format_duration(iteration_times[3]).c_str());
        }

        if (average_counts == 0) {
            log_error("run() function did not call test_time_condition() in any thread");
        } else {
            if (while_loops)
                maybe_log_error(test_flag_ignore_do_while,
                                "run() function appears to use while (test_time_condition()) instead of do {} while");

            // find the threads where test_time_condition() wasn't called
            for (int cpu = 0; average_counts != num_cpus() && cpu < num_cpus(); ++cpu) {
                PerThread &thr = per_thread[cpu];
                if (thr.iteration_times[0].time_since_epoch().count() == 0)
                    log_message(cpu, SANDSTONE_LOG_WARNING "run() function did not call test_time_condition() in this thread");
            }

            average /= average_counts;
            if (average < 1us) {
                // avoid division by zero
                maybe_log_error(test_flag_ignore_loop_timing,
                                "Inner loop is FAR too short, couldn't even get accurate timings");
            } else if (average < MinimumLoopDuration) {
                maybe_log_error(test_flag_ignore_loop_timing,
                                "Inner loop is too short (average %s) -- suggest making the test %" PRId64 "x longer",
                                format_duration(average).c_str(), TargetLoopDuration.count() / average.count());
            } else if (average > MaximumLoopDuration) {
                maybe_log_error(test_flag_ignore_loop_timing,
                                "Inner loop is too long (average %s) -- suggest making the test %" PRId64 "x shorter",
                                format_duration(average).c_str(), average.count() / TargetLoopDuration.count());
            } else {
                log_info("Inner loop average duration: %s", format_duration(average).c_str());
            }
        }
    }

#undef maybe_log_error
}

namespace {
class BarrierThreadSynchronization : public SandstoneThreadSynchronizationBase
{
public:
    struct alignas(64) AlignedAtomicInt : std::atomic_int {
        using std::atomic_int::atomic;
    };

    void init() noexcept override;
    void synchronize() noexcept override { do_sync(); }
    virtual void do_wait(std::atomic_int &, int) noexcept;
    virtual void do_wake(std::atomic_int &) noexcept;
    void do_sync() noexcept;

    std::array<AlignedAtomicInt, 2> phases;
    AlignedAtomicInt phase_idx = 0;
};

void BarrierThreadSynchronization::init() noexcept
{
    phases[0].store(num_cpus(), std::memory_order_relaxed);
    phases[1].store(INT_MAX, std::memory_order_relaxed);
    phase_idx.store(0, std::memory_order_relaxed);
}

void BarrierThreadSynchronization::do_sync() noexcept
{
    int idx = phase_idx.load(std::memory_order_relaxed);
    auto &phase = phases[idx];

    // are we the last to arrive?
    int remaining = phase.fetch_add(-1, std::memory_order_relaxed) - 1;
    assert(remaining >= 0);
    assert(remaining < num_cpus());
    if (remaining > 0) {
        // not the last, so wait
        return do_wait(phase, remaining);
    }

    // yes, set up the next phase
    idx ^= 1;
    phases[idx].store(num_cpus(), std::memory_order_relaxed);
    phase_idx.store(idx, std::memory_order_relaxed);
    do_wake(phase);
}

void BarrierThreadSynchronization::do_wait(std::atomic_int &phase, int) noexcept
{
    while (phase.load(std::memory_order_relaxed) >= 0) {
        // no pause
    }
}

void BarrierThreadSynchronization::do_wake(std::atomic_int &phase) noexcept
{
    // release the other threads
    phase.store(-1, std::memory_order_relaxed);
}

class FutexThreadSynchronization : public BarrierThreadSynchronization
{
public:
    void do_wait(std::atomic_int &phase, int remaining) noexcept override;
    void do_wake(std::atomic_int &phase) noexcept override;
};

void FutexThreadSynchronization::do_wait(std::atomic_int &phase, int remaining) noexcept
{
    while (futex_wait(&phase, remaining) != 0) {
        remaining = phase.load(std::memory_order_relaxed);
        if (remaining < 0)
            return;
    }
}

void FutexThreadSynchronization::do_wake(std::atomic_int &phase) noexcept
{
    BarrierThreadSynchronization::do_wake(phase);
    futex_wake_all(&phase);
}

#ifdef __x86_64__
#pragma GCC push_options
#pragma GCC target("waitpkg")

static constexpr int WaitpkgWaitState = 1;       // C0.1
void check_waitpkg()
{
    if (cpu_has_feature(cpu_feature_waitpkg)) {
        // test that the OS has enabled this
        uint64_t current_tsc = __rdtsc();
        if (_tpause(WaitpkgWaitState, current_tsc + 1) == 0)
            return;
    }

    fprintf(stderr, "%s: waitpkg is not supported on this CPU or this OS.\n",
            program_invocation_name);
    exit(EX_OSERR);
}

class TPauseThreadSynchronization : public BarrierThreadSynchronization
{
public:
    TPauseThreadSynchronization() { check_waitpkg(); }
    void do_wait(std::atomic_int &phase, int remaining) noexcept override;
    void do_wake(std::atomic_int &phase) noexcept override;

    std::atomic<uint64_t> tsc;
};

void TPauseThreadSynchronization::do_wait(std::atomic_int &phase, int remaining) noexcept
{
    BarrierThreadSynchronization::do_wait(phase, remaining);
    _tpause(WaitpkgWaitState, tsc.load(std::memory_order_relaxed));
}

void TPauseThreadSynchronization::do_wake(std::atomic_int &phase) noexcept
{
    uint64_t target_tsc = __rdtsc() + 16;
    tsc.store(target_tsc, std::memory_order_relaxed);
    BarrierThreadSynchronization::do_wake(phase);
    _tpause(WaitpkgWaitState, target_tsc);
}

class UMWaitThreadSynchronization : public BarrierThreadSynchronization
{
public:
    UMWaitThreadSynchronization() { check_waitpkg(); }
    void do_wait(std::atomic_int &phase, int remaining) noexcept override;
};

void UMWaitThreadSynchronization::do_wait(std::atomic_int &phase, int remaining) noexcept
{
    _umonitor(&phase);      // arm the monitor first
    if (phase.load(std::memory_order_relaxed) < 0)
        return;
    _umwait(WaitpkgWaitState, __rdtsc() + 128);
}

#pragma GCC pop_options
#endif
} // unnamed namespace

static ShortDuration test_duration()
{
    /* global (-t) option overrides this all */
    if (sApp->test_time > 0s)
        return sApp->test_time;
    return SandstoneApplication::DefaultTestDuration;
}

static ShortDuration test_duration(const test_cfg_info &test_cfg)
{
    const struct test *test = test_cfg.test;

    /* Start with the test prefered default time */
    ShortDuration target_duration(test->desired_duration);
    ShortDuration min_duration(test->minimum_duration);
    ShortDuration max_duration(test->maximum_duration);

    /* apply the global (-t) override */
    if (sApp->test_time.count())
        target_duration = sApp->test_time;

    /* apply the per-test time from the test list (overrides global -t) */
    if (test_cfg.duration.count())
        target_duration = test_cfg.duration;

    /* fallback to the default if test preference is zero */
    if (target_duration <= 0s)
        target_duration = SandstoneApplication::DefaultTestDuration;

    /* if --force-test-time specified, ignore the test-specified time limits */
    if (sApp->force_test_time)
        return target_duration;

    /* clip to the maximum duration */
    if (max_duration != 0s && target_duration > max_duration)
        target_duration = max_duration;
    /* and clip to the minimum duration */
    if (target_duration < min_duration)
        target_duration = min_duration;

    return target_duration;
}

static ShortDuration test_timeout(ShortDuration regular_duration)
{
    // use the override value if there is one
    if (sApp->max_test_time != Duration::zero())
        return sApp->max_test_time;

    ShortDuration result = regular_duration * 5 + 30s;
    if (result < 300s)
        result = 300s;

    return result;
}

static MonotonicTimePoint calculate_wallclock_deadline(Duration duration, MonotonicTimePoint *pnow = nullptr)
{
    MonotonicTimePoint later = MonotonicTimePoint::clock::now();
    if (pnow)
        *pnow = later;

    return later + duration;
}

static bool wallclock_deadline_has_expired(MonotonicTimePoint deadline)
{
    MonotonicTimePoint now = MonotonicTimePoint::clock::now();

    if (now > deadline)
        return true;
    if (sApp->shmem->use_strict_runtime && now > sApp->endtime)
        return true;
    return false;
}

static bool max_loop_count_exceeded(const struct test *the_test)
{
    PerThreadData::Test *data = sApp->test_thread_data(thread_num);

    // unsigned comparisons so sApp->current_max_loop_count == -1 causes an always false
    if (unsigned(data->inner_loop_count) >= unsigned(sApp->shmem->current_max_loop_count))
        return true;

    /* Desired duration -1 means "runs once" */
    if (the_test->desired_duration == -1)
        return true;
    return false;
}

extern "C" void test_loop_iterate() noexcept;    // see below

/* returns 1 if the test should keep running, useful for a while () loop */
#undef test_time_condition
bool test_time_condition() noexcept
{
    test_loop_iterate();
    sApp->test_tests_iteration(current_test);
    sApp->test_thread_data(thread_num)->inner_loop_count++;

    if (max_loop_count_exceeded(current_test))
        return 0;  // end the test if max loop count exceeded

    if (wallclock_deadline_has_expired(sApp->shmem->current_test_endtime))
        return 0;

    if (sApp->thread_synchronization)
        sApp->thread_synchronization->synchronize();
    return 1;
}

bool test_is_retry() noexcept
{
    // negative values indicate a retry
    return sApp->current_iteration_count < 0;
}

// Creates a string containing all socket temperatures like: "P0:30oC P2:45oC"
static string format_socket_temperature_string(const vector<int> & temps)
{
    string temp_string;
    for(int i=0; i<temps.size(); ++i){
        if (temps[i] != INVALID_TEMPERATURE){
            char buffer[64];
            sprintf(buffer, "P%d:%.1foC", i, temps[i]/1000.0);
            temp_string += string(buffer) + " ";
        }
    }
    return temp_string;
}

static void print_temperature_and_throttle()
{
    if (sApp->thermal_throttle_temp < 0)
        return;     // throttle disabled

    vector<int> temperatures = ThermalMonitor::get_all_socket_temperatures();

    if (temperatures.empty()) return; // Cant find temperature files at all (probably on windows)

    int highest_temp = *max_element(temperatures.begin(), temperatures.end());

    while ((highest_temp > sApp->thermal_throttle_temp) && sApp->threshold_time_remaining > 0) {

        if ((sApp->threshold_time_remaining % 1000) == 0) {
            logging_printf(LOG_LEVEL_VERBOSE(1),
                           "# CPU temperature (%.1foC) above threshold (%.1foC), throttling (%.1f s remaining)\n",
                           highest_temp / 1000.0, sApp->thermal_throttle_temp / 1000.0,
                           sApp->threshold_time_remaining / 1000.0);
            logging_printf(LOG_LEVEL_VERBOSE(1),
                    "# All CPU temperatures: %s\n", format_socket_temperature_string(temperatures).c_str());
        }

        const int throttle_ms = 100;
        usleep(throttle_ms * 1000);
        sApp->threshold_time_remaining -= throttle_ms;

        temperatures = ThermalMonitor::get_all_socket_temperatures();
        highest_temp = *max_element(temperatures.begin(), temperatures.end());
    }

    logging_printf(LOG_LEVEL_VERBOSE(1),
                   "# CPU temperatures: %s\n", format_socket_temperature_string(temperatures).c_str());
}

static void apply_group_inits(/*nonconst*/ struct test *test)
{
    // Create an array with the replacement functions per group and cache.
    // If the group_init function decides that the group cannot run at all, it
    // will return a pointer to a replacement function that will in turn cause
    // the test to fail or skip during test_init().

    std::span<const struct test_group> groups = { &__start_test_group, &__stop_test_group };
    static auto replacements = [=]() {
        struct Result {
            decltype(test_group::group_init) group_init;
            decltype(test_group::group_init()) replacement;
        };

        std::vector<Result> replacements(groups.size());
        size_t i = 0;
        for ( ; i < replacements.size(); ++i) {
            replacements[i].group_init = groups[i].group_init;
            replacements[i].replacement = nullptr;
        }
        return replacements;
    }();

    for (auto ptr = test->groups; *ptr; ++ptr) {
        for (size_t i = 0; i < groups.size(); ++i) {
            if (*ptr != &groups.begin()[i])
                continue;
            if (replacements[i].group_init && !replacements[i].replacement) {
                // call the group_init function, only once
                replacements[i].replacement = replacements[i].group_init();
                replacements[i].group_init = nullptr;
            }
            if (replacements[i].replacement) {
                test->test_init = replacements[i].replacement;
                return;
            }
        }
    }
}

void prepare_test(/*nonconst*/ struct test *test)
{
    if (test->test_preinit) {
        test->test_preinit(test);
        test->test_preinit = nullptr;   // don't rerun in case the test is re-added
    }
    if (test->groups)
        apply_group_inits(test);

#ifdef SANDSTONE
    if (test->flags & test_type_kvm) {
        if (!test->test_init) {
            test->test_init = kvm_generic_init;
            test->test_run = kvm_generic_run;
            test->test_cleanup = kvm_generic_cleanup;
        }
    }
#endif
}


static void init_internal(const struct test *test)
{
    print_temperature_and_throttle();

    logging_init(test);
}

static void init_per_thread_data()
{
    auto initer = [](auto *data, int) { data->init(); };
    for_each_main_thread(initer);
    for_each_test_thread(initer);
}

/* not static: used in tests/smi_count/smi_count.cpp */
void initialize_smi_counts()
{
    std::optional<uint64_t> v = sApp->count_smi_events(cpu_info[0].cpu_number);
    if (!v)
        return;
    sApp->smi_counts_start.resize(num_cpus());
    sApp->smi_counts_start[0] = *v;
    for (int i = 1; i < num_cpus(); i++)
        sApp->smi_counts_start[i] = sApp->count_smi_events(cpu_info[i].cpu_number).value_or(0);
}

static void cleanup_internal(const struct test *test)
{
    logging_finish();
}

static int cleanup_global(int exit_code, SandstoneApplication::PerCpuFailures per_cpu_failures)
{
    if (sApp->vary_frequency_mode)
        sApp->frequency_manager.restore_core_frequency_initial_state();

    if (sApp->vary_uncore_frequency_mode)
        sApp->frequency_manager.restore_uncore_frequency_initial_state();

    exit_code = print_application_footer(exit_code, std::move(per_cpu_failures));
    return logging_close_global(exit_code);
}

template <uint64_t X, uint64_t Y, typename P = int>
static void inline __attribute__((always_inline)) assembly_marker(P param = 0)
{
#ifdef __x86_64__
    __asm__("cmpxchg %%eax, %%eax"      // just an expensive no-op
            : : "D" (param), "a" (X), "d" (Y)
            : "cc");
#endif
}

namespace AssemblyMarker {
static constexpr uint64_t Test = 0x4e49414d54534554;        // "TESTMAIN"
static constexpr uint64_t TestLoop = 0x504f4f4c54534554;    // "TESTLOOP"
static constexpr uint32_t Start = 0x54525453;               // "STRT"
static constexpr uint64_t Iterate = 0x0045544152455449;     // "ITERATE\0"
static constexpr uint32_t End = 0x00444e45;                 // "END\0";
}

extern "C" {
// The test_start() and test_stop() functions are no-op, but exist to
// facilitate catching test starts and stops from external tools like the Intel
// SDE (-start_address test_start -stop_address test_end) and Valgrind
// (--toggle-collect=thread_runner).

static void __attribute__((noinline, noclone)) test_start()
{
    using namespace AssemblyMarker;
    assembly_marker<Test, Start>();
}

static void __attribute__((noinline, noclone, sysv_abi)) test_end(ThreadState state)
{
    using namespace AssemblyMarker;
    assembly_marker<Test, End>(state);
}

// This wrapper function is needed by emulation to be able to identify
// what the starting LIP to start execution on when they land on the emulator.
static __attribute__((noinline))
int test_run_wrapper_function(const struct test *test, int thread_number)
{
    return test->test_run(const_cast<struct test *>(test), thread_number);
}

#ifndef _WIN32
#  pragma GCC visibility push(hidden)
#endif

// Ditto for TEST_LOOP:
//     -start_address test_loop_start -stop_address test_loop_end
// OR: -start_address test_loop_start -stop_address test_loop_iterate
//
// Notes:
// - if the test fails, the functions following a report_fail() or
//   memcpy_or_fail() will not run
// - The test will run N loops of the content (see TEST_LOOP docs)
//   between calls of these functions

void test_loop_start() noexcept
{
#ifdef __x86_64__
    sApp->test_thread_data(thread_num)->last_tsc = __rdtsc();
#endif

    using namespace AssemblyMarker;
    assembly_marker<TestLoop, Start>();
}

void test_loop_iterate() noexcept
{
    using namespace AssemblyMarker;
    assembly_marker<TestLoop, Iterate>();
}

void test_loop_end() noexcept
{
    using namespace AssemblyMarker;
    assembly_marker<TestLoop, End>(sApp->test_thread_data(thread_num)->inner_loop_count);
}

#ifndef _WIN32
#  pragma GCC visibility pop
#endif
} // extern "C"

static uintptr_t thread_runner(int thread_number)
{
    // convert from internal Sandstone numbering to the system one
    pin_to_logical_processor(LogicalProcessor(cpu_info[thread_number].cpu_number), current_test->id);

    PerThreadData::Test *this_thread = sApp->test_thread_data(thread_number);
    random_init_thread(thread_number);
    int ret = EXIT_FAILURE;

    auto cleanup = scopeExit([&] {
        // let SIGQUIT handler know we're done
        ThreadState new_state = thread_failed;
        if (!this_thread->has_failed()) {
            if (ret == EXIT_SUCCESS)
                new_state = thread_succeeded;
            else if (ret < EXIT_SUCCESS)
                new_state = thread_skipped;
        }
        this_thread->thread_state.store(new_state, std::memory_order_relaxed);

        if (new_state == thread_failed) {
            if (sApp->shmem->ud_on_failure)
                ud2();
            logging_mark_thread_failed(thread_number);
        }
        test_end(new_state);
    });

    // indicate to SIGQUIT handler that we're running
    this_thread->thread_state.store(thread_running, std::memory_order_relaxed);

    CPUTimeFreqStamp before;
    before.Snapshot(thread_number);
    test_start();

    try {
        ret = test_run_wrapper_function(current_test, thread_number);
    } catch (std::exception &e) {
        log_error("Caught C++ exception: \"%s\" (type '%s')", e.what(), typeid(e).name());
        // no rethrow
    }

    cleanup.run_now();

    CPUTimeFreqStamp after;
    after.Snapshot(thread_number);
    this_thread->effective_freq_mhz = CPUTimeFreqStamp::EffectiveFrequencyMHz(before, after);

    if (sApp->shmem->verbosity >= 3)
        log_message(thread_number, SANDSTONE_LOG_INFO "inner loop count for thread %d = %" PRIu64 "\n",
                    thread_number, this_thread->inner_loop_count);


    // our caller doesn't care what we return, but the returned value helps if
    // you're running strace
    return ret;
}

int num_cpus()
{
    return sApp->thread_count;
}

int num_packages() {
    return Topology::topology().packages.size();
}

void checkpoint(int thread_idx) {
    // Checks if cpujump enable, but for now do nothing.
    if ( sApp->cpujump ) {

        CPUJump *cpujump_info = sApp->cpujump_vec[thread_idx];
        log_warning("Thread %d is waiting on barrier", thread_idx);
        pthread_barrier_wait(cpujump_info->barrier);

        // Jump to next cpu
        pin_to_logical_processor(LogicalProcessor(cpujump_info->next_cpu));

        int tmp_cpu = cpujump_info->next_cpu;
        cpujump_info->next_cpu = cpujump_info->current_cpu;
        cpujump_info->current_cpu = tmp_cpu;
        log_warning("Current CPU: %d, Next CPU: %d", cpujump_info->current_cpu, cpujump_info->next_cpu);

        return;
    }

    log_warning("# Checkpoint is not enabled");
    return;
}

static LogicalProcessorSet init_cpus()
{
    LogicalProcessorSet result = ambient_logical_processor_set();
    sApp->thread_count = result.count();
    sApp->user_thread_data.resize(sApp->thread_count);
#ifdef M_ARENA_MAX
    mallopt(M_ARENA_MAX, sApp->thread_count * 2);
#endif
    return result;
}

static void attach_shmem_internal(int fd, size_t size)
{
    void *base = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        perror_for_mmap("internal error: could not map the shared memory file to memory");
        exit(EX_IOERR);
    }

    sApp->shmem = static_cast<SandstoneApplication::SharedMemory *>(base);

    assert(sApp->shmem->thread_data_offset);
    assert(sApp->shmem->main_thread_count);
    auto ptr = reinterpret_cast<unsigned char *>(sApp->shmem);
    ptr += sApp->shmem->thread_data_offset;

    sApp->main_thread_data_ptr = reinterpret_cast<PerThreadData::Main *>(ptr);
    ptr += ROUND_UP_TO_PAGE(sizeof(PerThreadData::Main) * sApp->shmem->main_thread_count);
    sApp->test_thread_data_ptr = reinterpret_cast<PerThreadData::Test *>(ptr);
}

static void init_shmem()
{
    using namespace PerThreadData;
    static_assert(sizeof(PerThreadData::Main) == 64,
            "PerThreadData::Main size grew, please check if it was intended");
    static_assert(sizeof(PerThreadData::Test) == 64,
            "PerThreadData::Test size grew, please check if it was intended");
    assert(sApp->current_fork_mode() != SandstoneApplication::child_exec_each_test);
    assert(sApp->shmem == nullptr);
    assert(num_cpus());

    unsigned per_thread_size = sizeof(PerThreadData::Main);
    per_thread_size = ROUND_UP_TO(per_thread_size, alignof(PerThreadData::Test));
    per_thread_size += sizeof(PerThreadData::Test) * num_cpus();
    per_thread_size = ROUND_UP_TO_PAGE(per_thread_size);

    unsigned thread_data_offset = sizeof(SandstoneApplication::SharedMemory) +
            sizeof(Topology::Thread) * num_cpus();
    thread_data_offset = ROUND_UP_TO_PAGE(thread_data_offset);

    size_t size = thread_data_offset;

    // our child (if we have one) will inherit this file descriptor
    int fd = open_memfd(MemfdInheritOnExec);
    if (fd < 0 || ftruncate(fd, size) < 0) {
        perror("internal error: could not create temporary file for sharing memory");
        exit(EX_CANTCREAT);
    }

    void *base = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        perror_for_mmap("internal error: could not map the shared memory file to memory");
        exit(EX_CANTCREAT);
    }

    sApp->shmemfd = fd;
    sApp->shmem = new (base) SandstoneApplication::SharedMemory;
    sApp->shmem->thread_data_offset = thread_data_offset;
    sApp->shmem->main_process_pid = getpid();
}

static void commit_shmem()
{
    // the most detailed plan is the last
    const std::vector<CpuRange> &plan = sApp->slice_plans.plans.end()[-1];
    size_t main_thread_count = plan.size();
    sApp->shmem->main_thread_count = main_thread_count;
    sApp->shmem->total_cpu_count = num_cpus();

    // unmap the current area, because Windows doesn't allow us to have two
    // blocks for this file
    ptrdiff_t offset = sApp->shmem->thread_data_offset;
    munmap(sApp->shmem, offset);

    // enlarge the file and map the extra data
    size_t size = sizeof(PerThreadData::Main) * main_thread_count;
    size = ROUND_UP_TO_PAGE(size);
    size += sizeof(PerThreadData::Test) * num_cpus();
    size = ROUND_UP_TO_PAGE(size);

    if (ftruncate(sApp->shmemfd, offset + size) < 0) {
        perror("internal error: could not enlarge temporary file for sharing memory");
        exit(EX_CANTCREAT);
    }
    attach_shmem_internal(sApp->shmemfd, offset + size);

    if (sApp->current_fork_mode() != SandstoneApplication::exec_each_test) {
        close(sApp->shmemfd);
        sApp->shmemfd = -1;
    }

    // sApp->shmem has probably moved
    restrict_topology({ 0, num_cpus() });
}

static void attach_shmem(int fd)
{
    assert(sApp->current_fork_mode() == SandstoneApplication::child_exec_each_test);

    size_t size;
    if (struct stat st; fstat(fd, &st) >= 0) {
        size = st.st_size;
        assert(size == ROUND_UP_TO_PAGE(size));
    } else {
        fprintf(stderr, "internal error: could not get the size of shared memory (fd = %d): %m\n",
                fd);
        exit(EX_IOERR);
    }

    attach_shmem_internal(fd, size);
    close(fd);

    // barrier with the parent process
    sApp->main_thread_data()->thread_state.exchange(thread_not_started, std::memory_order_acquire);
}

static void protect_shmem()
{
    size_t protected_len = sApp->shmem->thread_data_offset;
    assert(protected_len == ROUND_UP_TO_PAGE(protected_len) &&
            "SharedMemory::main_thread_data is not page-aligned");
    IGNORE_RETVAL(mprotect(sApp->shmem, protected_len, PROT_READ));
}

static void slice_plan_init(int max_cores_per_slice)
{
    auto set_to_full_system = []() {
        // only one plan and that's the full system
        std::vector plan = { CpuRange{ 0, num_cpus() } };
        sApp->slice_plans.plans.fill(plan);
        return;
    };
    for (std::vector<CpuRange> &plan : sApp->slice_plans.plans)
        plan.clear();

    if (sApp->current_fork_mode() == SandstoneApplication::no_fork || max_cores_per_slice < 0)
        return set_to_full_system();

    // The heuristic is enabled by max_cores_per_slice == 0 and a valid
    // topology:
    // - if the CPU Set has less than or equal toMinimumCpusPerSocket (8)
    //   logical processors per socket (on average), we ignore the topology and
    //   will instead run in slices of up to DefaultMaxCoresPerSlice (32)
    //   logical processors.
    // - otherwise, we'll have at least one slice per socket, and maybe more
    //   for sockets with more than 32 cores per socket.
    //   * hardware threads of a given core are always sliced together, so a
    //     2-thread core system will have up to 64 logical processors in a
    //     slice (a hypothetical 4-thread system would have up to 128).
    //
    // The heuristic slices will be balanced as follows:
    // - if the number of cores in the socket is not a multiple of
    //   DefaultMaxCoresPerSlice (32) but is of SecondaryMaxCoresPerSlice (24),
    //   we'll use the secondary maximum
    // - the number of cores per slice is kept as a multiple of 4; that is, a
    //   60-core socket will have a slice of 32 cores and one of 28 cores,
    //   instead of 30+30.
    // - other than that, the number of cores per slice is balanced; that is,
    //   a 40-core socket is split as two 20-core slices instead of 32+8.
    //
    // If the user specifies a --max-cores-per-slice option in the
    // command-line, it will bypass the heuristic but keep the slice balancing
    // as described above, including keeping the multiple-of-4 sliceing, if the
    // requested target is also a multiple of 4. Be aware bypasses the minimum
    // average processor per socket check.
    //
    // As a result, expect the following sliceing:
    //  Topology            slices
    //  invalid             everything
    //  1 x 32              [32]
    //  1 x 36              [20 + 16]
    //  1 x 40              [20 + 20]
    //  1 x 60              [32 + 28]
    //  1 x 64              [32 + 32]
    //  1 x 96              [32 + 32 + 32]
    //  1 x 120             [24 + 24 + 24 + 24 + 24] (uses secondary max)
    //  1 x 124             [32 + 32 + 32 + 28]
    //  1 x 128             [32 + 32 + 32 + 32]
    //  1 x 143             [32 + 32 + 32 + 32 + 15]
    //  1 x 144             [24 + 24 + 24 + 24 + 24 + 24] (uses secondary max)
    //  1 x 192             [32 + 32 + 32 + 32 + 32 + 32] (does not use secondary max)
    //  2 x 8               [16]
    //  2 x 16              [16] + [16]
    //  2 x 32              [32] + [32]
    //  2 x 40              [20 + 20] + [20 + 20]
    //  4 x 8               [32]
    //  4 x 16              [16] + [16] + [16] + [16]
    //  8 x 8               [32] + [32]
    //  16 x 4              [32] + [32]
    //  16 x 8              [32] + [32] + [32] + [32]
    // etc.

    int max_cpu = num_cpus();
    const Topology &topology = Topology::topology();
    while (topology.isValid()) {     // not a loop, just so we can use break
        using SlicePlans = SandstoneApplication::SlicePlans;
        static constexpr int MinimumCpusPerSocket = SlicePlans::MinimumCpusPerSocket;
        static constexpr int DefaultMaxCoresPerSlice = SlicePlans::DefaultMaxCoresPerSlice;
        static constexpr int SecondaryMaxCoresPerSlice = SlicePlans::SecondaryMaxCoresPerSlice;

        bool using_defaults = false;
        if (max_cores_per_slice == 0) {
            // apply defaults
            using_defaults = true;
            int average_cpus_per_socket = max_cpu / topology.packages.size();
            max_cores_per_slice = DefaultMaxCoresPerSlice;
            if (average_cpus_per_socket <= MinimumCpusPerSocket)
                break;
        }

        // set up proper plans
        std::vector<CpuRange> &fullsocket = sApp->slice_plans.plans[SlicePlans::IsolateSockets];
        std::vector<CpuRange> &split = sApp->slice_plans.plans[SlicePlans::Heuristic];
        auto push_to = [](std::vector<CpuRange> &to, const Topology::Core *start, const Topology::Core *end) {
            int start_cpu = start[0].threads.front().cpu();
            int end_cpu = end[-1].threads.back().cpu();
            assert(end_cpu >= start_cpu);
            to.push_back(CpuRange{ start_cpu, end_cpu + 1 - start_cpu });
        };

        for (const Topology::Package &p : topology.packages) {
            if (p.cores.size() == 0)
                continue;       // untested socket

            const Topology::Core *c = p.cores.data();
            const Topology::Core *end = c + p.cores.size();
            push_to(fullsocket, c, end);

            ptrdiff_t slice_count = p.cores.size() / max_cores_per_slice;
            if (p.cores.size() % max_cores_per_slice) {
                if (using_defaults && (p.cores.size() % SecondaryMaxCoresPerSlice) == 0) {
                    // use the secondary count
                    slice_count = p.cores.size() / SecondaryMaxCoresPerSlice;
                } else {
                    ++slice_count;  // round up (also makes at least 1)
                }
            }

            ptrdiff_t slice_size = p.cores.size() / slice_count;
            if ((max_cores_per_slice & 3) == 0 && (slice_size & 3))
                slice_size = ((slice_size >> 2) + 1) << 2;  // make it multiple of 4

            for ( ; end - c > slice_size; c += slice_size)
                push_to(split, c, c + slice_size);
            push_to(split, c, end);
        }
        return;
    }

    if (max_cores_per_slice == 0) {
        set_to_full_system();
    } else {
        // dumb plan, not *cores*
        int slice_count = (max_cpu - 1) / max_cores_per_slice + 1;
        std::vector<CpuRange> plan;
        plan.reserve(slice_count);

        int slice_size = max_cpu / slice_count;
        int cpu = 0;
        for ( ; cpu < max_cpu - slice_size; cpu += slice_size)
            plan.push_back(CpuRange{ cpu, slice_size });
        plan.push_back(CpuRange{ cpu, max_cpu - cpu });
        sApp->slice_plans.plans.fill(plan);
    }
}

__attribute__((weak, noclone, noinline)) void print_application_banner()
{
}

__attribute__((weak, noclone, noinline)) void cpu_specific_init()
{
}

__attribute__((weak, noclone, noinline)) int print_application_footer(int exit_code, SandstoneApplication::PerCpuFailures per_cpu_failures)
{
    return exit_code;
}

static std::string cpu_features_to_string(uint64_t f)
{
    std::string result;
    const char *comma = "";
    for (size_t i = 0; i < std::size(x86_locators); ++i) {
        if (f & (UINT64_C(1) << i)) {
            result += comma;
            result += features_string + features_indices[i] + 1;
            comma = ",";
        }
    }
    return result;
}

static void dump_cpu_info()
{
    int i;

    // find the best matching CPU
    const char *detected = "<unknown>";
    for (const auto &arch : x86_architectures) {
        if ((arch.features & cpu_features) == arch.features) {
            detected = arch.name;
            break;
        }
        if (sApp->shmem->verbosity > 1)
            printf("CPU is not %s: missing %s\n", arch.name,
                   cpu_features_to_string(arch.features & ~cpu_features).c_str());
    }
    printf("Detected CPU: %s; family-model-stepping (hex): %02x-%02x-%02x; CPU features: %s\n",
           detected, cpu_info[0].family, cpu_info[0].model, cpu_info[0].stepping,
           cpu_features_to_string(cpu_features).c_str());
    printf("# CPU\tPkgID\tCoreID\tThrdID\tMicrocode\tPPIN\n");
    for (i = 0; i < num_cpus(); ++i) {
        printf("%d\t%d\t%d\t%d\t0x%" PRIx64, cpu_info[i].cpu_number,
               cpu_info[i].package_id, cpu_info[i].core_id, cpu_info[i].thread_id,
               cpu_info[i].microcode);
        if (cpu_info[i].ppin)
            printf("\t%016" PRIx64, cpu_info[i].ppin);
        puts("");
    }
}

static void suggest_help(char **argv) {
    printf("Try '%s --help' for more information.\n", argv[0]);
}

static void usage(char **argv)
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

// Called every time we restart the tests
static void restart_init(int iterations)
{
}

static void run_threads_in_parallel(const struct test *test)
{
    SandstoneTestThread thr[num_cpus()];    // NOLINT: -Wvla
    int i;

    for (i = 0; i < num_cpus(); i++) {
        thr[i].start(thread_runner, i);
    }
    /* wait for threads to end */
    for (i = 0; i < num_cpus(); i++) {
        thr[i].join();
    }
}

static void run_threads_sequentially(const struct test *test)
{
    // we still start one thread, in case the test uses report_fail_msg()
    // (which uses pthread_cancel())
    SandstoneTestThread thread;
    thread.start([](int cpu) {
        for ( ; cpu != num_cpus(); thread_num = ++cpu)
            thread_runner(cpu);
        return uintptr_t(cpu);
    }, 0);
    thread.join();
}

static void run_threads(const struct test *test)
{
    current_test = test;

    switch (test->flags & test_schedule_mask) {
    default:
        run_threads_in_parallel(test);
        break;

    case test_schedule_sequential:
        run_threads_sequentially(test);
        break;
    }

    current_test = nullptr;
}

namespace {
struct StartedChild
{
    intptr_t pid;
    int fd;
};

struct ChildrenList
{
    ChildrenList() = default;
    ChildrenList(const ChildrenList &) = delete;
    ChildrenList &operator=(const ChildrenList &) = delete;
#ifdef _WIN32
    ~ChildrenList()
    {
        for (auto &p : handles) {
            HANDLE h = reinterpret_cast<HANDLE>(p);
            if (h != INVALID_HANDLE_VALUE)
                CloseHandle(h);
        }
    }
#else
    ~ChildrenList()
    {
        for (auto &p : pollfds) {
            if (p.fd != -1)
                close(p.fd);
        }
    }

    std::vector<pollfd> pollfds;
#endif
    std::vector<pid_t> handles;
    std::vector<ChildExitStatus> results;

    void add(StartedChild child)
    {
        handles.push_back(child.pid);
#ifndef _WIN32
        pollfds.emplace_back(pollfd{ .fd = child.fd, .events = POLLIN });
#endif
    }
};
} // unnamed namespace

static void wait_for_children(ChildrenList &children, const struct test *test)
{
    Duration remaining = test_timeout(sApp->current_test_duration);
    int children_left = children.handles.size();
    children.results.resize(children_left);

#if !defined(_WIN32)
    // add even if -1
    children.pollfds.emplace_back(pollfd{ .fd = sApp->shmem->server_debug_socket, .events = POLLIN });
    auto remove_debug_socket = scopeExit([&] { children.pollfds.pop_back(); });

    static constexpr int TimeoutSignal = SIGQUIT;
    auto kill_children = [&](int sig = SIGKILL) {
        // Send the signal to the child's process group, so all its children
        // get the signal too.
        for (pid_t child : children.handles) {
            if (child)
                kill(-child, sig);
        }
    };
    auto single_wait = [&, caughtSignal = 0](milliseconds timeout) mutable {
        int ret = poll(children.pollfds.data(), children.pollfds.size(), timeout.count());
        if (ret == 0)
            return 0;           // timed out

        if (__builtin_expect(ret < 0 && errno != EINTR, false)) {
            perror("poll");
            exit(EX_OSERR);
        }
        if (ret < 0) {
            // we've received a signal, which one?
            auto [signal, count] = last_signal();
            if (signal != 0) {
                // forward the signal to all children
                kill_children(signal);
            }

            // if it was SIGINT, we print a message and wait for the test
            if (count == 1 && signal == SIGINT) {
                logging_printf(LOG_LEVEL_QUIET, "# Caught SIGINT, stopping current test "
                                                "(press Ctrl+C again to exit without waiting)\n");
                logging_print_log_file_name();
                enable_interrupt_catch();       // re-arm SIGINT handler
                caughtSignal = signal;
                return 0;
            } else {
                // for any other signal (e.g., SIGTERM), we don't
                return int(signal);
            }
        }

        auto now = MonotonicTimePoint::clock::now();
        if (pollfd &pfd = children.pollfds.back(); pfd.revents & POLLIN) {
            // one child (or more than one) is crashing
            debug_crashed_child(children.handles);
        }

        // check if any of the children have exited
        for (int i = 0; i < children.pollfds.size() - 1; ++i) {
            pollfd &pfd = children.pollfds[i];
            if (pfd.revents == 0)
                continue;

            // wait for this child
            struct forkfd_info info;
            struct rusage usage;
            EINTR_LOOP(ret, forkfd_wait4(pfd.fd, &info, WNOHANG, &usage));
            if (ret == -1) {
                if (errno == EAGAIN)
                    continue;           // shouldn't happen...
                perror("forkfd_wait");
                exit(EX_OSERR);
            }
            forkfd_close(pfd.fd);
            pfd.fd = -1;
            pfd.events = 0;
            children.handles[i] = 0;
            children.results[i] = test_result_from_exit_code(info);
            children.results[i].endtime = now;
            children.results[i].usage = usage;
            --children_left;
        }
        return caughtSignal;
    };
#elif defined(_WIN32)
    static constexpr DWORD TimeoutSignal = EXIT_TIMEOUT;
    auto kill_children = [&](DWORD exitCode = DWORD(-1)) {
        // Note: Windows code cannot kill grand-children processes!
        for (intptr_t child : children.handles) {
            HANDLE hnd = HANDLE(child);
            if (hnd == INVALID_HANDLE_VALUE)
                continue;
            TerminateProcess(hnd, exitCode);
        }
    };
    auto single_wait = [&](milliseconds timeout) {
        HANDLE handles[MAXIMUM_WAIT_OBJECTS];
        DWORD nCount = 0;
        if (sApp->shmem->debug_event)
            handles[nCount++] = HANDLE(sApp->shmem->debug_event);
        for (auto it = children.handles.begin(); it != children.handles.end() && nCount < MAXIMUM_WAIT_OBJECTS; ++it) {
            HANDLE hnd = HANDLE(*it);
            if (hnd == INVALID_HANDLE_VALUE)
                continue;
            handles[nCount] = hnd;
            ++nCount;
        }
        bool bWaitAll = false;
        DWORD result = WaitForMultipleObjects(nCount, handles, bWaitAll, timeout.count());
        if (__builtin_expect(result == WAIT_FAILED, false)) {
            fprintf(stderr, "%s: WaitForMultipleObjects() failed: %lx; children left = %d\n",
                    program_invocation_name, GetLastError(), children_left);
            abort();
        }
        if (result == WAIT_TIMEOUT)
            return 0;

        int idx = result - WAIT_OBJECT_0;
        if (idx == 0 && sApp->shmem->debug_event) {
            // one child (or more than one) is crashing
            debug_crashed_child(children.handles);
            return 0;
        }

        HANDLE hExited = handles[idx];
        if (GetExitCodeProcess(hExited, &result) == 0) {
            fprintf(stderr, "%s: GetExitCodeProcess(child = %p) failed: %lx\n",
                    program_invocation_name, handles[idx], GetLastError());
            abort();
        }

        auto childResult = test_result_from_exit_code(result);
        childResult.endtime = MonotonicTimePoint::clock::now();
        if (FILETIME dummy, stime, utime; GetProcessTimes(hExited, &dummy, &dummy, &stime, &utime)) {
            auto cvt = [](FILETIME f) {
                // FILETIME stores tenths of microseconds (100 ns) granularity
                uint64_t time = f.dwHighDateTime;
                time = (time << 32) | f.dwLowDateTime;
                struct timeval tv;
                tv.tv_sec = time / 1000 / 1000 / 10;
                tv.tv_usec = time % (1000 * 1000) / 10;
                return tv;
            };
            childResult.usage.ru_stime = cvt(stime);
            childResult.usage.ru_utime = cvt(utime);
        }
        if (PROCESS_MEMORY_COUNTERS mi; GetProcessMemoryInfo(hExited, &mi, sizeof(mi))) {
            childResult.usage.ru_maxrss = mi.PeakWorkingSetSize;
            childResult.usage.ru_majflt = mi.PageFaultCount;
        }

        // close the handle and store result
        for (idx = 0; idx < int(children.handles.size()); ++idx) {
            if (hExited == HANDLE(children.handles[idx])) {
                CloseHandle(hExited);
                children.handles[idx] = intptr_t(INVALID_HANDLE_VALUE);
                children.results[idx] = childResult;
                break;
            }
        }
        --children_left;
        return 0;
    };
#else
#  error "What platform is this?"
#endif
    auto terminate_children = [&] {
        for (size_t i = 0; i < children.handles.size(); ++i) {
            auto child = children.handles[i];
            if (children.results[i].endtime == MonotonicTimePoint{}) {
                debug_hung_child(child, children.handles);
#ifdef _WIN32
                log_message(-int(i) - 1, SANDSTONE_LOG_ERROR "Child %ld did not exit, using TerminateProcess()",
                            GetProcessId(HANDLE(child)));
#else
                log_message(-int(i) - 1, SANDSTONE_LOG_ERROR "Child %d did not exit, sending signal SIGQUIT", child);
#endif
            }
        }
        kill_children(TimeoutSignal);
    };
    auto wait_for_all_children = [&](Duration remaining) {
        MonotonicTimePoint deadline = steady_clock::now() + remaining;
        for ( ; children_left && remaining > 0s; remaining = deadline - steady_clock::now()) {
            int ret = single_wait(ceil<milliseconds>(remaining));
            if (ret == 0)
                continue;

            for (ChildExitStatus &result : children.results)
                result = { TestResult::Interrupted };

            // Problem waiting: we must have caught a signal
            // (child has likely not been able to write results)
            int exit_code = 128 | ret;

            logging_print_results(children.results, test);
            exit_code = cleanup_global(exit_code, {});

            // now exit with the same signal
            disable_interrupt_catch();
            raise(exit_code & 0x7f);
            _exit(exit_code);           // just in case
        }
    };

    /* first wait set : normal exit */
    wait_for_all_children(remaining);
    if (children_left == 0)
        return;

    /* at least one child timed out; force them to exit */
    terminate_children();

    /* wait for the termination to take effect */
    wait_for_all_children(20s);
    if (children_left) {
        /* timed out again, take drastic measures */
        kill_children();
        wait_for_all_children(20s);
    }
    if (children_left) {
        for (size_t i = 0; i < children.handles.size(); ++i) {
            if (children.handles[i] == 0)
                continue;
            log_platform_message(SANDSTONE_LOG_ERROR "# Child %td is hung and won't exit",
                                 intptr_t(children.handles[i]));
            children.results[i] = { TestResult::TimedOut };
        }
    }
}

static TestResult child_run(/*nonconst*/ struct test *test, int child_number)
{
    if (sApp->current_fork_mode() != SandstoneApplication::no_fork) {
        protect_shmem();
        sApp->select_main_thread(child_number);
        pin_to_logical_processors(sApp->main_thread_data()->cpu_range, "control");
        restrict_topology(sApp->main_thread_data()->cpu_range);
        signals_init_child();
        debug_init_child();
    }
    if (sApp->thread_synchronization)
        sApp->thread_synchronization->init();

    prepare_test(test);

    TestResult state = TestResult::Passed;

    do {
        int ret = 0;
        test->per_thread = sApp->user_thread_data.data();
        std::fill_n(test->per_thread, sApp->thread_count, test_data_per_thread{});
        init_per_thread_data();

        sApp->test_tests_init(test);
        if (test->test_init) {
            // ensure the init function is run pinned to a specific logical
            // processor but its pinning doesn't affect this control thread
            auto init_thread_runner = [](void *testptr) {
                auto test = static_cast</*nonconst*/ struct test *>(testptr);
                pin_to_logical_processor(LogicalProcessor(cpu_info[0].cpu_number));
                thread_num = -1;
                intptr_t ret = test->test_init(test);
                return reinterpret_cast<void *>(ret);
            };
            pthread_t init_thread;
            void *retptr;
            pthread_create(&init_thread, nullptr, init_thread_runner, test);
            pthread_join(init_thread, &retptr);
            ret = intptr_t(retptr);
        }

        if (ret > 0 || sApp->main_thread_data()->has_failed()) {
            logging_mark_thread_failed(-1);
            if (ret > 0)
                log_error("Init function failed with code %i", ret);
            state = TestResult::Failed;
            break;
        } else if (ret < 0) {
            if (ret != EXIT_SKIP)
                log_skip(RuntimeSkipCategory, "Unexpected OS error: %s", strerror(-ret));
            state = TestResult::Skipped;
            break;
        }

        run_threads(test);

        if (sApp->shmem->use_strict_runtime && wallclock_deadline_has_expired(sApp->endtime)){
            // skip cleanup on the last test when using strict runtime
        } else {
            if (test->test_cleanup) {
                ret = test->test_cleanup(test);
                if (state == TestResult::Passed) {
                    if (ret == EXIT_SKIP) {
                        log_skip(RuntimeSkipCategory, "SKIP requested in cleanup");
                        state = TestResult::Skipped;
                    } else if (ret < EXIT_SUCCESS) {
                        log_skip(RuntimeSkipCategory, "Unexpected OS error in cleanup: %s", strerror(-ret));
                        state = TestResult::Skipped;
                    } else if (ret > EXIT_SUCCESS) {
                        state = TestResult::Failed;
                    }
                }
            }
        }

        sApp->test_tests_finish(test);
    } while (false);

    return state;
}

static StartedChild call_forkfd()
{
    pid_t pid;

#ifdef __linux__
    /*
     * glibc up until release 2.25 used to cache the process's PID in each thread's
     * specific data and that's what was returned from getpid(). The fork()
     * function did overwrite it so that the child side would get the correct PID,
     * but forkfd() has code to use clone() directly if the kernel is recent
     * enough (CLONE_PIDFD support). When that happens, the getpid() function calls
     * in the child side will fail. See:
     *
     * https://sourceware.org/bugzilla/show_bug.cgi?id=15368
     * https://yarchive.net/comp/linux/getpid_caching.html
     */
    static constexpr eventfd_t PidProperlyUpdated = 0x646950646f6f47,
        PidIncorrectlyCached = 0x646950646142;

    /*
     * Additionally, Red Hat botched the backport of the pidfd feature from 5.4
     * to their 4.18 tree for Red Hat Enterprise Linux 8.5/8.6. Kernel releases
     * 358 to 391 support pidfd, but poll(2) fails to wait on it and always
     * returns immediately
     *
     * https://bugreports.qt.io/browse/QTBUG-100174
     * https://bugzilla.redhat.com/show_bug.cgi?id=2107643
     * https://access.redhat.com/errata/RHSA-2022:6460
     */
    static constexpr eventfd_t PollWorks = 0x6c6c6f50646f6f47,
            PollFails = 0x6c6c6f50646142;
    static int ffd_extra_flags = -1;
    if (__builtin_expect(ffd_extra_flags < 0, false)) {
        // determine if we need to pass FFD_USE_FORK
        pid_t parentpid = getpid();
        int efdpid = eventfd(0, EFD_CLOEXEC);
        int efdpoll = eventfd(0, EFD_CLOEXEC);
        assert(efdpid != -1);

        int ffd = forkfd(FFD_CLOEXEC, &pid);

        if (ffd == -1) {
            // forkfd failed (probably CLONE_PIDFD rejected)
            ffd_extra_flags = FFD_USE_FORK;
        } else if (ffd == FFD_CHILD_PROCESS) {
            // child side - wait for parent to try to poll() us
            eventfd_t pollstatus;
            eventfd_read(efdpoll, &pollstatus);
            close(efdpoll);
            if (pollstatus == PollFails)
                _exit(127);

            // confirm that the PID updated
            bool pid_updated = (getpid() != parentpid);
            eventfd_write(efdpid, pid_updated ? PidProperlyUpdated : PidIncorrectlyCached);
            close(efdpid);
            if (!pid_updated)
                _exit(127);

            // no problems seen, return to caller as child process
            return { .pid = pid, .fd = FFD_CHILD_PROCESS };
        } else {
            // parent side
            int ret;
            eventfd_t result;

            // check if poll() works
            struct pollfd pfd = { .fd = ffd, .events = POLLIN };
            EINTR_LOOP(ret, poll(&pfd, 1, 1));  // 1ms is enough
            if (ret == 1) {
                eventfd_write(efdpoll, PollFails);
                close(efdpoll);
            } else {
                // it does, proceed with the getpid() check
                eventfd_write(efdpoll, PollWorks);
                close(efdpoll);

                EINTR_LOOP(ret, eventfd_read(efdpid, &result));
                close(efdpid);

                if (result == PidProperlyUpdated) {
                    // no problems seen, return to caller as parent process
                    ffd_extra_flags = 0;
                    return { .pid = pid, .fd = ffd };
                }
            }

            // found a problem, wait for the child and try again
            EINTR_LOOP(ret, forkfd_wait(ffd, nullptr, nullptr));
            forkfd_close(ffd);
            ffd_extra_flags = FFD_USE_FORK;
        }
    }
#else
    static constexpr int ffd_extra_flags = 0;
#endif

    int ffd = forkfd(FFD_CLOEXEC | ffd_extra_flags, &pid);
    if (ffd == -1) {
        perror("fork");
        exit(EX_OSERR);
    }
    return { .pid = pid, .fd = ffd };
}

static StartedChild spawn_child(const struct test *test, int child_number)
{
    assert(sApp->shmemfd != -1);
    std::string shmemfdstr = stdprintf("%d", sApp->shmemfd);
    std::string childnumstr = stdprintf("%d", child_number);
    std::string random_seed = random_format_seed();

    StartedChild ret = {};
#ifdef _WIN32
    // _spawn on Windows requires argv elements to be quoted if they contain space.
    const char * const argv0 = SANDSTONE_EXECUTABLE_NAME ".exe";
    if (sApp->gdb_server_comm.size()) {
        // we need the actual Windows handle, because the file
        // descriptors don't inherit properly via gdbserver
       shmemfdstr = stdprintf("h%tx", _get_osfhandle(sApp->shmemfd));
    }
#else
    const char * const argv0 = SANDSTONE_EXECUTABLE_NAME;
#endif
    const char *argv[] = {
        // argument order must match exec_mode_run()
        argv0, "-x", test->id, random_seed.c_str(),
        shmemfdstr.c_str(),
        childnumstr.c_str(),
        nullptr
    };

    const char *gdbserverargs[std::size(argv) + 3] = {
        "gdbserver", "--no-startup-with-shell", sApp->gdb_server_comm.c_str(),
        program_invocation_name
    };
    std::copy(argv + 1, std::end(argv), gdbserverargs + 4);

#ifdef _WIN32
    // save stderr
    static int saved_stderr = _dup(STDERR_FILENO);
    logging_init_child_preexec();

    if (sApp->gdb_server_comm.size()) {
        // launch gdbserver instead
        ret.pid = _spawnvp(_P_NOWAIT, gdbserverargs[0], const_cast<char **>(gdbserverargs));
    } else {
        ret.pid = _spawnv(_P_NOWAIT, path_to_exe(), argv);
    }

    int saved_errno = errno;

    // restore stderr
    _dup2(saved_stderr, STDERR_FILENO);

    if (ret.pid == -1) {
        errno = saved_errno;
        perror("_spawnv");
        exit(EX_OSERR);
    }
#else
    ret = call_forkfd();
    if (ret.fd == FFD_CHILD_PROCESS) {
        logging_init_child_preexec();

        if (sApp->gdb_server_comm.size()) {
            // launch gdbserver instead
            execvp(gdbserverargs[0], const_cast<char **>(gdbserverargs));
        }

        execv(path_to_exe(), const_cast<char **>(argv));
        /* does not return */
        perror("execv");
        _exit(EX_OSERR);
    }
#endif /* __linux__ */

    return ret;
}

static int slices_for_test(const struct test *test)
{
    SandstoneApplication::SlicePlans::Type type = [=]() {
        switch (test->flags & test_schedule_mask) {
        case test_schedule_sequential:  // sequential tests see the full system
        case test_schedule_fullsystem:
            return SandstoneApplication::SlicePlans::FullSystem;

        case test_schedule_isolate_socket:
            return SandstoneApplication::SlicePlans::IsolateSockets;

        case test_schedule_default:
            break;
        }
        return SandstoneApplication::SlicePlans::Heuristic;
    }();
    if (type == SandstoneApplication::SlicePlans::FullSystem) {
        sApp->main_thread_data()->cpu_range = { 0, num_cpus() };
        return 1;
    }

    const std::vector<CpuRange> &plan = sApp->slice_plans.plans[type];
    for (size_t i = 0; i < plan.size(); ++i)
        sApp->main_thread_data(i)->cpu_range = plan[i];

    return plan.size();
}

static void run_one_test_children(ChildrenList &children, const struct test *test)
{
    int child_count = slices_for_test(test);
    if (sApp->current_fork_mode() != SandstoneApplication::exec_each_test) {
        assert(sApp->current_fork_mode() != SandstoneApplication::child_exec_each_test
                && "child_exec_each_test mode can only happen in the child side!");
        assert((sApp->current_fork_mode() != SandstoneApplication::no_fork || child_count == 1)
               && "-fno-fork can only start 1 child!");

        for (int i = 0; i < child_count; ++i) {
            StartedChild ret = { .fd = FFD_CHILD_PROCESS };
            if (sApp->current_fork_mode() == SandstoneApplication::fork_each_test)
                ret = call_forkfd();
            if (ret.fd == FFD_CHILD_PROCESS) {
                /* child - run test's code */
                logging_init_child_preexec();
                TestResult result = child_run(const_cast<struct test *>(test), i);
                if (sApp->current_fork_mode() == SandstoneApplication::fork_each_test)
                    _exit(test_result_to_exit_code(result));

                children.results.emplace_back(ChildExitStatus{ result });
                return;
            } else {
                children.add(ret);
            }
        }
    } else {
        for (int i = 0; i < child_count; ++i)
            children.add(spawn_child(test, i));
    }

    /* wait for the children */
    wait_for_children(children, test);
}

static TestResult run_one_test_once(const struct test *test)
{
    ChildrenList children;

    sApp->current_test_count++;
    if (uint64_t missing = (test->minimum_cpu | test->compiler_minimum_cpu) & ~cpu_features) {
        init_per_thread_data();

        // for brevity, don't report the bits that the framework itself needs
        missing &= ~_compilerCpuFeatures;
        log_skip(CpuNotSupportedSkipCategory, "test requires %s\n", cpu_features_to_string(missing).c_str());
        (void) missing;

        children.results.emplace_back(ChildExitStatus{ TestResult::Skipped });
    } else if (test->quality_level >= 0 && test->quality_level < sApp->requested_quality) {
        init_per_thread_data();
        log_skip(TestResourceIssueSkipCategory, "Test %s is in BETA quality, try again using --beta option", test->id);
        children.results.emplace_back(ChildExitStatus{ TestResult::Skipped });
    } else if (test->quality_level >= sApp->requested_quality) {
        run_one_test_children(children, test);
    }

    // print results and find out if the test failed
    TestResult testResult = logging_print_results(children.results, test);
    switch (testResult) {
    case TestResult::Passed:
    case TestResult::Skipped:
    case TestResult::Failed:
    case TestResult::CoreDumped:
    case TestResult::Killed:
        break;          // continue running tests

    case TestResult::OperatingSystemError:
    case TestResult::TimedOut:
    case TestResult::OutOfMemory:
        if (!sApp->ignore_os_errors) {
            _exit(cleanup_global(EXIT_INVALID, {}));
        } else {
            // not a pass either, but won't affect the result
            testResult = TestResult::Skipped;
        }
        break;

    case TestResult::Interrupted:
        assert(false && "internal error: shouldn't have got here!");
        __builtin_unreachable();
        break;
    }

    return testResult;
}

static void analyze_test_failures(const struct test *test, int fail_count, int attempt_count,
                                  const SandstoneApplication::PerCpuFailures &per_cpu_failures)
{
    logging_printf(LOG_LEVEL_VERBOSE(1), "# Test failed %d out of %d times"
                                         " (%.1f%%)\n", fail_count, attempt_count,
                   fail_count * 100.0 / attempt_count);
    logging_restricted(LOG_LEVEL_QUIET, "Test failed (#%s%x).", test->id, fail_count - 1);

    // First, determine if all CPUs failed the exact same way
    bool all_cpus_failed_equally = true;
    uint64_t fail_pattern = 0;
    int nfailures = 0;
    for (size_t i = 0; i < num_cpus() && all_cpus_failed_equally; ++i) {
        if (per_cpu_failures[i]) {
            if (++nfailures == 1)
                fail_pattern = per_cpu_failures[i];
            else if (per_cpu_failures[i] != fail_pattern)
                all_cpus_failed_equally = false;
        }
    }
    if (all_cpus_failed_equally && nfailures == num_cpus()) {
        logging_printf(LOG_LEVEL_VERBOSE(1), "# All CPUs failed equally. This is highly unlikely (SW bug?)\n");
        return;
    }

    Topology topology  = Topology::topology();
    if (!topology.isValid()) {
        // can't use this information
        if (all_cpus_failed_equally)
            logging_printf(LOG_LEVEL_VERBOSE(1), "# All failing CPUs failed equally.\n");
    } else if (test->flags & test_failure_package_only) {
        // Failure cannot be attributed to a single thread or core.  Let's see if it
        // can be pinned down to a single package.
        logging_printf(LOG_LEVEL_VERBOSE(1), "# Topology analysis:\n");

        // Analysis is not needed if there's only a single package.
        if (topology.packages.size() == 1) {
            logging_printf(LOG_LEVEL_VERBOSE(1), "# - Failures localised to package %d\n",
                           topology.packages[0].id());
            return;
        }

        std::vector<int> pkg_failures(topology.packages.size(), -1);
        int failed_packages = 0;
        int last_bad_package = -1;
        for (size_t p = 0; p < topology.packages.size(); ++p) {
            Topology::Package *pkg = &topology.packages[p];
            for (size_t c = 0; c < pkg->cores.size(); ++c) {
                Topology::Core *core = &pkg->cores[c];
                for (const Topology::Thread &thr : core->threads) {
                    if (per_cpu_failures[thr.cpu()] && (pkg_failures[p] == -1)) {
                        last_bad_package = pkg->id();
                        failed_packages++;
                        pkg_failures[p] = pkg->id();
                    }
                }
            }
        }
        if (failed_packages == 1) {
            logging_printf(LOG_LEVEL_VERBOSE(1), "# - Failures localised to package %d\n", last_bad_package);
        } else {
            logging_printf(LOG_LEVEL_VERBOSE(1), "# - Failure detected on multiple packages:\n");
            for (int p : pkg_failures) {
                if (pkg_failures[p] >= 0)
                    logging_printf(LOG_LEVEL_VERBOSE(1), "#   - Package %d failed\n", p);
            }
        }
    } else {
        // valid topology, we can do more a interesting analysis
        logging_printf(LOG_LEVEL_VERBOSE(1), "# Topology analysis:\n");
        for (size_t p = 0; p < topology.packages.size(); ++p) {
            Topology::Package *pkg = &topology.packages[p];
            for (size_t c = 0; c < pkg->cores.size(); ++c) {
                Topology::Core *core = &pkg->cores[c];
                bool all_threads_failed_once = true;
                bool all_threads_failed_equally = true;
                int nthreads = 0;
                fail_pattern = 0;
                for (const Topology::Thread &thr : core->threads) {
                    auto this_pattern = per_cpu_failures[thr.cpu()];
                    if (this_pattern == 0)
                        all_threads_failed_once = false;
                    if (++nthreads == 1) {
                        // first thread of this core (maybe only)
                        fail_pattern = this_pattern;
                    } else {
                        if (this_pattern != fail_pattern)
                            all_threads_failed_equally = false;
                        if (this_pattern && !fail_pattern)
                            fail_pattern = this_pattern;
                    }
                }

                if (fail_pattern == 0) {
                    continue;       // no failure
                } else if (nthreads == 1) {
                    logging_printf(LOG_LEVEL_VERBOSE(1), "# - Only thread of package %d core %d\n",
                                   int(p), int(c));
                } else if (all_threads_failed_equally) {
                    logging_printf(LOG_LEVEL_VERBOSE(1), "# - All threads of package %d core %d failed exactly the same way\n",
                                   int(p), int(c));
                } else if (all_threads_failed_once) {
                    logging_printf(LOG_LEVEL_VERBOSE(1), "# - All threads of package %d core %d failed at least once\n",
                                   int(p), int(c));
                } else {
                    logging_printf(LOG_LEVEL_VERBOSE(1), "# - Some threads of package %d core %d failed but some others succeeded\n",
                                   int(p), int(c));
                }
            }
        }
    }
}

static TestResult
run_one_test(const test_cfg_info &test_cfg, SandstoneApplication::PerCpuFailures &per_cpu_fails)
{
    const struct test *test = test_cfg.test;
    TestResult state = TestResult::Skipped;
    int fail_count = 0;
    std::unique_ptr<char[]> random_allocation;
    MonotonicTimePoint first_iteration_target;
    bool auto_fracture = false;
    Duration runtime = 0ms;

    // resize and zero the storage
    if (per_cpu_fails.size() == num_cpus()) {
        std::fill_n(per_cpu_fails.begin(), num_cpus(), 0);
    } else {
        per_cpu_fails.clear();
        per_cpu_fails.resize(num_cpus(), 0);
    }
    auto mark_up_per_cpu_fail = [&per_cpu_fails, &fail_count](int i) {
        ++fail_count;
        if (i >= SandstoneApplication::MaxRetestCount)
            return;
        for_each_test_thread([&](PerThreadData::Test *data, int i) {
            using U = SandstoneApplication::PerCpuFailures::value_type;
            if (data->has_failed())
                per_cpu_fails[i] |= U(1) << i;
        });
    };

    sApp->current_test_duration = test_duration(test_cfg);
    first_iteration_target = MonotonicTimePoint::clock::now() + 10ms;

    if (test->fracture_loop_count) {
        // handled first, not overridable by --max-test-loop-count
        sApp->shmem->current_max_loop_count = test->fracture_loop_count;
    } else if (test->desired_duration == -1) {
        sApp->shmem->current_max_loop_count = -1;
    } else if (sApp->test_tests_enabled()) {
        // don't fracture in the test-the-test mode
        sApp->shmem->current_max_loop_count = -1;
    } else if (sApp->max_test_loop_count) {
        sApp->shmem->current_max_loop_count = sApp->max_test_loop_count;
    } else {
        /* for automatic fracture mode, do a 40 loop count */
        sApp->shmem->current_max_loop_count = 40;
        auto_fracture = true;
    }

    assert(sApp->retest_count >= 0);

    /* First we go to do our -- possibly fractured -- normal run, we'll do retries after */
    for (sApp->current_iteration_count = 0;; ++sApp->current_iteration_count) {

        //change frequency per fracture
        if (sApp->vary_frequency_mode == true)
            sApp->frequency_manager.change_core_frequency();

        //change uncore frequency per fracture
        if (sApp->vary_uncore_frequency_mode == true)
            sApp->frequency_manager.change_uncore_frequency();

        init_internal(test);

        // calculate starttime->endtime, reduce the overhead to have better test runtime calculations
        sApp->shmem->current_test_endtime =
                calculate_wallclock_deadline(sApp->current_test_duration - runtime,
                                             &sApp->current_test_starttime);
        state = run_one_test_once(test);
        runtime += MonotonicTimePoint::clock::now() - sApp->current_test_starttime;

        cleanup_internal(test);

        if ((sApp->shmem->current_max_loop_count > 0
             && MonotonicTimePoint::clock::now() < first_iteration_target && auto_fracture))
            sApp->shmem->current_max_loop_count *= 2;

        /* don't repeat skipped tests */
        if (state == TestResult::Skipped)
            goto out;

        if (state != TestResult::Passed) {
            // this counts as the first failure regardless of how many fractures we've run
            mark_up_per_cpu_fail(0);
            break;
        }

        // do we fracture?
        if (sApp->shmem->current_max_loop_count <= 0 || sApp->max_test_loop_count
                || (runtime >= sApp->current_test_duration))
            goto out;

        // Advance the random seed.
        random_advance_seed();
    }

    /* now we process retries */
    if (fail_count > 0) {
        // disable fracture
        if (sApp->shmem->current_max_loop_count > 0 &&
                sApp->shmem->current_max_loop_count != sApp->max_test_loop_count)
            sApp->shmem->current_max_loop_count = -1;

        int iterations;
        auto should_retry_test = [&]() {
            // allow testing double the regular count if we've only ever
            // failed once (the original run)
            if (sApp->total_retest_count == 0)
                return false;
            if (fail_count == 1)
                return iterations <= 2 * sApp->retest_count;
            return iterations <= sApp->retest_count;
        };
        for (iterations = 1; should_retry_test(); ++iterations) {
            // reset for the next retry iteration
            if (sApp->total_retest_count > 0)
                --sApp->total_retest_count;
            sApp->current_iteration_count = -iterations;
            init_internal(test);
            sApp->shmem->current_test_endtime =
                    calculate_wallclock_deadline(sApp->current_test_duration,
                                                 &sApp->current_test_starttime);
            state = run_one_test_once(test);
            cleanup_internal(test);

            if (state > TestResult::Passed)
                mark_up_per_cpu_fail(iterations);
        }

        analyze_test_failures(test, fail_count, iterations, per_cpu_fails);
        state = TestResult::Failed;
    }

out:
    //reset frequency level idx for the next test
    if (sApp->vary_frequency_mode || sApp->vary_uncore_frequency_mode)
        sApp->frequency_manager.reset_frequency_level_idx();

    random_advance_seed();      // advance seed for the next test
    logging_flush();
    return state;
}

static auto collate_test_groups()
{
    struct Group {
        const struct test_group *definition = nullptr;
        std::vector<const struct test *> entries;
    };
    std::map<std::string_view, Group> groups;
    for (const auto &ti : *test_set) {
        for (auto ptr = ti.test->groups; ptr && *ptr; ++ptr) {
            Group &g = groups[(*ptr)->id];
            g.definition = *ptr;
            g.entries.push_back(ti.test);
        }
    }

    return groups;
}

static void list_tests(int opt)
{
    bool include_tests = (opt != raw_list_groups);
    bool include_groups = (opt != raw_list_tests);
    bool include_descriptions = (opt == 'l');

    auto groups = collate_test_groups();
    int i = 0;

    for (const auto &ti : *test_set) {
        struct test *test = ti.test;
        if (test->quality_level >= sApp->requested_quality) {
            if (include_tests) {
                if (include_descriptions) {
                    printf("%i %-20s \"%s\"\n", ++i, test->id, test->description);
                } else if (sApp->shmem->verbosity > 0) {
                    // don't report the FW minimum CPU features
                    uint64_t cpuf = test->compiler_minimum_cpu & ~_compilerCpuFeatures;
                    cpuf |= test->minimum_cpu;
                    printf("%-20s %s\n", test->id, cpu_features_to_string(cpuf).c_str());
                } else {
                    puts(test->id);
                }
            }
        }
    }

    if (include_groups && !groups.empty()) {
        if (include_descriptions)
            printf("\nGroups:\n");
        for (auto pair : groups) {
            const auto &g = pair.second;
            if (include_descriptions) {
                printf("@%-21s \"%s\"\n", g.definition->id, g.definition->description);
                for (auto test : g.entries)
                    if (test->quality_level >= sApp->requested_quality)
                        printf("  %s\n", test->id);
            } else {
                // just the group name
                printf("@%s\n", g.definition->id);
            }
        }
    }
}

static void list_group_members(const char *groupname)
{
    auto groups = collate_test_groups();
    for (auto pair : groups) {
        const auto &g = pair.second;
        if (groupname[0] == '@' && strcmp(g.definition->id, groupname + 1) == 0) {
            for (auto test : g.entries)
                printf("%s\n", test->id);
            return;
        }
    }

    fprintf(stderr, "No such group '%s'\n", groupname);
    exit(EX_USAGE);
}

static bool should_start_next_iteration(void)
{
    static int iterations = 0;
    ++iterations;

    Duration elapsed_time = MonotonicTimePoint::clock::now() - sApp->starttime;
    Duration average_time(elapsed_time.count() / iterations);
    logging_printf(LOG_LEVEL_VERBOSE(2), "# Loop iteration %d finished, average time %g ms, total %g ms\n",
                   iterations, std::chrono::nanoseconds(average_time).count() / 1000. / 1000,
                   std::chrono::nanoseconds(elapsed_time).count() / 1000. / 1000);


    if (!sApp->shmem->use_strict_runtime) {
        /* do we have time for one more run? */
        MonotonicTimePoint end = sApp->endtime;
        if (end != MonotonicTimePoint::max())
            end -= average_time;
        if (wallclock_deadline_has_expired(end))
            return false;
    }
    /* start from the beginning again */
    restart_init(iterations);
    return true;
}

static SandstoneTestSet::EnabledTestList::iterator get_first_test()
{
    logging_print_iteration_start();
    auto it = test_set->begin();
    while (it != test_set->end() && (it->test->quality_level < 0 && sApp->requested_quality >= 0))
        ++it;
    return it;
}


static SandstoneTestSet::EnabledTestList::iterator
get_next_test(SandstoneTestSet::EnabledTestList::iterator next_test)
{
    if (sApp->shmem->use_strict_runtime && wallclock_deadline_has_expired(sApp->endtime))
        return test_set->end();

    ++next_test;
    while (next_test != test_set->end() && (next_test->test->quality_level < 0 && sApp->requested_quality >= 0))
        ++next_test;
    if (next_test == test_set->end()) {
        if (should_start_next_iteration()) {
            return get_first_test();
        } else {
            return test_set->end();
        }
    }

    assert(next_test->test->id);
    assert(next_test->test->description);
    assert(strlen(next_test->test->id));
    return next_test;
}

static bool wait_delay_between_tests()
{
    useconds_t useconds = duration_cast<microseconds>(sApp->delay_between_tests).count();
    // make the system call even if delay_between_tests == 0
    return usleep(useconds) == 0;
}

static int exec_mode_run(int argc, char **argv)
{
    if (argc < 4)
        return EX_DATAERR;

    auto parse_int = [](const char *arg) {
        char *end;
        long n = strtol(arg, &end, 10);
        if (__builtin_expect(int(n) != n || n < 0 || *end, false)) {
#if defined(_WIN32) && !defined(NDEBUG)
           if (*arg == 'h') {
               // a handle
               n = _open_osfhandle(strtoll(arg + 1, &end, 16), O_RDWR);
               if (n >= 0)
                   return int(n);
               perror("_open_osfhandle");
           }
#endif
            exit(EX_DATAERR);
        }
        return int(n);
    };
    int child_number = parse_int(argv[3]);

    attach_shmem(parse_int(argv[2]));
    cpu_info = sApp->shmem->cpu_info;
    sApp->thread_count = sApp->shmem->total_cpu_count;
    sApp->user_thread_data.resize(sApp->thread_count);

    test_set = new SandstoneTestSet({ .is_selftest = sApp->shmem->selftest, }, SandstoneTestSet::enable_all_tests);
    std::vector<struct test *> tests_to_run = test_set->lookup(argv[0]);
    if (tests_to_run.size() != 1) return EX_DATAERR;

    logging_init_global_child();
    random_init_global(argv[1]);

    return test_result_to_exit_code(child_run(tests_to_run.at(0), child_number));
}

namespace {
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
} // unnamed namespace

static auto parse_testrun_range(const char *arg, int &starting_test_number, int &ending_test_number)
{
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

static void warn_deprecated_opt(const char *opt)
{
    fprintf(stderr, "%s: option '%s' is ignored and will be removed in a future version.\n",
            program_invocation_name, opt);
}

/* Setup of the performance counters we read to get getloadavg() on linux. */
#ifdef _WIN32

/* We dynamically open pdh.dll because it's not always present in all Windows
   installations (notably lacking from WinPE). */
namespace {
struct PdhFunctions {
    decltype(&::PdhOpenQueryA) PdhOpenQueryA;
    decltype(&::PdhAddEnglishCounterA) PdhAddEnglishCounterA;
    decltype(&::PdhCollectQueryDataEx) PdhCollectQueryDataEx;
    decltype(&::PdhGetFormattedCounterValue) PdhGetFormattedCounterValue;

    bool load_library();
};
}
static PdhFunctions pdh;

/* Performance counters we are going to read */
static const char PQL_COUNTER_PATH[] = "\\System\\Processor Queue Length";
static HCOUNTER pql_counter;

static const char PT_COUNTER_PATH[]  = "\\Processor(_Total)\\% Processor Time";
static HCOUNTER pt_counter;


static constexpr unsigned TOTAL_5MIN_SAMPLES_COUNT = ((5u * 60u) / 5u);
static constexpr unsigned SAMPLE_INTERVAL_SECONDS = 5u;
static constexpr double   EXP_LOADAVG = exp(5.0 / (5.0 * 60.0)); // exp(5sec/5min)

static std::atomic<double> loadavg = 0.0;
static double last_tick_seconds;

bool PdhFunctions::load_library()
{
    HMODULE pdhDll = LoadLibraryExA("pdh.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!pdhDll)
        return false;

    auto getProc = [&](auto &pfn, const char *name) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
        pfn = reinterpret_cast<decltype(+pfn)>(GetProcAddress(pdhDll, name));
#pragma GCC diagnostic pop
        return pfn != nullptr;
    };

    if (getProc(PdhOpenQueryA, "PdhOpenQueryA")
            && getProc(PdhAddEnglishCounterA, "PdhAddEnglishCounterA")
            && getProc(PdhCollectQueryDataEx, "PdhCollectQueryDataEx")
            && getProc(PdhGetFormattedCounterValue, "PdhGetFormattedCounterValue"))
        return true;

    /* failed somehow */
    FreeLibrary(pdhDll);
    *this = {};
    return false;
}

static void loadavg_windows_callback(PVOID, BOOLEAN)
{
    PDH_FMT_COUNTERVALUE vpql, vpt;

    if (pdh.PdhGetFormattedCounterValue((PDH_HCOUNTER)pql_counter, PDH_FMT_DOUBLE, 0, &vpql) != ERROR_SUCCESS) {
        return;
    }

    if (pdh.PdhGetFormattedCounterValue((PDH_HCOUNTER)pt_counter, PDH_FMT_DOUBLE, 0, &vpt) != ERROR_SUCCESS) {
        return;
    }

    // We calculate current average load as average instantaenous cpu load plus amount of
    // tasks that are ready to run but cannot be scheduled because CPUs are already
    // running other tasks.
    //
    // We divide by 100.0 to get value in range (0.0;1.0) instead of percents.
    //
    // We also mutliply by number of cpus to make the metric behave more like the
    // /proc/loadavg from Linux, so we get value from range (0.0;num_cpus()), where
    // num_cpus() value means all cores at 100% utilization.
    const double current_avg_cpu_usage = (vpt.doubleValue * num_cpus() / 100.0);
    const double current_proc_queue    = vpql.doubleValue;
    const double current_avg_load      = current_avg_cpu_usage + current_proc_queue;

    // Calculate how many sample windows we missed and adjust.
    const double current_tick_seconds  = GetTickCount64() / 1000.0;
    const double tick_diff_seconds     = current_tick_seconds - last_tick_seconds;
    const double sample_windows_count  = tick_diff_seconds / static_cast<double>(SAMPLE_INTERVAL_SECONDS);
    const double efactor               = 1.0 / pow(EXP_LOADAVG, sample_windows_count);

    // Exponential moving average, but don't allow values outside of range (0.0;num_cpus()*2)
    double loadavg_ = loadavg.load(std::memory_order::relaxed);
    loadavg_ = loadavg_ * efactor + current_avg_load * (1.0 - efactor);
    loadavg_ = std::clamp(loadavg_, 0.0, static_cast<double>(num_cpus()*2));

    last_tick_seconds = current_tick_seconds;
    loadavg.store(loadavg_, std::memory_order::relaxed);
}

static int setup_windows_loadavg_perf_counters()
{
    HQUERY load_query;
    HANDLE load_event;

    if (!pdh.load_library()) {
        win32_perror("Failed to load pdh.dll to determine when the system is idle");
        return 1;
    }

    last_tick_seconds = GetTickCount64() / 1000.0;

    if (pdh.PdhOpenQueryA(NULL, 0, &load_query) != ERROR_SUCCESS) {
        win32_perror("PdhOpenQueryA");
        return 2;
    }

    if (pdh.PdhAddEnglishCounterA(load_query, PQL_COUNTER_PATH, 0, &pql_counter)) {
        win32_perror("PdhAddEnglishCounterA on Processor Queue Length");
        return 3;
    }

    if (pdh.PdhAddEnglishCounterA(load_query, PT_COUNTER_PATH, 0, &pt_counter)) {
        win32_perror("PdhAddEnglishCounterA on Processor Time");
        return 4;
    }

    load_event = CreateEventA(NULL, FALSE, FALSE, "AvgLoad5sEvent");
    if (load_event == NULL) {
        win32_perror("CreateEvent");
        return 5;
    }

    if (pdh.PdhCollectQueryDataEx(load_query, SAMPLE_INTERVAL_SECONDS, load_event) != ERROR_SUCCESS) {
        win32_perror("PdhCollectQueryDataEx");
        return 6;
    }

    HANDLE h; // Dummy handle, we don't ever use it, It's closed by the system when the program exits.
    const int register_callback_status =
        RegisterWaitForSingleObject(&h, load_event, (WAITORTIMERCALLBACK)loadavg_windows_callback, NULL, INFINITE, WT_EXECUTEDEFAULT);

    if (register_callback_status == 0) {
        win32_perror("RegisterWaitForSingleObject");
        return 7;
    }

    return 0;
}
#endif // _WIN32


static float system_idle_load()
{
#ifdef __linux__
    FILE *loadavg;
    float load_5;
    int ret;

    // Look at loadavg for hints whether the system is reasonably idle or not
    // any error and we assume it's busy/under load for simplicity

    loadavg = fopen("/proc/loadavg", "r");
    if (!loadavg)
        return std::numeric_limits<float>::infinity();

    ret = fscanf(loadavg, "%*f %f %*f", &load_5);
    fclose(loadavg);

    if (ret == 1)
       return load_5;
#elif defined(_WIN32)
    return loadavg.load(std::memory_order::relaxed);
#else //__linux__
    return std::numeric_limits<float>::lowest();
#endif

    // this shouldn't happen!
    // assume the system isn't idle
    return std::numeric_limits<float>::infinity();
}

static void background_scan_init()
{
    using namespace SandstoneBackgroundScanConstants;
    struct FileLayout {
        std::atomic<int> initialized;
        std::atomic<int> dummy;
        std::array<MonotonicTimePoint::rep, 24> timestamp;
    };

    if (!sApp->service_background_scan)
        return;

    void *memblock = MAP_FAILED;
    int prot = PROT_READ | PROT_WRITE;
    int fd = create_runtime_file("timestamps");
    if (fd >= 0 && ftruncate(fd, sizeof(FileLayout)) >= 0) {
        int flags = MAP_SHARED;
        memblock = mmap(nullptr, sizeof(FileLayout), prot, flags, fd, 0);
    }
    if (memblock == MAP_FAILED) {
        // create an anonymous block, since we can't have a file
        int flags = MAP_ANONYMOUS | MAP_PRIVATE;
        memblock = mmap(nullptr, sizeof(FileLayout), prot, flags, -1, 0);
    }

    auto file = new (memblock) FileLayout;
    sApp->background_scan.timestamp = {
        reinterpret_cast<MonotonicTimePoint *>(file->timestamp.data()), file->timestamp.size()
    };
    if (file->initialized.exchange(true, std::memory_order_relaxed) == false) {
        // init timestamps to more than the batch testing time - this quickstarts
        // testing on first run
        MonotonicTimePoint now = MonotonicTimePoint::clock::now();
        std::fill(sApp->background_scan.timestamp.begin(), sApp->background_scan.timestamp.end(),
                  now - DelayBetweenTestBatch);
    }

    if (fd >= 0)
        close(fd);

#ifdef _WIN32
    if (setup_windows_loadavg_perf_counters() != 0) {
        // If setting up performance counters fail, assume system is never idle.
        loadavg.store(std::numeric_limits<double>::infinity(), std::memory_order_relaxed);
    }
#endif // _WIN32
}

static void background_scan_update_load_threshold(MonotonicTimePoint now)
{
    using namespace SandstoneBackgroundScanConstants;

    hours time_from_last_test =
        duration_cast<hours>(now - sApp->background_scan.timestamp.front());

    // scale our idle threshold value from 0.2 base, to 0.8 after 12h
    // every hour adds 0.05 to the threshold value
    sApp->background_scan.load_idle_threshold =
        sApp->background_scan.load_idle_threshold_init +
        (time_from_last_test.count() * sApp->background_scan.load_idle_threshold_inc_val);

    // prevent the idle threshold form rising above 0.8
    if(sApp->background_scan.load_idle_threshold > sApp->background_scan.load_idle_threshold_max)
        sApp->background_scan.load_idle_threshold = sApp->background_scan.load_idle_threshold_max;
}

// Don't run tests unless load is low or it's time to run a test anyway
static bool background_scan_wait()
{
    auto as_seconds = [](Duration d) -> int { return duration_cast<seconds>(d).count(); };

    auto do_wait = [](Duration base_wait, Duration variable) -> bool {
        microseconds ubase = duration_cast<microseconds>(base_wait);
        microseconds uvar = duration_cast<microseconds>(variable);

        // randomize the delay by multiplying it between -1.0 and 1.0
        float random_factor = frandomf_scale(2.0) - 1.0f;
        auto deviation = duration_cast<microseconds>(uvar * random_factor);
        microseconds sleep_time = ubase + deviation;

        return usleep(sleep_time.count()) == 0;
    };
    using namespace SandstoneBackgroundScanConstants;

    // move all timestaps except the oldest one
    auto array_data = sApp->background_scan.timestamp.data();
    std::move(array_data, array_data + sApp->background_scan.timestamp.size() - 1,
              array_data + 1);

    MonotonicTimePoint now = MonotonicTimePoint::clock::now();
    sApp->background_scan.timestamp.front() = now;

    // Don't run too many tests in a short period of time
    Duration elapsed = now - sApp->background_scan.timestamp.back();
    if (Duration expected_start = DelayBetweenTestBatch - elapsed; expected_start > 0s) {
        expected_start += MinimumDelayBetweenTests;
        logging_printf(LOG_LEVEL_VERBOSE(2), "# Background scan: %zu tests completed in "
                                             "%d s, waiting %d +/- %d s\n",
                       sApp->background_scan.timestamp.size(), as_seconds(elapsed),
                       as_seconds(expected_start), as_seconds(MinimumDelayBetweenTests));
        if (!do_wait(expected_start, MinimumDelayBetweenTests)) {
            return false;
        }
        goto skip_wait;
    }

    logging_printf(LOG_LEVEL_VERBOSE(3), "# Background scan: waiting %d +/- 10%% s\n",
                   as_seconds(MinimumDelayBetweenTests));
    while (1) {
        if (!do_wait(MinimumDelayBetweenTests, MinimumDelayBetweenTests / 10)) {
            return false;
        }

skip_wait:
        now = MonotonicTimePoint::clock::now();
        background_scan_update_load_threshold(now);

        // if the system is idle, run a test
        float idle_load = system_idle_load();
        if (idle_load < sApp->background_scan.load_idle_threshold) {
            logging_printf(LOG_LEVEL_VERBOSE(2), "# Background scan: system is sufficiently idle "
                                                 "(%.2f; below %.2f), executing next test\n",
                           idle_load, sApp->background_scan.load_idle_threshold);
            break;
        }

        // if we haven't run *any* tests in the last x hours, run a test
        // because of day/night cycles, 12 hours should help typical data center
        // duty cycles.
        if (now > (sApp->background_scan.timestamp.front() + MaximumDelayBetweenTests)) {
            logging_printf(LOG_LEVEL_VERBOSE(2), "# Background scan: system has gone too long"
                                                 " without a test -- forcing one now\n");
            break;
        }

        logging_printf(LOG_LEVEL_VERBOSE(3), "# Background scan: system is not idle "
                                             "(%.2f; above %.2f), waiting %d +/- 10%% s\n",
                       idle_load, sApp->background_scan.load_idle_threshold,
                       as_seconds(MinimumDelayBetweenTests));
    }
    return true;
}

extern constexpr const uint64_t minimum_cpu_features = _compilerCpuFeatures;
int main(int argc, char **argv)
{
    // initialize the main application
    new (sApp) SandstoneApplication;

    static struct option long_options[]  = {
        { "1sec", no_argument, nullptr, one_sec_option },
        { "30sec", no_argument, nullptr, thirty_sec_option },
        { "2min", no_argument, nullptr, two_min_option },
        { "5min", no_argument, nullptr, five_min_option },
        { "alpha", no_argument, &sApp->requested_quality, INT_MIN },
        { "beta", no_argument, &sApp->requested_quality, 0 },
        { "cpuset", required_argument, nullptr, cpuset_option },
        { "cpujump", no_argument, nullptr, cpujump_option },
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
        { "synchronize-threads", required_argument, nullptr, synchronize_threads_option },
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

    const char *seed = nullptr;
    int max_cores_per_slice = 0;
    int opt;
    int total_failures = 0;
    int total_successes = 0;
    int total_skips = 0;
    int thread_count = -1;
    bool fatal_errors = false;
    const char *on_hang_arg = nullptr;
    const char *on_crash_arg = nullptr;

    // test selection
    std::vector<const char *> enabled_tests;
    std::vector<const char *> disabled_tests;
    const char *test_list_file_path = nullptr;

    struct test_set_cfg test_set_config = {
        .ignore_unknown_tests = false,
        .randomize = false,
        .cycle_through = false,
    };
    const char *builtin_test_list_name = nullptr;
    int starting_test_number = 1;  // One based count for user interface, not zero based
    int ending_test_number = INT_MAX;

    thread_num = -1;            /* indicate main thread */
    find_thyself(argv[0]);
    setup_stack_size(argc, argv);
#ifdef __linux__
    prctl(PR_SET_TIMERSLACK, 1, 0, 0, 0);
#endif

    if (argc > 1 && strcmp(argv[1], "-x") == 0) {
        /* exec mode is when a brand new child is launched for each test, as opposed to
         * just forked. set when the child is launched with '-x' option by the parent
         * running with '-f exec' or on Windows. */
        sApp->fork_mode = SandstoneApplication::child_exec_each_test;

        return exec_mode_run(argc - 2, argv + 2);
    }

    {
        LogicalProcessorSet enabled_cpus = init_cpus();
        init_shmem();
        init_topology(std::move(enabled_cpus));
    }

    int coptind = -1;

    while (!SandstoneConfig::RestrictedCommandLine &&
           (opt = simple_getopt(argc, argv, long_options, &coptind)) != -1) {
        switch (opt) {
        case disable_option:
            disabled_tests.push_back(optarg);
            break;
        case 'e':
            enabled_tests.push_back(optarg);
            break;
        case 'f':
            if (strcmp(optarg, "no") == 0 || strcmp(optarg, "no-fork") == 0) {
                sApp->fork_mode = SandstoneApplication::no_fork;
            } else if (!strcmp(optarg, "exec")) {
                sApp->fork_mode = SandstoneApplication::exec_each_test;
#ifndef _WIN32
            } else if (strcmp(optarg, "yes") == 0 || strcmp(optarg, "each-test") == 0) {
                sApp->fork_mode = SandstoneApplication::fork_each_test;
#endif
            } else {
                fprintf(stderr, "%s: unknown option to -f: %s\n", argv[0], optarg);
                usage(argv);
                return EX_USAGE;
            }
            break;
        case 'F':
            fatal_errors = true;
            break;
        case 'h':
            usage(argv);
            return EXIT_SUCCESS;
        case 'l':
        case raw_list_tests:
        case raw_list_groups:
            test_set = new SandstoneTestSet(test_set_config, SandstoneTestSet::enable_all_tests);
            list_tests(opt);
            return EXIT_SUCCESS;
        case raw_list_group_members:
            test_set = new SandstoneTestSet(test_set_config, SandstoneTestSet::enable_all_tests);
            list_group_members(optarg);
            return EXIT_SUCCESS;
        case 'n':
            thread_count = ParseIntArgument<>{
                    .name = "-n / --threads",
                    .min = 1,
                    .max = sApp->thread_count,
                    .range_mode = OutOfRangeMode::Saturate
            }();
            break;
        case 'o':
            sApp->file_log_path = optarg;
            break;
        case 'O':
            sApp->shmem->log_test_knobs = true;
            if ( ! set_knob_from_key_value_string(optarg)){
                fprintf(stderr, "Malformed test knob: %s (should be in the form KNOB=VALUE)\n", optarg);
                return EX_USAGE;
            }
            break;

        case 'q':
            sApp->shmem->verbosity = 0;
            break;
        case 's':
            seed = optarg;
            break;
        case 't':
            sApp->test_time = string_to_millisecs(optarg);
            break;
        case force_test_time_option: /* overrides max and min duration specified by the test */
            sApp->force_test_time = true;
            break;
        case 'T':
            if (strcmp(optarg, "forever") == 0) {
                sApp->endtime = MonotonicTimePoint::max();
            } else {
                sApp->endtime = sApp->starttime + string_to_millisecs(optarg);
            }
            test_set_config.cycle_through = true; /* Time controls when the execution stops as
                                                     opposed to the number of tests. */
            break;
        case 'v':
            if (sApp->shmem->verbosity < 0)
                sApp->shmem->verbosity = 1;
            else
                ++sApp->shmem->verbosity;
            break;
        case 'Y':
            sApp->shmem->output_format = SandstoneApplication::OutputFormat::yaml;
            if (optarg)
                sApp->shmem->output_yaml_indent = ParseIntArgument<>{
                        .name = "-Y / --yaml",
                        .max = 160,     // arbitrary
                }();
            break;
        case cpuset_option:
            apply_cpuset_param(optarg);
            break;
        case cpujump_option:
            sApp->cpujump = true;
            break;
        case dump_cpu_info_option:
            dump_cpu_info();
            return EXIT_SUCCESS;
        case fatal_skips_option:
            sApp->fatal_skips = true;
            break;
#ifndef NDEBUG
        case gdb_server_option:
            sApp->gdb_server_comm = optarg;
            break;
#endif
        case ignore_os_errors_option:
            sApp->ignore_os_errors = true;
            break;
        case ignore_unknown_tests_option:
            test_set_config.ignore_unknown_tests = true;
            break;
        case is_asan_option:
        case is_debug_option:
            // these options are only accessible in the command-line if the
            // corresponding functionality is active
            return EXIT_SUCCESS;
        case max_cores_per_slice_option:
            max_cores_per_slice = ParseIntArgument<>{
                    .name = "--max-cores-per-slice",
                    .min = -1,
                }();
            break;
        case mce_check_period_option:
            sApp->mce_check_period = ParseIntArgument<>{"--mce-check-every"}();
            break;
        case no_slicing_option:
            max_cores_per_slice = -1;
            break;
        case on_crash_option:
            on_crash_arg = optarg;
            break;
        case on_hang_option:
            on_hang_arg = optarg;
            break;
        case output_format_option:
            if (strcmp(optarg, "key-value") == 0) {
                sApp->shmem->output_format = SandstoneApplication::OutputFormat::key_value;
            } else if (strcmp(optarg, "tap") == 0) {
                sApp->shmem->output_format = SandstoneApplication::OutputFormat::tap;
            } else if (strcmp(optarg, "yaml") == 0) {
                sApp->shmem->output_format = SandstoneApplication::OutputFormat::yaml;
            } else if (SandstoneConfig::Debug && strcmp(optarg, "none") == 0) {
                // for testing only
                sApp->shmem->output_format = SandstoneApplication::OutputFormat::no_output;
                sApp->shmem->verbosity = -1;
            } else {
                fprintf(stderr, "%s: unknown output format: %s\n", argv[0], optarg);
                return EX_USAGE;
            }
            break;

        case quality_option:
            sApp->requested_quality = ParseIntArgument<>{
                    .name = "--quality",
                    .min = -1000,
                    .max = +1000,
                    .range_mode = OutOfRangeMode::Saturate
            }();
            break;

        case quick_run_option:
            sApp->max_test_loop_count = 1;
            sApp->delay_between_tests = 0ms;
            break;
        case retest_on_failure_option:
            sApp->retest_count = ParseIntArgument<>{
                    .name = "--retest-on-failure",
                    .max = SandstoneApplication::MaxRetestCount,
                    .range_mode = OutOfRangeMode::Saturate
            }();
            break;
        case strict_runtime_option:
            sApp->shmem->use_strict_runtime = true;
            break;
        case synchronize_threads_option:
            if (std::string_view(optarg) == "barrier") {
                sApp->thread_synchronization = new BarrierThreadSynchronization;
            } else if (std::string_view(optarg) == "futex") {
                sApp->thread_synchronization = new FutexThreadSynchronization;
#ifdef __x86_64__
            } else if (std::string_view(optarg) == "tpause") {
                sApp->thread_synchronization = new TPauseThreadSynchronization;
            } else if (std::string_view(optarg) == "umwait") {
                sApp->thread_synchronization = new UMWaitThreadSynchronization;
#endif
            } else {
                fprintf(stderr, "%s: invalid option --synchronize-threads=%s. Valid options are: barrier, futex"
#ifdef __x86_64__
                                ", tpause, umwait"
#endif
                                "\n", argv[0], optarg);
                return EX_USAGE;
            }
            break;
        case syslog_runtime_option:
            sApp->syslog_ident = program_invocation_name;
            break;
#ifndef NO_SELF_TESTS
        case selftest_option:
            if (sApp->requested_quality != SandstoneApplication::DefaultQualityLevel) {
                fprintf(stderr, "%s: --selftest is incompatible with --beta or --quality.\n", argv[0]);
                return EX_USAGE;
            }
            sApp->requested_quality = 0;
            sApp->shmem->selftest = true;
            test_set_config.is_selftest = true;
            break;
#endif
        case service_option:
            // keep in sync with RestrictedCommandLine below
            fatal_errors = true;
            sApp->endtime = MonotonicTimePoint::max();
            sApp->service_background_scan = true;
            break;
        case ud_on_failure_option:
            sApp->shmem->ud_on_failure = true;
            break;
        case use_builtin_test_list_option:
            if (!SandstoneConfig::HasBuiltinTestList) {
                fprintf(stderr, "%s: --use-builtin-test-list specified but this build does not "
                                "have a built-in test list.\n", argv[0]);
                return EX_USAGE;
            }
            builtin_test_list_name = optarg ? optarg : "auto";
            break;
        case temperature_threshold_option:
            if (strcmp(optarg, "disable") == 0)
                sApp->thermal_throttle_temp = -1;
            else
                sApp->thermal_throttle_temp = ParseIntArgument<>{
                        .name = "--temperature-threshold",
                        .explanation = "value should be specified in thousandths of degrees Celsius "
                                       "(for example, 85000 is 85 degrees Celsius), or \"disable\" "
                                       "to disable monitoring",
                        .max = 160000,      // 160 C is WAAAY too high anyway
                        .range_mode = OutOfRangeMode::Saturate
                }();
            break;

        case test_delay_option:
            sApp->delay_between_tests = string_to_millisecs(optarg);
            break;

        case test_tests_option:
            sApp->enable_test_tests();
            if (sApp->test_tests_enabled()) {
                // disable other options that don't make sense in this mode
                sApp->retest_count = 0;
            }
            break;

        case timeout_option:
            sApp->max_test_time = string_to_millisecs(optarg);
            break;

        case total_retest_on_failure:
            sApp->total_retest_count = ParseIntArgument<>{
                    .name = "--total-retest-on-failure",
                    .min = -1
            }();
            break;

        case test_list_file_option:
            test_list_file_path = optarg;
            break;

        case test_index_range_option:
            if (parse_testrun_range(optarg, starting_test_number, ending_test_number) == EXIT_FAILURE)
                return EX_USAGE;
            break;

        case test_list_randomize_option:
            test_set_config.randomize = true;
            break;

        case max_logdata_option: {
            sApp->shmem->max_logdata_per_thread = ParseIntArgument<unsigned>{
                    .name = "--max-logdata",
                    .explanation = "maximum number of bytes of test's data to log per thread (0 is unlimited))",
                    .base = 0,      // accept hex
                    .range_mode = OutOfRangeMode::Saturate
            }();
            if (sApp->shmem->max_logdata_per_thread == 0)
                sApp->shmem->max_logdata_per_thread = UINT_MAX;
            break;
        }
        case max_messages_option:
            sApp->shmem->max_messages_per_thread = ParseIntArgument<>{
                    .name = "--max-messages",
                    .explanation = "maximum number of messages (per thread) to log in each test (0 is unlimited)",
                    .min = -1,
                    .range_mode = OutOfRangeMode::Saturate
            }();
            if (sApp->shmem->max_messages_per_thread <= 0)
                sApp->shmem->max_messages_per_thread = INT_MAX;
            break;

        case vary_frequency:
            if (!FrequencyManager::FrequencyManagerWorks) {
                fprintf(stderr, "%s: --vary-frequency works only on Linux\n", program_invocation_name);
                return EX_USAGE;
            }
            sApp->vary_frequency_mode = true;
            break;

        case vary_uncore_frequency:
            if (!FrequencyManager::FrequencyManagerWorks) {
                fprintf(stderr, "%s: --vary-uncore-frequency works only on Linux\n", program_invocation_name);
                return EX_USAGE;
            }
            sApp->vary_uncore_frequency_mode = true;
            break;

        case version_option:
            logging_print_version();
            return EXIT_SUCCESS;
        case one_sec_option:
            test_set_config.randomize = true;
            test_set_config.cycle_through = true;
            sApp->shmem->use_strict_runtime = true;
            sApp->endtime = sApp->starttime + 1s;
            break;
        case thirty_sec_option:
            test_set_config.randomize = true;
            test_set_config.cycle_through = true;
            sApp->shmem->use_strict_runtime = true;
            sApp->endtime = sApp->starttime + 30s;
            break;
        case two_min_option:
            test_set_config.randomize = true;
            test_set_config.cycle_through = true;
            sApp->shmem->use_strict_runtime = true;
            sApp->endtime = sApp->starttime + 2min;
            break;
        case five_min_option:
            test_set_config.randomize = true;
            test_set_config.cycle_through = true;
            sApp->shmem->use_strict_runtime = true;
            sApp->endtime = sApp->starttime + 5min;
            break;

        case max_test_count_option:
            sApp->max_test_count = ParseIntArgument<>{"--max-test-count"}();
            break;

        case max_test_loop_count_option:
            sApp->max_test_loop_count = ParseIntArgument<>{"--max-test-loop-count"}();
            if (sApp->max_test_loop_count == 0)
                    sApp->max_test_loop_count = std::numeric_limits<int>::max();
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

    if (SandstoneConfig::RestrictedCommandLine) {
        // Default options for the simplified OpenDCDiag cmdline
        static struct option restricted_long_options[] = {
            { "help", no_argument, nullptr, 'h' },
            { "query", no_argument, nullptr, 'q' },
            { "service", no_argument, nullptr, 's' },
            { "version", no_argument, nullptr, version_option },
            { nullptr, 0, nullptr, 0 }
        };

        while ((opt = simple_getopt(argc, argv, restricted_long_options)) != -1) {
            switch (opt) {
            case 'q':
                // ### FIXME
                fprintf(stderr, "%s: --query not implemented yet\n", argv[0]);
                abort();
            case 's':
                // keep in sync above
                sApp->endtime = MonotonicTimePoint::max();
                sApp->service_background_scan = true;
                break;
            case version_option:
                logging_print_version();
                return EXIT_SUCCESS;

            case 'h':
                usage(argv);
                return opt == 'h' ? EXIT_SUCCESS : EX_USAGE;
            default:
                suggest_help(argv);
                return EX_USAGE;
            }
        }

        if (SandstoneConfig::NoLogging) {
            sApp->shmem->output_format = SandstoneApplication::OutputFormat::no_output;
        } else  {
            sApp->shmem->verbosity = 1;
        }

        sApp->delay_between_tests = 50ms;
        sApp->thermal_throttle_temp = INT_MIN;
        fatal_errors = true;
        builtin_test_list_name = "auto";

        static_assert(!SandstoneConfig::RestrictedCommandLine || SandstoneConfig::HasBuiltinTestList,
                "Restricted command-line build must have a built-in test list");
    }

    if (optind < argc) {
        usage(argv);
        return EX_USAGE;
    }
    if (sApp->shmem->log_test_knobs && sApp->current_fork_mode() == SandstoneApplication::exec_each_test) {
        fprintf(stderr, "%s: error: --test-option is not supported in this configuration\n",
                program_invocation_name);
        return EX_USAGE;
    }

    if (sApp->total_retest_count < -1 || sApp->retest_count == 0)
        sApp->total_retest_count = 10 * sApp->retest_count; // by default, 100

    if (unsigned(thread_count) < unsigned(sApp->thread_count))
        restrict_topology({ 0, thread_count });
    slice_plan_init(max_cores_per_slice);
    commit_shmem();

    signals_init_global();
    resource_init_global();
    debug_init_global(on_hang_arg, on_crash_arg);
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, nullptr);

    print_application_banner();
    logging_init_global();
    cpu_specific_init();
    random_init_global(seed);
    background_scan_init();

    if (enabled_tests.size() || builtin_test_list_name || test_list_file_path) {
        /* if anything other than the "all tests" has been specified, start with
         * an empty list. */
        test_set = new SandstoneTestSet(test_set_config, 0);
    } else {
        /* otherwise, start with all the applicable tests (self tests or
         * regular. */
        test_set = new SandstoneTestSet(test_set_config, SandstoneTestSet::enable_all_tests);
    }

    /* Add all the tests we were told to enable. */
    if (enabled_tests.size()) {
        for (auto name : enabled_tests) {
            auto tis = test_set->add(name);
            if (!tis.size() && !test_set_config.ignore_unknown_tests) {
                fprintf(stderr, "%s: Cannot find matching tests for '%s'\n", program_invocation_name, name);
                exit(EX_USAGE);
            }
        }
    }

    /* Add the test list file */
    if (test_list_file_path) {
        std::vector<std::string> errors;
        test_set->add_test_list(test_list_file_path, errors);
        if (!errors.empty()) {
            fprintf(stderr, "Error loading test list file %s:\n", test_list_file_path);
            for (auto i = errors.begin(); i != errors.end(); i++) {
                fprintf(stderr, "    %s\n", (*i).c_str());
            }
            exit(EX_USAGE);
        }
    }

    if (builtin_test_list_name) {
        std::vector<std::string> errors;
        test_set->add_builtin_test_list(builtin_test_list_name, errors);
        if (!errors.empty()) {
            // FIXME: handle errors
            ;
            exit(EX_USAGE);
        }
    }


    /* Add mce_check as the last test to the set. It will be kept last by
     * SandstoneTestSet in case randomization is requested. */
    test_set->add(&mce_test);

    /* Remove all the tests we were told to disable */
    if (disabled_tests.size()) {
        for (auto name : disabled_tests) {
            test_set->remove(name);
        }
    }

    if (sApp->shmem->verbosity == -1)
        sApp->shmem->verbosity = (sApp->requested_quality < SandstoneApplication::DefaultQualityLevel) ? 1 : 0;

    if (InterruptMonitor::InterruptMonitorWorks && test_set->contains(&mce_test)) {
        sApp->last_thermal_event_count = sApp->count_thermal_events();
        sApp->mce_counts_start = sApp->get_mce_interrupt_counts();

        if (sApp->current_fork_mode() == SandstoneApplication::exec_each_test) {
            test_set->remove(&mce_test);
        } else if (sApp->mce_counts_start.empty()) {
            logging_printf(LOG_LEVEL_QUIET, "# WARNING: Cannot detect MCE events - you may be running in a VM - MCE checking disabled\n");
            test_set->remove(&mce_test);
        }

        sApp->mce_count_last = std::accumulate(sApp->mce_counts_start.begin(), sApp->mce_counts_start.end(), uint64_t(0));
    }

    //if --vary-frequency mode is used, do a initial setup for running different frequencies
    if (sApp->vary_frequency_mode)
        sApp->frequency_manager.initial_core_frequency_setup();

    //if --vary-uncore-frequency mode is used, do a initial setup for running different frequencies
    if (sApp->vary_uncore_frequency_mode)
        sApp->frequency_manager.initial_uncore_frequency_setup();

    /* CPU jump is only available with 2 or more threads
       This may change in the near future */
    if (sApp->cpujump ) {
        if (sApp->thread_count % 2 != 0) {
        fprintf(stderr, "%s: --cpujump requires an even number of threads\n", argv[0]);
        exit(EX_USAGE);
        }

        // Setup cpujump info
        sApp->cpujump_vec.resize(sApp->thread_count);
        for (int i = 0; i < sApp->thread_count; i+=2) {
            pthread_barrier_t *barrier = new pthread_barrier_t;
            pthread_barrier_init(barrier, nullptr, sApp->members_per_barrier);

            logging_printf(LOG_LEVEL_VERBOSE(1) , "Creating cpujump struct %d\n", i);
            sApp->cpujump_vec[i] = new CPUJump;
            sApp->cpujump_vec[i]->barrier = barrier;
            sApp->cpujump_vec[i]->current_cpu = cpu_info[i].cpu_number;
            sApp->cpujump_vec[i]->next_cpu = cpu_info[i+1].cpu_number;

            sApp->cpujump_vec[i+1] = new CPUJump;
            sApp->cpujump_vec[i+1]->barrier = barrier;
            sApp->cpujump_vec[i+1]->current_cpu = cpu_info[i+1].cpu_number;
            sApp->cpujump_vec[i+1]->next_cpu = cpu_info[i].cpu_number;

            //logging_printf(LOG_LEVEL_VERBOSE(1) , "Current CPU: %d, Next CPU: %d\n", sApp->cpujump_vec[i]->current_cpu, sApp->cpujump_vec[i]->next_cpu);
            //logging_printf(LOG_LEVEL_VERBOSE(1) , "Current CPU: %d, Next CPU: %d\n", sApp->cpujump_vec[i+1]->current_cpu, sApp->cpujump_vec[i+1]->next_cpu);
        }
    }

#ifndef __OPTIMIZE__
    logging_printf(LOG_LEVEL_VERBOSE(1), "THIS IS AN UNOPTIMIZED BUILD: DON'T TRUST TEST TIMING!\n");
#endif

#if SANDSTONE_SSL_BUILD
    if (SANDSTONE_SSL_LINKED || sApp->current_fork_mode() != SandstoneApplication::exec_each_test) {
        sandstone_ssl_init();
        sandstone_ssl_rand_init();
    }
#endif

    logging_print_header(argc, argv, test_duration(), test_timeout(test_duration()));

    SandstoneApplication::PerCpuFailures per_cpu_failures;

    sApp->current_test_count = 0;
    int total_tests_run = 0;
    TestResult lastTestResult = TestResult::Skipped;

    initialize_smi_counts();  // used by smi_count test

    for (auto it = get_first_test(); it != test_set->end(); it = get_next_test(it)) {
        if (lastTestResult != TestResult::Skipped) {
            if (sApp->service_background_scan) {
                if (!background_scan_wait()) {
                    logging_printf(LOG_LEVEL_VERBOSE(2), "# Background scan: waiting between tests interrupted\n");
                    break;
                }
            } else {
                if (!wait_delay_between_tests()) {
                    logging_printf(LOG_LEVEL_VERBOSE(2), "# Test execution interrupted between tests\n");
                    break;
                }
            }
        }

        lastTestResult = run_one_test(*it, per_cpu_failures);

        total_tests_run++;
        if (lastTestResult == TestResult::Failed) {
            ++total_failures;
            if (fatal_errors)
                break;
        } else if (lastTestResult == TestResult::Passed) {
            ++total_successes;
        } else if (lastTestResult == TestResult::Skipped) {
            ++total_skips;
            if (sApp->fatal_skips)
                break;
        }
        if (total_tests_run >= sApp->max_test_count)
            break;
    }

    if (total_failures) {
        logging_print_footer();
    } else if (sApp->shmem->verbosity == 0 && sApp->shmem->output_format == SandstoneApplication::OutputFormat::tap) {
        logging_printf(LOG_LEVEL_QUIET, "Ran %d tests without error (%d skipped)\n",
                       total_successes, total_tests_run - total_successes);
    }

    int exit_code = EXIT_SUCCESS;
    if (total_failures || (total_skips && sApp->fatal_skips))
        exit_code = EXIT_FAILURE;

    if (sApp->cpujump ) {
        for (int i = 0; i < sApp->thread_count; i+=2) {
            delete sApp->cpujump_vec[i]->barrier;
            delete sApp->cpujump_vec[i];
            delete sApp->cpujump_vec[i+1];
        }
    }

    // done running all the tests, clean up and exit
    return cleanup_global(exit_code, std::move(per_cpu_failures));
}
