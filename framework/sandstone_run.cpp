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

#include "sandstone.h"
#include "sandstone_p.h"
#include "sandstone_system.h"
#include "sandstone_thread.h"
#include "sandstone_tests.h"
#include "sandstone_utils.h"
#include "forkfd.h"
#include "interrupt_monitor.hpp"
#include "topology.h"
#if SANDSTONE_DEVICE_CPU
#   include "effective_cpu_freq.hpp"
#endif

#include <chrono>
#include <map>
#include <vector>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#if __has_include(<malloc.h>)
#  include <malloc.h>
#endif
#include <stdio.h>
#include <string.h>
#ifdef __unix__
#  include <poll.h>
#endif
#include <pthread.h>
#include <stdint.h>
#if __has_include(<sys/auxv.h>)         // FreeBSD and Linux
#  include <sys/auxv.h>
#endif
#ifdef __linux__
#  include <sys/eventfd.h>
#  include <sys/types.h>
#endif
#ifdef __unix__
#  include <sys/resource.h>
#endif
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef _WIN32
#  include <ntstatus.h>
#  include <shlwapi.h>
#  include <windows.h>
#  include <psapi.h>
#endif

#ifndef O_PATH
#  define O_PATH        0
#endif
#ifndef O_CLOEXEC
#  define O_CLOEXEC     0
#endif
#ifndef S_IRWXU
#  define S_IRWXU       0700
#endif

using namespace std;
using namespace std::chrono;
using namespace std::chrono_literals;

#ifndef __GLIBC__
char *program_invocation_name;
#endif

device_features_t device_features;

static const struct test *current_test = nullptr;
#ifdef __llvm__
thread_local int thread_num __attribute__((tls_model("initial-exec")));
#else
thread_local int thread_num = 0;
#endif

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

int test_result_to_exit_code(TestResult result)
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

static void merge_test_result(ChildExitStatus &current, ChildExitStatus incoming)
{
    // don't decrease a previously-stored severity
    if (current.result < incoming.result)
        current = incoming;
    current.endtime = MonotonicTimePoint::clock::now();
}

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
    if (sApp->shmem->cfg.ud_on_failure)
        ud2();

    if (!SandstoneConfig::NoLogging)
        log_error("Failed at %s:%d", file, line);
    report_fail_common();
}

void _report_fail_msg(const char *file, int line, const char *fmt, ...)
{
    /* Keep this very early */
    if (sApp->shmem->cfg.ud_on_failure)
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

#ifndef NDEBUG
bool _memcmp_or_fail_check_fmt_nonewline(const char *fmt, ...)
{
    bool ok = true;
    size_t size = 256;
    while (fmt) {
        char buf[size];  // nowarn: -Wvla-cxx-extension, -Wvla
        va_list va;
        va_start(va, fmt);
        int n = vsnprintf(buf, size, fmt, va);
        va_end(va);
        if (n < size) {
            ok = strchr(buf, '\n') == nullptr;
            break;
        }

        // insufficient buffer, try again
        size = n;
    }
    return ok;
}
#endif

void _memcmp_fail_report(const void *_actual, const void *_expected, size_t size, DataType type, const char *fmt, ...)
{
    // Execute UD2 early if we've failed
    if (sApp->shmem->cfg.ud_on_failure)
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

inline void test_the_test_data<true>::prepare_test_tests(const struct test *the_test)
{
    if (!shouldTestTheTest(the_test))
        return;

    hwm_at_start = memfpt_current_high_water_mark();
    per_thread.resize(thread_count());
    std::fill_n(per_thread.begin(), thread_count(), PerThread{});
}

inline void test_the_test_data<true>::test_tests_iteration(const struct test *the_test)
{
    if (!shouldTestTheTest(the_test))
        return;

    int n = sApp->test_thread_data(thread_num)->inner_loop_count;
    if (n >= DesiredIterations)
        return;

    auto &me = per_thread[thread_num];
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
        size_t per_thread_avg = (current_hwm - hwm_at_start) / thread_count();
        if (per_thread_avg < MaxAcceptableMemoryUseKB)
            log_info("Test memory use: (%zu - %zu) / %d = %zu kB",
                     current_hwm, hwm_at_start, thread_count(), per_thread_avg);
        else
            maybe_log_error(test_flag_ignore_memory_use,
                            "Test uses too much memory: (%zu - %zu) / %d = %zu kB",
                            current_hwm, hwm_at_start, thread_count(), per_thread_avg);
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

    if (sApp->shmem->current_test_endtime == MonotonicTimePoint::max() || the_test->desired_duration < 0) {
        return;
    }

    // check the overall time
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
    log_info("Sampled init timing: %s", format_duration(sApp->current_test_starttime_at_run - sApp->current_test_starttime).c_str());
    for (int t = 0; t < thread_count(); ++t) {
        PerThread &thr = per_thread[t];
        if (thr.iteration_times[0].time_since_epoch().count() == 0)
            continue;

        std::array<Duration, DesiredIterations> iteration_times = {};
        if (sApp->current_test_starttime_at_run_first_loop.time_since_epoch() > 0s) {
            iteration_times[0] = thr.iteration_times[0] - sApp->current_test_starttime_at_run_first_loop;
            log_message(t, SANDSTONE_LOG_DEBUG "Sampled full 1st iteration timing: %s",
                format_duration(thr.iteration_times[0] - sApp->current_test_starttime_at_run).c_str());
        } else { // no TEST_LOOP in test - no timing of additional run() overhead
            iteration_times[0] = thr.iteration_times[0] - sApp->current_test_starttime_at_run;
        }
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

        log_message(t, SANDSTONE_LOG_DEBUG "Sampled iteration timings: %s, %s, %s, %s",
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
        for (int t = 0; average_counts != thread_count() && t < thread_count(); ++t) {
            PerThread &thr = per_thread[t];
            if (thr.iteration_times[0].time_since_epoch().count() == 0)
                log_message(t, SANDSTONE_LOG_WARNING "run() function did not call test_time_condition() in this thread");
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

#undef maybe_log_error
}

static MonotonicTimePoint calculate_wallclock_deadline(Duration duration, MonotonicTimePoint *pnow = nullptr)
{
    MonotonicTimePoint later = MonotonicTimePoint::clock::now();
    if (pnow)
        *pnow = later;

    return later + duration;
}

bool wallclock_deadline_has_expired(MonotonicTimePoint deadline)
{
    MonotonicTimePoint now = MonotonicTimePoint::clock::now();

    if (now > deadline)
        return true;
    if (sApp->shmem->cfg.use_strict_runtime && now > sApp->endtime)
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

    return !wallclock_deadline_has_expired(sApp->shmem->current_test_endtime);
}

bool test_loop_condition(int N) noexcept
{
    if (sApp->shmem->current_test_sleep_duration != 0us)
    {
        usleep(sApp->shmem->current_test_sleep_duration.count() / N);
    }
    return test_time_condition();
}

bool test_is_retry() noexcept
{
    // negative values indicate a retry
    return sApp->current_iteration_count < 0;
}

static void init_internal(const struct test *test)
{
    print_temperature_of_device();

    logging_init(test);
}

static void init_per_thread_data()
{
    auto initer = [](auto *data, int) { data->init(); };
    for_each_main_thread(initer);
    for_each_test_thread(initer);
}

static void cleanup_internal(const struct test *test)
{
    logging_finish();
}

int cleanup_global(int exit_code, PerThreadFailures per_thread_failures)
{
#if SANDSTONE_FREQUENCY_MANAGER
    if (sApp->vary_frequency_mode)
        sApp->frequency_manager->restore_core_frequency_initial_state();

    if (sApp->vary_uncore_frequency_mode)
        sApp->frequency_manager->restore_uncore_frequency_initial_state();
#endif

    exit_code = print_application_footer(exit_code, std::move(per_thread_failures));
    return logging_close_global(exit_code);
}

template <uint32_t X, uint32_t Y, typename P = int>
static void inline __attribute__((always_inline)) assembly_marker(P param = 0)
{
#ifdef __x86_64__
    // GCC doesn't provide __SSC_MARK in <x86gprintrin.h>
    asm ("movl %0, %%ebx\n\t"
         "fs addr32 nop"
        : : "i" (X ^ Y), "D" (param) : "ebx");
#endif
}

namespace AssemblyMarker {
static constexpr uint32_t Test = 0x00;
static constexpr uint32_t TestLoop = 0x100;
static constexpr uint32_t Start = 0x53;             // "S"
static constexpr uint32_t Iterate = 0x49;           // "I"
static constexpr uint32_t End = 0x45;               // "E";
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
    sApp->current_test_starttime_at_run_first_loop = MonotonicTimePoint::clock::now();
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

void reschedule()
{
    if (sApp->device_scheduler)
        sApp->device_scheduler->reschedule_to_next_device();
}

#ifndef _WIN32
#  pragma GCC visibility pop
#endif
} // extern "C"

static uintptr_t thread_runner(int thread_number)
{
    // convert from internal Sandstone numbering to the system one
    pin_to_logical_processor(LogicalProcessor(device_info[thread_number].cpu_number), current_test->id);

    PerThreadData::Test *this_thread = sApp->test_thread_data(thread_number);
    random_init_thread(thread_number);
    int ret = EXIT_FAILURE;

    auto cleanup = scopeExit([&] {
        // let SIGQUIT handler know we're done
        ThreadState new_state = thread_failed;
        if (!this_thread->has_failed()) {
            if (this_thread->has_skipped() || ret < EXIT_SUCCESS)
                new_state = thread_skipped;
            else if (ret == EXIT_SUCCESS)
                new_state = thread_succeeded;
        }
        this_thread->thread_state.store(new_state, std::memory_order_relaxed);

        if (new_state == thread_failed) {
            if (sApp->shmem->cfg.ud_on_failure)
                ud2();
            logging_mark_thread_failed(thread_number);
            logging_run_callback();
        } else if (new_state == thread_skipped) {
            logging_mark_thread_skipped(thread_number);
        }
        test_end(new_state);

        // If rescheduling, do cleanup
        if (sApp->device_scheduler)
            sApp->device_scheduler->finish_reschedule();
    });

    // indicate to SIGQUIT handler that we're running
    this_thread->thread_state.store(thread_running, std::memory_order_relaxed);

#if SANDSTONE_DEVICE_CPU
    CPUTimeFreqStamp before;
    before.Snapshot(thread_number);
#endif
    test_start();

    try {
        ret = test_run_wrapper_function(current_test, thread_number);
    } catch (std::exception &e) {
        log_error("Caught C++ exception: \"%s\" (type '%s')", e.what(), typeid(e).name());
        // no rethrow
    }

    cleanup.run_now();

#if SANDSTONE_DEVICE_CPU
    CPUTimeFreqStamp after;
    after.Snapshot(thread_number);
    this_thread->effective_freq_mhz = CPUTimeFreqStamp::EffectiveFrequencyMHz(before, after);
#endif

    if (sApp->shmem->cfg.verbosity >= 3)
        log_message(thread_number, SANDSTONE_LOG_INFO "inner loop count for thread %d = %u\n",
                    thread_number, this_thread->inner_loop_count);


    // our caller doesn't care what we return, but the returned value helps if
    // you're running strace
    return ret;
}

static void protect_shmem()
{
    size_t protected_len = sApp->shmem->thread_data_offset;
    assert(protected_len == ROUND_UP_TO_PAGE(protected_len) &&
            "SharedMemory::main_thread_data is not page-aligned");
    IGNORE_RETVAL(mprotect(sApp->shmem, protected_len, PROT_READ));
}


__attribute__((weak, noclone, noinline)) int print_application_footer(int exit_code, PerThreadFailures per_thread_failures)
{
    return exit_code;
}

static void run_threads_in_parallel(const struct test *test)
{
    SandstoneTestThread thr[thread_count()];    // NOLINT: -Wvla
    int i;

    for (i = 0; i < thread_count(); i++) {
        thr[i].start(thread_runner, i);
    }
    /* wait for threads to end */
    for (i = 0; i < thread_count(); i++) {
        thr[i].join();
    }
}

static void run_threads_sequentially(const struct test *test)
{
    // we still start one thread, in case the test uses report_fail_msg()
    // (which uses pthread_cancel())
    SandstoneTestThread thread;
    thread.start([](int t) {
        for ( ; t != thread_count(); thread_num = ++t)
            thread_runner(t);
        return uintptr_t(t);
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
            merge_test_result(children.results[i], test_result_from_exit_code(info));
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
        if (result == WAIT_TIMEOUT)
            return 0;

        DWORD idx = result - WAIT_OBJECT_0;
        if (idx >= nCount) [[unlikely]] {
            DWORD err = GetLastError();
            fprintf(stderr, "%s: WaitForMultipleObjects() failed: %lx; children left = %d: %s\n",
                    program_invocation_name, result, children_left, win32_strerror(err).c_str());
            abort();
        }
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
                merge_test_result(children.results[idx], childResult);
                --children_left;
                return 0;
            }
        }

        fprintf(stderr, "%s: INTERNAL ERROR: somehow got unknown handle 0x%p\n",
                program_invocation_name, hExited);
        abort();
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
                children.results[i].result = TestResult::TimedOut;
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

            MonotonicTimePoint now = MonotonicTimePoint::clock::now();
            for (ChildExitStatus &result : children.results) {
                result.result = TestResult::Interrupted;
                if (result.endtime == MonotonicTimePoint())
                    result.endtime = now;
            }

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
    wait_for_all_children(sApp->timeout_to_kill);
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

static TestResult run_one_test_inner(struct test *test, bool init_in_aux_thread = false)
{
    TestResult state = TestResult::Passed;

    do {
        int ret = 0;
        test->per_thread = sApp->user_thread_data.data();
        std::fill_n(test->per_thread, sApp->thread_count, test_data_per_thread{});
        init_per_thread_data();

        sApp->prepare_test_tests(test);
        state = prepare_test_for_device(test);
        if (state != TestResult::Passed) {
            break;
        }

        if (test->test_init) {
            if (init_in_aux_thread) {
                // ensure the init function is run pinned to a specific logical
                // processor but its pinning doesn't affect this control thread
                auto init_thread_runner = [](void *testptr) {
                    auto test = static_cast</*nonconst*/ struct test *>(testptr);
                    pin_to_logical_processor(LogicalProcessor(device_info[0].cpu_number));
                    thread_num = -1;
                    intptr_t ret = test->test_init(test);
                    return reinterpret_cast<void *>(ret);
                };
                pthread_t init_thread;
                void *retptr;
                pthread_create(&init_thread, nullptr, init_thread_runner, test);
                pthread_join(init_thread, &retptr);
                ret = intptr_t(retptr);
            } else {
                ret = test->test_init(test);
            }
            if (ret > 0) {
                state = TestResult::Failed;
            } else if (ret < 0) {
                state = TestResult::Skipped;
            } else {
                // check if the thread has failed with log_error() or skipped
                // with log_skip()
                PerThreadData::Main *thr = sApp->main_thread_data();
                if (thr->has_skipped())
                    state = TestResult::Skipped;
                else if (thr->has_failed())
                    state = TestResult::Failed;
            }
        }

        if (state == TestResult::Failed) {
            logging_mark_thread_failed(-1);
            if (ret > 0)
                log_error("Init function failed with code %i", ret);
            state = TestResult::Failed;
            break;
        } else if (state == TestResult::Skipped) {
            if (ret != 0 && ret != EXIT_SKIP)
                log_skip(RuntimeSkipCategory, "Unexpected OS error: %s", strerror(-ret));
            state = TestResult::Skipped;
            break;
        }

        sApp->current_test_starttime_at_run = MonotonicTimePoint::clock::now();
        run_threads(test);

        if (test->test_cleanup) {
            ret = test->test_cleanup(test);
            PerThreadData::Main *thr = sApp->main_thread_data();
            if (ret > EXIT_SUCCESS || thr->has_failed()) {
                state = TestResult::Failed;
            } else if (ret == EXIT_SKIP || thr->has_skipped()) {
                log_skip(RuntimeSkipCategory, "SKIP requested in cleanup");
                state = TestResult::Skipped;
            } else if (ret < EXIT_SUCCESS) {
                log_skip(RuntimeSkipCategory, "Unexpected OS error in cleanup: %s", strerror(-ret));
                state = TestResult::Skipped;
            }
        }

        finish_test_for_device(test);
        sApp->test_tests_finish(test);
    } while (false);

    return state;
}

TestResult child_run(/*nonconst*/ struct test *test, int child_number)
{
    if (sApp->current_fork_mode() != SandstoneApplication::ForkMode::no_fork) {
        protect_shmem();
        sApp->select_main_thread(child_number);
        pin_to_logical_processors(sApp->main_thread_data()->device_range, "control");
        restrict_topology(sApp->main_thread_data()->device_range);
        signals_init_child();
        debug_init_child();
    }

    return run_one_test_inner(test, true);
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

        case test_schedule_isolate_numa_domain:
            return SandstoneApplication::SlicePlans::IsolateNuma;

        case test_schedule_default:
            break;
        }
        return SandstoneApplication::SlicePlans::Heuristic;
    }();
    if (type == SandstoneApplication::SlicePlans::FullSystem) {
        sApp->main_thread_data()->device_range = { 0, thread_count() };
        return 1;
    }

    const std::vector<DeviceRange> &plan = sApp->slice_plans.plans[type];
    for (size_t i = 0; i < plan.size(); ++i)
        sApp->main_thread_data(i)->device_range = plan[i];

    return plan.size();
}

static void run_one_test_children(ChildrenList &children, const struct test *test)
{
    int child_count = slices_for_test(test);
    if (sApp->current_fork_mode() != SandstoneApplication::ForkMode::exec_each_test) {
        assert(sApp->current_fork_mode() != SandstoneApplication::ForkMode::child_exec_each_test
                && "child_exec_each_test mode can only happen in the child side!");
        assert((sApp->current_fork_mode() != SandstoneApplication::ForkMode::no_fork || child_count == 1)
               && "-fno-fork can only start 1 child!");

        for (int i = 0; i < child_count; ++i) {
            StartedChild ret = { .fd = FFD_CHILD_PROCESS };
            if (sApp->current_fork_mode() == SandstoneApplication::ForkMode::fork_each_test)
                ret = call_forkfd();
            if (ret.fd == FFD_CHILD_PROCESS) {
                /* child - run test's code */
                logging_init_child_preexec();
                TestResult result = child_run(const_cast<struct test *>(test), i);
                if (sApp->current_fork_mode() == SandstoneApplication::ForkMode::fork_each_test)
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

static void run_one_test_init_in_parent(ChildrenList &children, const struct test *test)
{
    TestResult res;
    init_per_thread_data();
    int ret = test->test_init(const_cast<struct test *>(test));

    PerThreadData::Main *main = sApp->main_thread_data();
    if (ret < 0) [[likely]] {
        assert(main->has_skipped() &&
               "Internal error: init-in-parent returned a skip but did not call log_skip()");
        res = TestResult::Skipped;
    } else if (ret == EXIT_SUCCESS) [[likely]] {
        if (main->has_skipped()) {
            res = TestResult::Skipped;
        } else if (main->has_failed()) {
            res = TestResult::Failed;
        } else {
            assert(!"Internal error: init-in-parent succeeded");
            __builtin_unreachable();
        }
    } else {
        assert(main->has_failed() &&
               "Internal error: init-in-parent returned an error but did not call log_error()");
        res = TestResult::Failed;
    }

    children.results.emplace_back(ChildExitStatus{ res });
}

static void run_one_test_in_parent(ChildrenList &children, const struct test *test)
{
    auto state = run_one_test_inner(const_cast<struct test*>(test));
    children.results.emplace_back(ChildExitStatus{ state });
}

static TestResult run_one_test_once(const struct test *test)
{
    ChildrenList children;

    sApp->current_test_count++;
    if (device_features_t missing = (test->compiler_minimum_device | test->minimum_cpu) & ~device_features) {
        init_per_thread_data();

        // be as brief as possible: if the feature missing is required by the
        // test, then report only those. if not, report the features the test
        // was compiled with, but not those already required by the framework.
        device_features_t missing_to_report = missing & ~test->compiler_minimum_device;
        if (missing_to_report) {
            log_skip(CpuNotSupportedSkipCategory, "test requires %s\n", device_features_to_string(missing_to_report).c_str());
        } else {
            missing_to_report = missing & ~device_compiler_features;
            log_skip(CpuNotSupportedSkipCategory, "test compiled with %s\n", device_features_to_string(missing_to_report).c_str());
        }

        children.results.emplace_back(ChildExitStatus{ TestResult::Skipped });
    } else if (test->quality_level == TEST_QUALITY_BETA && test->quality_level < sApp->requested_quality) {
        init_per_thread_data();
        log_skip(TestResourceIssueSkipCategory, "Test %s is in BETA quality, try again using --beta option", test->id);
        children.results.emplace_back(ChildExitStatus{ TestResult::Skipped });
    } else if (test->flags & test_in_parent) {
        run_one_test_in_parent(children, test);
    } else if (test->flags & test_init_in_parent) {
        run_one_test_init_in_parent(children, test);
    } else {
        run_one_test_children(children, test);
    }

    // print results and find out if the test failed
    MonotonicTimePoint now = MonotonicTimePoint::clock::now();
    for (ChildExitStatus &result : children.results) {
        if (result.endtime == MonotonicTimePoint())
            result.endtime = now;
    }
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
                                  const PerThreadFailures &per_thread_failures)
{
    logging_printf(LOG_LEVEL_VERBOSE(1), "# Test failed %d out of %d times"
                                         " (%.1f%%)\n", fail_count, attempt_count,
                   fail_count * 100.0 / attempt_count);
    logging_restricted(LOG_LEVEL_QUIET, "Test failed (#%s%x).", test->id, fail_count - 1);

    // First, determine if all threads failed the exact same way
    bool all_threads_failed_equally = true;
    PerThreadFailures::value_type fail_pattern = 0;
    int nfailures = 0;
    for (size_t i = 0; i < thread_count() && all_threads_failed_equally; ++i) {
        if (per_thread_failures[i]) {
            if (++nfailures == 1)
                fail_pattern = per_thread_failures[i];
            else if (per_thread_failures[i] != fail_pattern)
                all_threads_failed_equally = false;
        }
    }
    if (all_threads_failed_equally && nfailures == thread_count()) {
        logging_printf(LOG_LEVEL_VERBOSE(1), "# All threads failed equally. This is highly unlikely (SW bug?)\n");
        return;
    }

    analyze_test_failures_for_topology(test, per_thread_failures);
}

TestResult run_one_test(const test_cfg_info &test_cfg, PerThreadFailures &per_thread_failures)
{
    const struct test *test = test_cfg.test;
    TestResult state = TestResult::Skipped;
    int fail_count = 0;
    std::unique_ptr<char[]> random_allocation;
    MonotonicTimePoint first_iteration_target;
    bool auto_fracture = false;
    Duration runtime = 0ms;

    // resize and zero the storage
    if (per_thread_failures.size() == thread_count()) {
        std::fill_n(per_thread_failures.begin(), thread_count(), 0);
    } else {
        per_thread_failures.clear();
        per_thread_failures.resize(thread_count(), 0);
    }
    auto mark_up_per_thread_fail = [&per_thread_failures, &fail_count](int i) {
        ++fail_count;
        if (i >= SandstoneApplication::MaxRetestCount)
            return;
        for_each_test_thread([&](PerThreadData::Test *data, int i) {
            using U = PerThreadFailures::value_type;
            if (data->has_failed())
                per_thread_failures[i] |= U(1) << i;
        });
    };

    sApp->current_test_duration = test_duration_(test_cfg);
    first_iteration_target = MonotonicTimePoint::clock::now() + 10ms;

    if (sApp->inject_idle > 0) {
        float idle_rate = sApp->inject_idle / 100.0;
        sApp->shmem->current_test_sleep_duration = duration_cast<microseconds>(
            sApp->current_test_duration * idle_rate
        );
        // When injecting idle time, reduce the test duration accordingly
        sApp->current_test_duration = duration_cast<ShortDuration>(
            sApp->current_test_duration * (1 - idle_rate)
        );
    }

    if (sApp->max_test_loop_count) {
        sApp->shmem->current_max_loop_count = sApp->max_test_loop_count;
    } else if (test->desired_duration == -1) {
        sApp->shmem->current_max_loop_count = -1;
    } else if (sApp->test_tests_enabled()) {
        // don't fracture in the test-the-test mode
        sApp->shmem->current_max_loop_count = -1;
    } else if (test->fracture_loop_count == 0) {
        /* for automatic fracture mode, do a 40 loop count */
        sApp->shmem->current_max_loop_count = 40;
        auto_fracture = true;
    } else {
        sApp->shmem->current_max_loop_count = test->fracture_loop_count;
    }

    assert(sApp->retest_count >= 0);

    /* First we go to do our -- possibly fractured -- normal run, we'll do retries after */
    for (sApp->current_iteration_count = 0;; ++sApp->current_iteration_count) {

#if SANDSTONE_FREQUENCY_MANAGER
        //change frequency per fracture
        if (sApp->vary_frequency_mode == true)
            sApp->frequency_manager->change_core_frequency();

        //change uncore frequency per fracture
        if (sApp->vary_uncore_frequency_mode == true)
            sApp->frequency_manager->change_uncore_frequency();
#endif

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
            mark_up_per_thread_fail(0);
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
                mark_up_per_thread_fail(iterations);
        }

        analyze_test_failures(test, fail_count, iterations, per_thread_failures);
        state = TestResult::Failed;
    }

out:
#if SANDSTONE_FREQUENCY_MANAGER
    //reset frequency level idx for the next test
    if (sApp->vary_frequency_mode || sApp->vary_uncore_frequency_mode)
        sApp->frequency_manager->reset_frequency_level_idx();
#endif

    random_advance_seed();      // advance seed for the next test
    logging_flush();
    return state;
}

int thread_count()
{
    return sApp->thread_count;
}

int8_t sandstone_verbosity_level()
{
    return std::to_underlying(sApp->shmem->cfg.verbosity);
}
