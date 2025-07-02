/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __INCLUDE_GUARD_SANDSTONE_H_
#define __INCLUDE_GUARD_SANDSTONE_H_

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#ifdef __x86_64__
#pragma GCC diagnostic push
#  ifndef __clang__
#    pragma GCC diagnostic ignored "-Wuninitialized"
#    pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#  endif
#include <immintrin.h>
#pragma GCC diagnostic pop
#endif

#include "cpu_features.h"
#include "sandstone_config.h"
#include "sandstone_data.h"
#include <sandstone_test_groups.h>
#include "test_knobs.h"
#include "sandstone_chrono.h"

#ifdef __cplusplus
#include <atomic>
using std::atomic_int;
extern "C" {
#else
#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#define thread_local _Thread_local
#define noexcept __attribute__((__nothrow__))
#endif

#define SANDSTONE_STRINGIFY(name)       SANDSTONE_STRINGIFY2(name)
#define SANDSTONE_STRINGIFY2(name)      #name

#define MAX_HWTHREADS_PER_CORE  4

#ifdef __APPLE__
#  define SANDSTONE_SECTION_PREFIX              "__DATA,"
#else
#  define SANDSTONE_SECTION_PREFIX
#endif

// Requested thread stack size for our test threads:
// We have some tests that do deep recursion, so we need a stable value
#define THREAD_STACK_SIZE   (8192*1024)

#define SANDSTONE_LOG_ERROR     "E> "
#define SANDSTONE_LOG_WARNING   "W> "
#define SANDSTONE_LOG_INFO      "I> "
#define SANDSTONE_LOG_DEBUG     "d> "

/// logs a formatted error message to the logfile.  log_error accepts a constant format string
/// followed by 0 or more arguments that provide data for the format string.
#define log_error(...)          log_message(thread_num, SANDSTONE_LOG_ERROR __VA_ARGS__)
/// logs a formatted warning message to the logfile.  log_warning accepts a constant format string
/// followed by 0 or more arguments that provide data for the format string.
#define log_warning(...)        log_message(thread_num, SANDSTONE_LOG_WARNING __VA_ARGS__)
/// logs a formatted info message to the logfile.  log_info accepts a constant format string
/// followed by 0 or more arguments that provide data for the format string.
#define log_info(...)           log_message(thread_num, SANDSTONE_LOG_INFO __VA_ARGS__)
/// logs a formatted debug message to the logfile.  log_debug accepts a constant format string
/// followed by 0 or more arguments that provide data for the format string.  The message
/// is only logged in debug builds.  This macro has no effect in release builds and generates
/// no code.
#ifndef NDEBUG
#  define log_debug(...)        log_message(thread_num, SANDSTONE_LOG_DEBUG __VA_ARGS__)
#else
#  define log_debug( ...)       (void)0
#endif

// skip categories
typedef enum SkipCategory {
    CpuNotSupportedSkipCategory = 1,
    CpuTopologyIssueSkipCategory,
    TestResourceIssueSkipCategory,
    OSResourceIssueSkipCategory,
    OsNotSupportedSkipCategory,
    DeviceNotFoundSkipCategory,
    DeviceNotConfiguredSkipCategory,
    UnknownSkipCategory,
    IgnoredMceCategory,
    RuntimeSkipCategory,
    TestObsoleteSkipCategory,
    SelftestSkipCategory,
} SkipCategory;

/// Values to be used in the test's .quality_level field
typedef enum TestQuality {
    /// test should not be run (ever)
    TEST_QUALITY_SKIP               = -1,
    /// test is a beta test (default) and should be run only if --beta is used
    TEST_QUALITY_BETA               = 0,
    /// test is a production-quality test but should not be run by default
    TEST_QUALITY_OPTIONAL           = 1,
    /// test is a production test and should be run by default
    TEST_QUALITY_PROD               = 2,
} test_quality;

/// logs a skip message to the logfile. log_skip accepts the category to which the skip belongs to
/// and accepts a constant format string followed by 0 or more arguments that provide data for the
/// format string.
#define log_skip(skip_category, ...)          log_message_skip(thread_num, skip_category, __VA_ARGS__)

/// used to determine whether one or more CPU features are available at runtime.  f is a bitmask
/// of cpu features as defined in the auto-generated cpu_features.h file.  For example, a test
/// may call cpu_has_feature(cpu_feature_avx512f) to determine whether AVX-512 is available.
/// Normally, cpuid detection is handle automatically by the framework via test's minimum_cpu field.
/// This macro is provided in case tests need more fine grained control.
#define cpu_has_feature(f)      ((_compilerCpuFeatures & (f)) == (f) || (cpu_features & (f)) == (f))

#if defined(__clang__) && !SANDSTONE_NO_LOGGING
#  define ATTRIBUTE_PRINTF(x, y)    __attribute__((__format__(printf, x, y)))
#elif defined(__GNUC__) && !SANDSTONE_NO_LOGGING
#  define ATTRIBUTE_PRINTF(x, y)    __attribute__((__format__(gnu_printf, x, y)))
#else
#  define ATTRIBUTE_PRINTF(x, y)
#endif

#ifdef __cplusplus
#define IGNORE_RETVAL(call)                     \
    __extension__ ({                            \
        auto __return_value__  = call;          \
        (void)__return_value__;                 \
    })

#else
#define IGNORE_RETVAL(call)                     \
    __extension__ ({                            \
        __auto_type __return_value__  = call;   \
        (void)__return_value__;                 \
    })
#endif

/// to be used in the test_run function of a test.  TEST_LOOP executes its body continuously until it is
/// asked to terminate by the OpenDCDiag framework. The second parameter, N, specifies the
/// granularity of the loop.  On each iteration of the loop, the body is executed N times.  The
/// framework then checks to see if the test's time slot has elapsed.  If it has, the loop terminates.
/// If it has not, the body is executed another N times before another check is made.
/// By convention, the second parameter to TEST_LOOP is always a power of two.
#define TEST_LOOP(test, N)                          \
    static_assert(N > 0, "N must be positive");     \
    test_loop_start();                              \
    for (int _loop_i_ = 0; _loop_i_ == 0; test_loop_end(), _loop_i_ = 1)          \
        for ( ; _loop_i_ < N || (_loop_i_ = 0, test_loop_condition(N)); ++_loop_i_)

/// used in a test's test_init function to indicate that a test should be skipped.
#define EXIT_SKIP               -255

#define DECLARE_TEST_INNER2(test_id, test_description) \
    __attribute__((aligned(alignof(void*)), used, section(SANDSTONE_SECTION_PREFIX "tests"))) \
    struct test _test_ ## test_id = {                   \
        .compiler_minimum_cpu = _compilerCpuFeatures,   \
        .id = SANDSTONE_STRINGIFY(test_id),             \
        .description = test_description,
#define DECLARE_TEST_INNER(test_id, test_description)   DECLARE_TEST_INNER2(test_id, test_description)

#ifndef DECLARE_TEST
#  define DECLARE_TEST(test_id, test_description)       DECLARE_TEST_INNER(test_id, test_description)
#endif

#define DECLARE_TEST_GROUPS(...)                                      \
    __extension__ (const struct test_group* const[]){ __VA_ARGS__, NULL }

#define END_DECLARE_TEST   };

/// Variadic macros to count the number of arguments passed to other macro.
/// @see OVERLOAD()
#define NARGN(\
            em, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10,n11,n12,n13,n14,n15,n16,n17,n18,n19,n20,n21,n22,n23,n24,n25,n26,n27,n28,n29,n30,n31,\
            n32,n33,n34,n35,n36,n37,n38,n39,n40,n41,n42,n43,n44,n45,n46,n47,n48,n49,n50,n51,n52,n53,n54,n55,n56,n57,n58,n59,n60,n61,n62,n63,\
            N, ...) \
        N

#define APPEND_NON_EMPTY(...) ,##__VA_ARGS__
#define NARG_(...) NARGN(__VA_ARGS__)
#define NARGS(...) NARG_( \
            -1 APPEND_NON_EMPTY(__VA_ARGS__),\
            63,62,61,60,59,58,57,56,55,54,53,52,51,50,49,48,47,46,45,44,43,42,41,40,39,38,37,36,35,34,33,32,\
            31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

static_assert(NARGS() == 0, "Empty list");
static_assert(NARGS(a1) == 1, "single element");
static_assert(NARGS(a1, a2) == 2, "two elements");
static_assert(NARGS(a1, a2, a3, a4, a5, a6, a7, a8) == 8, "8 elements");

static_assert(NARGS(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15) == 63, "63 elements");

/**
 * Variadic macro to alias functions in C/macros.
 * Example instantiation:
 * `#define V(...)   OVERLOAD(V,NARGS(__VA_ARGS__))(__VA_ARGS__)`
 * with appropriate Vs() definitions:
 * `#define V1(a)    build_float((a))`
 * `#define V2(a, b) build_rational((a), (b))`
 * after expansion V might be used with single (e.g. where float value is passed)
 * or with two arguments (e.g. where number might be expressed as rational number)
 * All possible expressions must be defined, otherwise the code won't compile.
 */
#define OVERLOAD_(name,num) name##num
#define OVERLOAD(name,num) OVERLOAD_(name,num)

/**
 * Variadic macro to suppress warnings on unused arguments/variables
 */
#define UNUSED_ARGS_0()
#define UNUSED_ARGS_1(e)       ((void) (e));
#define UNUSED_ARGS_2(e, ...)  UNUSED_ARGS_1(e) UNUSED_ARGS_1(__VA_ARGS__)
#define UNUSED_ARGS_3(e, ...)  UNUSED_ARGS_1(e) UNUSED_ARGS_2(__VA_ARGS__)
#define UNUSED_ARGS_4(e, ...)  UNUSED_ARGS_1(e) UNUSED_ARGS_3(__VA_ARGS__)
#define UNUSED_ARGS_5(e, ...)  UNUSED_ARGS_1(e) UNUSED_ARGS_4(__VA_ARGS__)
#define UNUSED_ARGS_6(e, ...)  UNUSED_ARGS_1(e) UNUSED_ARGS_5(__VA_ARGS__)
#define UNUSED_ARGS_7(e, ...)  UNUSED_ARGS_1(e) UNUSED_ARGS_6(__VA_ARGS__)
#define UNUSED_ARGS_8(e, ...)  UNUSED_ARGS_1(e) UNUSED_ARGS_7(__VA_ARGS__)
#define UNUSED_ARGS_9(e, ...)  UNUSED_ARGS_1(e) UNUSED_ARGS_8(__VA_ARGS__)
#define UNUSED_ARGS_10(e, ...) UNUSED_ARGS_1(e) UNUSED_ARGS_9(__VA_ARGS__)
#define UNUSED_ARGS_11(e, ...) UNUSED_ARGS_1(e) UNUSED_ARGS_10(__VA_ARGS__)
#define UNUSED_ARGS_12(e, ...) UNUSED_ARGS_1(e) UNUSED_ARGS_11(__VA_ARGS__)
#define UNUSED_ARGS_13(e, ...) UNUSED_ARGS_1(e) UNUSED_ARGS_12(__VA_ARGS__)
#define UNUSED_ARGS_14(e, ...) UNUSED_ARGS_1(e) UNUSED_ARGS_13(__VA_ARGS__)
#define UNUSED_ARGS_15(e, ...) UNUSED_ARGS_1(e) UNUSED_ARGS_14(__VA_ARGS__)
#define UNUSED_ARGS_16(e, ...) UNUSED_ARGS_1(e) UNUSED_ARGS_15(__VA_ARGS__)
#define UNUSED_ARGS_17(e, ...) UNUSED_ARGS_1(e) UNUSED_ARGS_16(__VA_ARGS__)
#define UNUSED_ARGS_18(e, ...) UNUSED_ARGS_1(e) UNUSED_ARGS_17(__VA_ARGS__)
#define UNUSED_ARGS_19(e, ...) UNUSED_ARGS_1(e) UNUSED_ARGS_18(__VA_ARGS__)
#define UNUSED_ARGS_20(e, ...) UNUSED_ARGS_1(e) UNUSED_ARGS_19(__VA_ARGS__)

#define UNUSED_ARGS(...) do { OVERLOAD(UNUSED_ARGS_,NARGS(__VA_ARGS__))(__VA_ARGS__) } while(0)

/// Macro to check if pointer is properly aligned. Alignment must be a valid power of 2.
#define IS_ALIGNED(ptr, alignment) ((((uint64_t) (ptr)) & ((alignment) - 1)) == 0)

/// Macro to build mask value for particular number of bits.
#define MASK(bits) (((bits) == 64) ? 0xffffffffffffffffULL : ((1ULL << ((bits == 64) ? 0 : (bits))) - 1))

/// can be used in the clobber list of inline assembly to indicate
/// that all the R registers have been modified by the assembly code.
#define RCLOBBEREDLIST "r8",\
                       "r9",\
                       "r10",\
                       "r11",\
                       "r12",\
                       "r13",\
                       "r14",\
                       "r15"

/// can be used in the clobber list of inline assembly to indicate
/// that all the MMX registers have been modified by the assembly code.
#define MMCLOBBEREDLIST "mm0",\
                        "mm1",\
                        "mm2",\
                        "mm3",\
                        "mm4",\
                        "mm5",\
                        "mm6",\
                        "mm7"

/// can be used in the clobber list of inline assembly to indicate
/// that all the XMM registers have been modified by the assembly code.
#define XMMCLOBBEREDLIST "xmm0",\
                         "xmm1",\
                         "xmm2",\
                         "xmm3",\
                         "xmm4",\
                         "xmm5",\
                         "xmm6",\
                         "xmm7",\
                         "xmm8",\
                         "xmm9",\
                         "xmm10",\
                         "xmm11",\
                         "xmm12",\
                         "xmm13",\
                         "xmm14",\
                         "xmm15"

/// can be used in the clobber list of inline assembly to indicate
/// that all the YMM registers have been modified by the assembly code.
#define YMMCLOBBEREDLIST "ymm0",\
                         "ymm1",\
                         "ymm2",\
                         "ymm3",\
                         "ymm4",\
                         "ymm5",\
                         "ymm6",\
                         "ymm7",\
                         "ymm8",\
                         "ymm9",\
                         "ymm10",\
                         "ymm11",\
                         "ymm12",\
                         "ymm13",\
                         "ymm14",\
                         "ymm15"

/// can be used in the clobber list of inline assembly to indicate
/// that all the ZMM registers have been modified by the assembly code.
#define ZMMCLOBBEREDLIST "zmm0",\
                         "zmm1",\
                         "zmm2",\
                         "zmm3",\
                         "zmm4",\
                         "zmm5",\
                         "zmm6",\
                         "zmm7",\
                         "zmm8",\
                         "zmm9",\
                         "zmm10",\
                         "zmm11",\
                         "zmm12",\
                         "zmm13",\
                         "zmm14",\
                         "zmm15",\
                         "zmm16",\
                         "zmm17",\
                         "zmm18",\
                         "zmm19",\
                         "zmm20",\
                         "zmm21",\
                         "zmm22",\
                         "zmm23",\
                         "zmm24",\
                         "zmm25",\
                         "zmm26",\
                         "zmm27",\
                         "zmm28",\
                         "zmm29",\
                         "zmm30",\
                         "zmm31"

/// can be used in the clobber list of inline assembly to indicate
/// that all the K registers have been modified by the assembly code.
#define KMASKCLOBBEREDLIST "k0","k1","k2","k3","k4","k5","k6","k7"

/// used as follows: if instruction cache, only cache_instruction is valid; if
/// data, only data is valid; if unified, both are set to the same value. In all
/// the cases the value is the cache size in bytes.  A field is valid if it
/// contains a value >= 0.  Fields with negative values are invalid.
/// TODO: consider changing this, with L1D & L1I being the same size, they are
/// indistinguishable from a unified cache.
struct cache_info {
    int cache_instruction;
    int cache_data;
};

/// cpu_info contains information about a logical CPU
struct cpu_info {
    uint64_t ppin;          ///! Processor ID read from MSR
    uint64_t microcode;     ///! Microcode version read from /sys

    /// Logical OS processor number.
    /// On Unix systems, this is a sequential ID; on Windows, it encodes
    /// 64 * ProcessorGroup + ProcessorNumber
    int cpu_number;

    /// Thread ID inside a core, usually 0 or 1 (-1 if not known).
    int16_t thread_id;
    /// Core ID inside of a package, -1 if not known.
    int16_t core_id;
    /// Module ID inside of a package, -1 if not known.
    int16_t module_id;
    /// Tile ID inside of a package, -1 if not known. May combine with the die ID.
    int16_t tile_id;
    /// NUMA node ID in the system, -1 if not known.
    int16_t numa_id;
    /// Package ID in the system, -1 if not known.
    int16_t package_id;

    /// On x86, it's the APICID or x2APICID, if known; -1 if not.
    int hwid;

    struct cache_info cache[3]; ///! Cache info from OS

#ifdef __cplusplus
    int cpu() const;        ///! Internal CPU number
#endif
};

struct test;

typedef int (*initfunc)(struct test *test);
typedef int (*cleanupfunc)(struct test *test);

typedef int (*runfunc)(struct test *test, int cpu);

typedef enum test_flag {
    test_type_regular       = 0x00,     ///! regular test type
    test_type_kvm           = 0x01,     ///! test using Sandstone's KVM functionality

    test_schedule_default           = 0x00,
    test_schedule_mask              = 0x0e,

    /// Asks the framework to run the threads sequentially, instead of all in
    /// parallel.
    test_schedule_sequential        = 0x02,

    /// Asks the framework to run all the threads for all logical processors in
    /// one single process.
    test_schedule_fullsystem        = 0x04,

    /// Asks the framework to run one child process per each socket in the
    /// system, with all cores.
    test_schedule_isolate_socket    = 0x06,

    /// Tells the --test-tests mode to ignore memory consumption for this test
    test_flag_ignore_memory_use     = 0x0010,

    /// Tells the --test-tests mode to ignore this test's full run time being
    /// over 25% more than the requested duration.
    test_flag_ignore_test_overtime  = 0x0020,

    /// Tells the --test-tests mode to ignore this test's full run time being
    /// under 25% below the requested duration. Note: set the test's
    /// .desired_duration to -1 if it is not expected to loop.
    test_flag_ignore_test_undertime = 0x0040,

    /// Tells the --test-tests mode to ignore this test's inner loop timing.
    /// This suppresses the error too short or too long a loop.
    test_flag_ignore_loop_timing    = 0x0080,

    /// Tells the --test-tests mode to ignore the detection that this test
    /// may have called test_time_condition() before doing any work.
    test_flag_ignore_do_while       = 0x0100,

    /// Indicates that a test can only attribute failure to a particular
    /// package and not to threads or cores.
    test_failure_package_only       = 0x1000,
} test_flags;

struct test_data_per_thread
{
    /* private fields for test use only */
    void *data;
};

struct kvm_ctx;
typedef struct kvm_ctx kvm_ctx_t;
struct kvm_config;
typedef struct kvm_config kvm_config_t;
typedef const kvm_config_t *(*kvmconfigfunc)(void);

struct test {
    /* metadata */
    /// filled in by the DECLARE_TEST macro
    uint64_t compiler_minimum_cpu;

    /// Identifier of the test.  Each test must have a unique string identifier
    const char *id;
    /// A one line description of the test.
    const char *description;
    /// An array of pointers to group instances.
    const struct test_group * const *groups;

    /* methods */
    initfunc test_preinit;        ///! called from the main thread
    initfunc test_init;                ///! called from the main thread
    runfunc test_run;                ///! called per CPU
    cleanupfunc test_cleanup;        ///! called from the main thread

    /// kvm_config for kvm test type
    kvmconfigfunc test_kvm_config;

    /* generic data for test running */
    /* filled in by framework, used by framework and tests */

    /// minimum CPU required to be run, skipped if too old
    uint64_t minimum_cpu;

    /// duration (in ms) the test wants to run for
    /// Special values:
    /// INT_MAX runs forever and must be killed
    ///  0      default (no preference)
    ///  <0     no looping, test is run only once
    int desired_duration;

    /// duration (in ms) that is the upper bound of time for this test
    /// Special values:
    ///  0      default (no limit)
    int minimum_duration;

    /// duration (in ms) that is the upper bound of time for this test to have value
    /// Special values:
    ///  0      default (no limit)
    int maximum_duration;

    /// fracture the test time into smaller runs
    /// Special values:
    ///  <0         never
    ///  0      default (automatic)
    ///  >1     always; value is the inner loop count value at which to fracture the run
    int fracture_loop_count;

    /// whether to enable this test
    test_quality quality_level;

    /// flags for this test. See enum for possible values
    test_flags flags;

    /* private fields for test use only */

    /// can be used by tests to store a pointer to test specific resources whose lifetime
    /// is valid for the entire test.  Typically, tests will allocate
    /// such resources in the test_init function, store a pointer to them in this
    /// field, retrieve and use the resources in the test_run function and optionally
    /// free them in the test_cleanup function.
    void *data;
    struct test_data_per_thread *per_thread;
};

/* internal function; see C macro and C++ templates at the end of this file */
extern void _memcmp_fail_report(const void *actual, const void *expected, size_t size, enum DataType, const char *fmt, ...)
    ATTRIBUTE_PRINTF(5, 6) __attribute__((cold, noreturn));

/// can be called from a test's test_run function to fail the test.
/// This macro will kill the calling thread and cause the test to
/// exit.
#define report_fail(test)       _report_fail(test, __FILE__, __LINE__)
/// can be called from a test's test_run function to fail the test.
/// The failure will be annotated by the provided format string.
/// This macro will kill the calling thread and cause the test to
/// exit.
#define report_fail_msg(...)    _report_fail_msg(__FILE__, __LINE__, __VA_ARGS__)
extern void _report_fail(const struct test *test, const char *file, int line) __attribute__((noreturn));
extern void _report_fail_msg(const char *file, int line, const char *msg, ...)
    ATTRIBUTE_PRINTF(3, 4) __attribute__((noreturn));

/// @internal function called by TEST_LOOP
extern void test_loop_start(void) noexcept;
/// @internal function called by TEST_LOOP
extern void test_loop_end(void) noexcept;

/// may be called inside a test's test_run function.  It returns a
/// non-zero value if time remains in the test's time slot and the
/// test should continue to execute.
extern bool test_time_condition() noexcept;
#define test_time_condition(test)       test_time_condition()

/// Called from the TEST_LOOP macro to determine if loop should continue.
/// Argument N is the requested number of loop iterations. If idle cycle
/// injection is configured, this function will issue usleep() for calculated time.
extern bool test_loop_condition(int N) noexcept;

/// Returns true if this is a retry.
bool test_is_retry() noexcept __attribute__((pure));

/// outputs msg to the logs, prefixing it with the string "Platform issue:"
/// This function is usually used to log a warning when an error is detected
/// in a test's test_init or test_run functions that is due to a platform issue
/// rather than a problem with the CPU.  Examples, of such errors include
/// failures to allocate memory or create a file.
extern void log_platform_message(const char *msg, ...) ATTRIBUTE_PRINTF(1, 2);
extern void log_message(int thread_num, const char *msg, ...) ATTRIBUTE_PRINTF(2, 3);
extern void log_message_skip(int thread_num, SkipCategory c, const char *msg, ...) ATTRIBUTE_PRINTF(3, 4);
/// logs binary data to the logs.  The data is specified in the data
/// parameter and the size of the data in bytes in the size parameter.
/// The message parameter provides a description of the data which
/// precedes it in the log file.  The data is output in hexadecimal.
extern void log_data(const char *message, const void *data, size_t size);

/// retrieves the physical address of a given pointer.  Currently
/// this function is only supported on Linux and requires root
/// privileges.
uint64_t retrieve_physical_address(const volatile void *ptr);

#if defined(__linux__) && defined(__x86_64__)
/// reads the value of the MSR, specified by msr, of CPU cpu.
/// The value is returned in the value parameter.  The function
/// returns true if the value can be read and false otherwise.
/// This function is only supported on Linux and requires root
/// privileges.
bool read_msr(int cpu, uint32_t msr, uint64_t *value);
/// writes the value specified by value to the MSR, specified by msr,
/// of CPU cpu.  The function returns true if the value can be written
/// and false otherwise.   This function is only supported on Linux and
/// requires root privileges.
bool write_msr(int cpu, uint32_t msr, uint64_t value);
#else
static inline bool read_msr(int cpu, uint32_t msr, uint64_t *value)
{
    (void) cpu; (void) msr; (void) value;
    return false;
}
static inline bool write_msr(int cpu, uint32_t msr, uint64_t value)
{
    (void) cpu; (void) msr; (void) value;
    return false;
}
#endif


/// Calls aligned_alloc but first checks to see whether size is a multiple
/// of alignment.  If it is not, the requested size of the allocation is increased
/// so that size is a multiple of alignment ensuring that the pre-requisites of
/// aligned_alloc are met.
static inline void *aligned_alloc_safe(size_t alignment, size_t size)
{
    extern void *aligned_alloc(size_t, size_t); // in case it isn't defined
    if (alignment < sizeof(void*))
        alignment = sizeof(void*);
    size_t aligned_size = (size / alignment) * alignment;
    if (aligned_size < size)
        aligned_size += alignment;
    return aligned_alloc(alignment, aligned_size);
}

/// Returns a random unsigned 32 bit integer.
extern uint32_t random32(void);
/// Returns a random unsigned 64 bit integer.
extern uint64_t random64(void);
/// Returns a random unsigned 128 bit integer.
extern __uint128_t random128(void);
/// Sets each byte in the buffer pointed to by dest to a random value.
/// The size of the buffer in bytes is provided by the n parameter.
extern void *memset_random(void *dest, size_t n);
/// Generates a random, positive 32 bit floating point number between
/// 0.0 and scale.
extern float frandomf_scale(float scale);
/// Generates a random, positive 64 bit floating point number between
/// 0.0 and scale.
extern double frandom_scale(double scale);
/// Generates a random, positive 80 bit floating point number between
/// 0.0 and scale.
extern long double frandoml_scale(long double scale);
/// Generates a random, positive 32 bit floating point number between
/// 0.0 and 1.0.
static inline float frandomf()
{
    return frandomf_scale(1.0);
}
/// Generates a random, positive 64 bit floating point number between
/// 0.0 and 1.0.
static inline double frandom()
{
    return frandom_scale(1.0);
}
/// Generates a random, positive 80 bit floating point number between
/// 0.0 and 1.0.
static inline long double frandoml()
{
    return frandoml_scale(1.0L);
}

/// Returns a 64 bit unsigned integer in which num_bits_to_set of the
/// first bitwidth bits are randomly set.  For example,
/// set_random_bits(2, 8) would return a uint64_t in which 2 of the
/// least significant 8 bits are randomly set and all other bits are 0.
uint64_t set_random_bits(unsigned num_bits_to_set, uint32_t bitwidth);

extern uint64_t cpu_features;
/// thread_num always contains the integer identifier for the executing
/// thread.  It can be used to index the cpu_info array and is equivalent
/// to the cpu parameter in the test_run function.
#ifdef __llvm__
extern thread_local int thread_num;
#else
extern __thread int thread_num __attribute__((tls_model("initial-exec")));
#endif

/// cpu_info is an array of cpu_info structures.  Each element of the array
/// contains information about a logical CPU that will be used to
/// execute a test's test_run function.  The size of this array is
/// equal to the value returned by num_cpus().
extern struct cpu_info *cpu_info;

/// Returns the number of hardware threads (logical CPUs) available to a
/// test.  It is equal to the number of test threads the framework runs.
/// Normally, this value is equal to the number of CPU threads in the
/// device under test but the value can be lower if --cpuset option
/// is used, the tests specifies a value for test.max_threads or the OS
/// restricts the number of CPUs sandstone can see.
int num_cpus() __attribute__((pure));

/// Returns the number of physical CPU packages (a.k.a. sockets) available to a
/// test.
int num_packages() __attribute__((pure));

// CPU reschedule
void reschedule();

#ifdef __cplusplus
}
inline int cpu_info::cpu() const
{
    return this - ::cpu_info;
}

constexpr inline test_flags operator|(test_flag f1, test_flag f2)
{
    return test_flags(unsigned(f1) | unsigned(f2));
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security"
template <typename T, typename... FmtArgs> [[noreturn, gnu::cold]] static inline std::enable_if_t<SandstoneDataDetails::TypeToDataType<T>::IsValid>
memcmp_fail_report(const T *actual, const T *expected, size_t count, const char *fmt, FmtArgs &&... args)
{
    DataType type = SandstoneDataDetails::TypeToDataType<T>::Type;
    size_t elemSize = 1;
    if constexpr (!std::is_same_v<T, void>)
        elemSize = sizeof(T);
    if (SandstoneConfig::NoLogging)
        _memcmp_fail_report(actual, expected, count * elemSize, type, nullptr);
    else
        _memcmp_fail_report(actual, expected, count * elemSize, type, fmt, std::forward<FmtArgs>(args)...);
}

/// compares the arrays actual and expected, both of which are expected to have count elements,
/// and fails the test if the two arrays are not equal.  In the case of a mismatch the calling
/// thread will exit and diagnostic information will be output to the logs to indicate the
/// first mismatch detected.  The fmt and args arguments can be used to provide additional
/// information about the comparison being performed.  These fields are useful if a test performs
/// more than one array comparison.  Note count is the number of elements in each array and
/// not the number of bytes they contain.
template <typename T, typename... FmtArgs> static inline std::enable_if_t<SandstoneDataDetails::TypeToDataType<T>::IsValid>
memcmp_or_fail(const T *actual, const T *expected, size_t count, const char *fmt, FmtArgs &&... args)
{
    size_t elemSize = 1;
    if constexpr (!std::is_same_v<T, void>)
        elemSize = sizeof(T);
    if (__builtin_memcmp(actual, expected, count * elemSize) != 0)
        memcmp_fail_report(actual, expected, count, fmt, std::forward<FmtArgs>(args)...);
}

template <typename T> static inline std::enable_if_t<SandstoneDataDetails::TypeToDataType<T>::IsValid>
memcmp_or_fail(const T *actual, const T *expected, size_t count)
{
    return memcmp_or_fail(actual, expected, count, nullptr);
}
#pragma GCC diagnostic pop

#else
#define memcmp_fail_report(actual, expected, size, fmt, ...)        \
    __extension__ ({                                                \
        enum DataType _type = DATATYPEFORTYPE(*(_actual));          \
        size_t _size2 = sizeof(*_actual) * (size);                  \
        _Pragma("GCC diagnostic push");                             \
        _Pragma("GCC diagnostic ignored \"-Wformat-security\"");    \
        _Pragma("GCC diagnostic ignored \"-Wunused-variable\"");    \
        _memcmp_fail_report((actual), (expected), _size2, _type,    \
                            *(fmt) ? (fmt) : NULL, ##__VA_ARGS__);  \
        _Pragma("GCC diagnostic pop");                              \
    })

#define _memcmp_or_fail(actual, expected, size, fmt, ...)           \
    __extension__ ({                                                \
        __auto_type _actual = (actual);                             \
        __auto_type _expected = (expected);                         \
        size_t _size = sizeof(*_actual) * (size);                   \
        if (__builtin_memcmp(_actual, _expected, _size) != 0)       \
            memcmp_fail_report(_actual, _expected, (size), fmt, ##__VA_ARGS__); \
    })
#define memcmp_or_fail(actual, expected, size, ...) \
    _memcmp_or_fail(actual, expected, size, "" __VA_ARGS__)

#endif

#if SANDSTONE_NO_LOGGING
#  undef log_data
#  undef log_error
#  undef log_warning
#  undef log_info
#  undef report_fail
#  undef report_fail_msg

#  define log_data(message, data, size)     (void)0
#  define log_error(...)                    log_message(thread_num, SANDSTONE_LOG_ERROR "")
#  define log_warning(...)                  (void)0
#  define log_info(...)                     (void)0
#  define report_fail(test)                 _report_fail(test, NULL, 0)
#  define report_fail_msg(...)              _report_fail_msg(NULL, 0, NULL)

#  define log_message(thrnum, msg, ...)     ({ if (msg[0] == SANDSTONE_LOG_ERROR[0]) log_message(thrnum, SANDSTONE_LOG_ERROR); })
#  define log_platform_message(msg, ...)    ({ if (msg[0] == SANDSTONE_LOG_ERROR[0]) log_platform_message(SANDSTONE_LOG_ERROR); })

#  ifdef memcmp_fail_report
#    define _memcmp_fail_report(actual, expected, size, type, ...) \
        _memcmp_fail_report(actual, expected, size, type, NULL)
#  endif
#endif

// Static C++ test runner to instantiate appropriate test class or always skipping one
#ifdef __cplusplus
template<class T>
class TestRunner
{
public:
    TestRunner(void) = delete;

    // test context
    static int init(struct test *test)
    {
        assert((test->data == nullptr) && (!!"Test runner already initialized"));
        T* t = new T(test);
        test->data = t;
        return t->init(test);
    }

    static int run(struct test *test, int cpu)
    {
        assert((test->data != nullptr) && (!!"Test runner not initialized"));
        T* t = static_cast<T*>(test->data);
        return t->run(test, cpu);
    }

    static int cleanup(struct test *test)
    {
        assert((test->data != nullptr) && (!!"Test runner not initialized"));
        T* t = static_cast<T*>(test->data);
        int ret = t->cleanup(test);
        test->data = nullptr;
        delete t;
        return ret;
    }
};

class CpuNotSupported
{
public:
    CpuNotSupported(struct test* test)
    {}

    int init(struct test *test)
    {
        log_skip(CpuNotSupportedSkipCategory, "Not supported on this OS");
        return EXIT_SKIP;
    }

    int run(struct test *test, int cpu)
    {
        __builtin_unreachable();
    }

    int cleanup(struct test *test)
    {
        return EXIT_SUCCESS;
    }
};

class OsNotSupported
{
public:
    OsNotSupported(struct test* test)
    {}

    int init(struct test *test)
    {
        log_skip(OsNotSupportedSkipCategory, "Not supported on this OS");
        return EXIT_SKIP;
    }

    int run(struct test *test, int cpu)
    {
        __builtin_unreachable();
    }

    int cleanup(struct test *test)
    {
        return EXIT_SUCCESS;
    }
};
#endif // __cplusplus

#endif  /* __INCLUDE_GUARD_SANDSTONE_H_ */
