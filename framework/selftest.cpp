/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#define SANDSTONE_FAKE_FLOAT16

#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/kvm.h>
#include <sys/ioctl.h>
#endif

#include "sandstone.h"
#ifndef _WIN32
#include "sandstone_asm.h"
#include "sandstone_kvm.h"
#endif // _WIN32
#include "sandstone_p.h"

#include "sandstone_tests.h"
#include "SelectorFactory.h"
#include "WeightedRepeatingSelector.h"
#include "WeightedNonRepeatingSelector.h"
#include "PrioritizedSelector.h"
#include "TestrunSelectorBase.h"

#include <exception>
#include <unordered_map>

#ifdef _WIN32
#  include <windows.h>
#endif

using namespace std::chrono;
using namespace std::chrono_literals;

using long_double = long double;
using uint128_t = __uint128_t;
#define FOREACH_DATATYPE(F)         \
    F(uint8_t, 0x55)                \
    F(uint16_t, 0xaaaa)             \
    F(uint32_t, 0x11111111)         \
    F(uint64_t, UINT64_C(0x0102030405060708)) \
    F(uint128_t, (uint128_t(UINT64_C(0x0102030405060708)) << 64) + UINT64_C(0x090a0b0c0d0e0f00)) \
    F(Float16, -1.5f)               \
    F(float, 0.5f)                  \
    F(double, 65535.0)              \
    F(long_double, 4294967296.0L)

struct SelftestException : std::exception
{
    const char *what() const noexcept override
    {
        return "OpenDCDiag C++ selftest exception";
    }
};

static int selftest_pass_run(struct test *test, int cpu)
{
    printf("# This was printed from the test. YOU SHOULD NOT SEE THIS!\n");
    return EXIT_SUCCESS;
}

template <useconds_t Usecs>
static int selftest_timedpass_run(struct test *test, int cpu)
{
    do {
        if (Usecs)
            usleep(Usecs);
    } while (test_time_condition(test));
    return EXIT_SUCCESS;
}

template <useconds_t Usecs>
static int selftest_timedpass_whileloop_run(struct test *test, int cpu)
{
    while (test_time_condition(test)) {
        if (Usecs)
            usleep(Usecs);
    }
    return EXIT_SUCCESS;
}

template <useconds_t Usecs>
static int selftest_timedpass_noloop_run(struct test *test, int cpu)
{
    if (Usecs)
        usleep(Usecs);
    return EXIT_SUCCESS;
}

static int selftest_logs_init(struct test *test)
{
    log_debug("This is a debug message from init function");
    log_info("This is a multiline info message from init function\nSecond line.");
    log_warning("This is a warning message from init function ending in newline\n");
    fputs("*** This was written to stderr ***\n*** in multiple lines ***", stderr);
    return EXIT_SUCCESS;
}

static int selftest_logs_run(struct test *test, int cpu)
{
    log_debug("This is a debug message from cpu %d", cpu);
    log_info("This is a multiline info message from cpu %d\nSecond line.", cpu);
    log_warning("This is a warning message from cpu %d. Random number: %d'", cpu, rand());
    return EXIT_SUCCESS;
}

static int selftest_logdata_run(struct test *test, int cpu)
{
    char buf[] =
            "0123456789" "0123456789" "0123456789"
            "0123456789" "0123456789" "0123456789"
            "0123456";
    log_data("same", buf, sizeof(buf) - 1);

    /* fill it with random data */
    memset_random(buf, sizeof(buf));
    log_data("random", buf, sizeof(buf));

    return EXIT_SUCCESS;
}

static int selftest_log_platform_init(struct test *test)
{
    (void)test;
    log_platform_message(SANDSTONE_LOG_INFO "This is an informational platform message");
    return EXIT_SUCCESS;
}

static int selftest_logs_options_init(struct test *test)
{
    const char *strvalue = get_testspecific_knob_value_string(test, "StringValue", "DefaultValue");
    const char *nullstrvalue = get_testspecific_knob_value_string(test, "NullStringValue", nullptr);
    uint64_t u64 = get_testspecific_knob_value_uint(test, "UIntValue", 0);
    int64_t i64 = get_testspecific_knob_value_int(test, "IntValue", -1);

    // log them
    log_info("StringValue = %s", strvalue);
    if (nullstrvalue)
        log_info("NullStringValue = %s", nullstrvalue);
    if (u64 || i64 != -1)
        log_info("Numbers: %" PRIu64 " %" PRId64, u64, i64);

    return EXIT_SUCCESS;
}

static int selftest_skip_init(struct test *test)
{
    log_info("Requesting skip (this message should be visible)");
    return EXIT_SKIP;
}

static int selftest_skip_run(struct test *test, int cpu)
{
    log_error("We should not reach here");
    abort();
    return EXIT_FAILURE;
}

static int selftest_log_skip_init(struct test *test)
{
    log_skip(SelftestSkipCategory, "This is a skip in init");
    return EXIT_SKIP;
}

static int selftest_log_skip_run(struct test *test, int cpu)
{
    log_skip(SelftestSkipCategory, "Control shouldn't reach here");
    return EXIT_SUCCESS;
}

static int selftest_log_skip_run_all_threads(struct test *test, int cpu)
{
    log_skip(SelftestSkipCategory, "Skipping on all threads");
    return EXIT_SKIP;
}

static int selftest_log_skip_run_even_threads(struct test *test, int cpu)
{
    if (cpu % 2 == 0) {
        log_skip(SelftestSkipCategory, "Skipping on even numbered threads");
        return EXIT_SKIP;
    }
    return EXIT_SUCCESS;
}

static int selftest_log_skip_newline_init(struct test *test)
{
    log_skip(SelftestSkipCategory, "This is a skip in init \nwith a new line.\nWill it work?");
    return EXIT_SKIP;
}

static int selftest_log_skip_newline_run(struct test *test, int cpu)
{
    log_skip(RuntimeSkipCategory, "This message should never be displayed");
    return EXIT_FAILURE;
}

static int selftest_uses_too_much_mem_run(struct test *, int)
{
    static constexpr int Size = 1024 * test_the_test_data<true>::MaxAcceptableMemoryUseKB * 2;
    static constexpr int Count = Size / sizeof(uint32_t);
    std::unique_ptr<uint32_t[]> data(new uint32_t[Count]);

    // fault in the memory, in case the kernel didn't
    for (int i = 0; i < Count; i += 4096)
        data[i] = i;

    // sleep a little so the other threads have a chance to catch up
    usleep(200'000);

    return EXIT_SUCCESS;
}

static int selftest_noreturn_run(struct test *test, int cpu)
{
    struct timespec forever = { LLONG_MAX, 0 };
    nanosleep(&forever, NULL);
    return EXIT_FAILURE;
}

static int selftest_fail_socket1_run(struct test *test, int cpu)
{
    return cpu_info[cpu].package_id == 1 ? EXIT_FAILURE : EXIT_SUCCESS;
}

static int selftest_50pct_freeze_fail_run(struct test *test, int cpu)
{
    if (rand() & 1)
        return selftest_noreturn_run(test, cpu);
    return EXIT_FAILURE;
}

static int selftest_randomprint_init(struct test *test)
{
    log_info("Random number: %#016" PRIx64, random64());
    return EXIT_SUCCESS;
}

template <typename Ratio>
static constexpr unsigned maskFromRatio()
{
    static_assert(Ratio::num == 1, "Numerator must be 1");
    static_assert(__builtin_popcountll(Ratio::den) == 1, "Denominator must be a power of 2");
    int BitPosition = __builtin_ctzll(Ratio::den);

    // because this is constexpr, the following expression will check the range of BitPosition
    return 1U << (BitPosition - 1);
}

template <typename Ratio>
static int selftest_randomfail_run(struct test *test, int cpu)
{
    constexpr unsigned Value = maskFromRatio<Ratio>();
    return rand() % (Value * sApp->thread_count) ? EXIT_SUCCESS : EXIT_FAILURE;
}

template <useconds_t Sleeptime, typename Ratio>
static int selftest_timed_randomfail_run(struct test *test, int cpu)
{
    constexpr unsigned Value = maskFromRatio<Ratio>();

    int i = 0;
    do {
        usleep(Sleeptime);
        ++i;
        if (rand() % (Value * sApp->thread_count))
            continue;
        report_fail_msg("Randomly failing on iteration %d (TTF should be ~%u ms)",
                        i, unsigned(Sleeptime) * i);
    } while (test_time_condition(test));
    return EXIT_SUCCESS;
}

static int selftest_fail_run(struct test *test, int cpu)
{
    return EXIT_FAILURE;
}

static int selftest_failinit_init(struct test *test)
{
    selftest_randomprint_init(test);
    return EXIT_FAILURE;
}

static int selftest_failinit_run(struct test *test, int cpu)
{
    log_error("We should not reach here");
    abort();
    return EXIT_SUCCESS;
}

static int selftest_logerror_run(struct test *test, int cpu)
{
    log_error("This is an error message from CPU %d", cpu);
    return EXIT_SUCCESS;
}

static int selftest_reportfail_run(struct test *test, int cpu)
{
    report_fail(test);
    log_error("We should not reach here");
    abort();
    return EXIT_SUCCESS;
}

static int selftest_reportfailmsg_run(struct test *test, int cpu)
{
    report_fail_msg("Failure message from thread %d", cpu);
    log_error("We should not reach here");
    abort();
    return EXIT_SUCCESS;
}

template <typename T> static T make_datacompare_value();
#define MAKE_DATA_VALUE(Type, Value)    \
    template<> Type make_datacompare_value() { return Value; }
FOREACH_DATATYPE(MAKE_DATA_VALUE)
#undef MAKE_DATA_VALUE

template <typename T> static int selftest_datacomparefail_run(struct test *, int cpu)
{
    constexpr size_t Count = 16;
    T values[Count + 1] = {};

    int diff = (cpu & (Count - 1));
    values[diff] = make_datacompare_value<T>();

    memcmp_or_fail(values, values + 1, Count);
    return EXIT_SUCCESS;
}

static int selftest_cxxthrow_run(struct test *, int cpu) noexcept(false)
{
    throw SelftestException();
    log_error("We should not reach here");
    abort();
    return EXIT_SUCCESS;
}

template <auto F> static void run_crashing_function()
{
    F();
    const char *f = strstr(__PRETTY_FUNCTION__, "[with auto F = ");
    log_warning("Crashing function %s did return", f);
}

template <auto F> static int selftest_crash_initcleanup(struct test *)
{
    run_crashing_function<F>();
    return EXIT_SUCCESS;
}

template <auto F>
static int selftest_crash_run(struct test *test, int cpu)
{
    if (cpu == 1 || sApp->thread_count == 1) {
        usleep(10000);
        run_crashing_function<F>();
    }

    usleep(250'000);
    return EXIT_SUCCESS;
}

static void cause_sigill()
{
    // some values for us to see in the register dump
#ifdef __x86_64__
    uint32_t random = random32();
    int *errno_location = &errno;
    int local_thread_num = thread_num;
    long double ld1 = 1.0L;
    long double ldpi = acosl(-1);
    __m128i i = _mm_setr_epi32(42, 0xfeed, 0xdeadbeef, 0xc0ffee);
    __m128 f = _mm_set_ps(1, 0, -1.5, std::numeric_limits<float>::infinity());
    __m128d d1 = _mm_set_pd(1, std::numeric_limits<double>::epsilon());
    __m128d d2 = _mm_set_pd(std::numeric_limits<double>::quiet_NaN(),
                            -std::numeric_limits<double>::infinity());

    __m128i one = _mm_set1_epi32(-1);
#ifndef __clang__
    if (cpu_has_feature(cpu_feature_avx)) {
        // init the AVX state (using inline assembly to avoid vzeroupper)
        if (cpu_has_feature(cpu_feature_avx512f)) {
            // %gN: make zmm
            asm ("vpternlogd $0xff, %g0, %g0, %g0" : "=x" (one));
        } else {
            // %tN: make ymm
            asm ("vpcmpeqb %t0, %t0, %t0" : "=x" (one));
        }
    }
#endif

    // make sure there are no function calls between the instruction above and the one below

    asm volatile(
#if defined(__clang__) || defined(__APPLE__)
                "ud2" : :           // clang's integrated assembler doesn't support ud1
#else
                "ud1 %0, %1" : :
#endif
                "m" (local_thread_num),
                "a" (42),
                "c" (0xfeed),
                "d" (0xc0ffee),
                "D" (random),
                "S" (errno_location),
                "f" (ld1),      // x87 register
                "f" (ldpi),
                "Yz" (d1),      // force XMM0
                "x" (d2),
                "x" (i),
                "x" (f),
                "x" (one)
                );
#else
    __builtin_trap();
#endif
}

static void cause_sigfpe()
{
#ifdef __x86_64__
    int r = 0;
    asm volatile ("idivl %0, %0" : "+a" (r));
#else
    volatile int r = 0;
    r = r/r;
#endif
}

__attribute__((__no_sanitize_address__))
static int force_memory_load(uintptr_t ptr)
{
    asm("" ::: "memory");
    //    asm volatile ("movl (%1), %0" : "=r" (result) : "r" (ptr));
    return *reinterpret_cast<volatile int *>(ptr);
}

__attribute__((__no_sanitize_address__))
static void force_call(uintptr_t ptr)
{
    asm("" ::: "memory");
    //    asm volatile ("jmp *%0" : : "r" (ptr));
    reinterpret_cast<void (*)(void)>(ptr)();
}

static void cause_sigbus()
{
    // SIGBUS happens if memory can't be faulted in, instead of invalid
    // addresses. We cause that by shrinkingi the file we've memory mapped.
    int fd = open_memfd(MemfdCloseOnExec);
    IGNORE_RETVAL(ftruncate(fd, 4096));
    void *ptr = mmap(nullptr, 4096, PROT_READ, MAP_SHARED, fd, 0);
    IGNORE_RETVAL(ftruncate(fd, 0));

    int result = force_memory_load(uintptr_t(ptr));
    (void) result;

    munmap(ptr, 4096);
    close(fd);
}

static void cause_sigsegv_null()
{
    // not exactly null, but first page
    uintptr_t ptr = rand() & 0xfff;
    int result = force_memory_load(ptr);
    (void) result;
}

static void cause_sigsegv_kernel()
{
    uintptr_t ptr = ~uintptr_t(0) - 64 * 1024 * 1024;
    ptr += rand() & 0xfff;
    int result = force_memory_load(ptr);
    (void) result;
}

static void cause_sigsegv_noncanonical()
{
    // even with Linear Address Masking (LAM), an address is non-canonical if
    // bit 63 and bit 56 (5-level page tables) or bit 47 (4-level) don't match
    uintptr_t ptr = UINT64_C(1) << 63;
    ptr += rand() & 0xfff;
    int result = force_memory_load(ptr);
    (void) result;
}

static void cause_sigsegv_instruction()
{
    uintptr_t ptr = rand() & 0xfff;
    force_call(ptr);
}

static void cause_sigtrap_int3()
{
#ifdef __x86_64__
    asm volatile("int3");
#endif
    raise(SIGTRAP);
}

#ifdef _WIN32
static void raise_fastfail()
{
    asm volatile ("int %0" : : "i" (0x29), "c" (FAST_FAIL_FATAL_APP_EXIT));
}
#else
static void raise_sigkill()
{
    raise(SIGKILL);

}
#endif

static int selftest_malloc_fail(struct test *test, int cpu)
{
    // ask for a very, very silly allocation size, which malloc can't possibly honor
    size_t size = size_t(1) << 62;
    void *ptr = malloc(size);
    int ret = (ptr == NULL ? EXIT_SUCCESS : EXIT_FAILURE);
    free(ptr);
    return ret;
}

static int selftest_oserror_run(struct test *test, int cpu)
{
    _exit(EX_CONFIG);
}

#if defined(STATIC) && defined(__GLIBC__)
extern "C" {
[[noreturn]] void __libc_fatal (const char *message);
}

static int selftest_libc_fatal_run(struct test *, int)
{
    __libc_fatal("__libc_fatal called\n");
}
#endif

#if defined(__linux__) && defined(__x86_64__)
BEGIN_ASM_FUNCTION(payload_long_64bit)
    asm("movabs $0x1234deadbeaf5678, %rax\n"
        "mov    $0x12345, %ebx\n"
        "mov    %rax, (%rbx)\n"
        "mov    (%rbx), %rdx\n"
        "cmp    %rax, %rdx\n"
        "jne    0f\n"
        "mov    $0, %eax\n"
        "hlt\n"
    "0:\n"
        "mov    $1, %eax\n"
        "hlt");
END_ASM_FUNCTION()

static const kvm_config_t kvm_config_long_64bit = {
    .addr_mode = KVM_ADDR_MODE_PROTECTED_64BIT,
    .ram_size = 8 * 1024 * 1024,
    .payload = &payload_long_64bit,
    .payload_end = &payload_long_64bit_end,
};

static const kvm_config_t *selftest_kvm_config_long_64bit()
{
    return &kvm_config_long_64bit;
}

BEGIN_ASM16_FUNCTION(payload_real_16bit)
    asm("mov    $1, %ax\n"
        "test   $1, %ax\n"
        "jz     0f\n"
        "mov    $0, %ax\n"
        "hlt\n"
    "0:"
        "mov    $1, %ax\n"
        "hlt");
END_ASM_FUNCTION()

static const kvm_config_t kvm_config_real_16bit = {
    .addr_mode = KVM_ADDR_MODE_REAL_16BIT,
    .ram_size = 2 * 1024 * 1024,
    .payload = &payload_real_16bit,
    .payload_end = &payload_real_16bit_end
};

static const kvm_config_t *selftest_kvm_config_real_16bit()
{
    return &kvm_config_real_16bit;
}

BEGIN_ASM16_FUNCTION(payload_real_setup_check)
    asm("mov $2, %bx\n"
        "mov (%bx), %dx\n"
        "mov $0, %ax\n"
        "hlt");
END_ASM_FUNCTION()

static int selftest_kvm_setup_check_setup(kvm_ctx_t *ctx, struct test *test, int cpu)
{
    struct kvm_sregs sregs;
    uint16_t ints[2] = { 0xffff, static_cast<uint16_t>(cpu) };

    if (ioctl(ctx->cpu_fd, KVM_GET_SREGS, &sregs) == -1)
        return -errno;
    sregs.ds.base = 0x10000;
    sregs.ds.selector = 0x1000;
    if (ioctl(ctx->cpu_fd, KVM_SET_SREGS, &sregs) == -1)
        return -errno;

    memcpy(ctx->ram + sregs.ds.base, ints, sizeof(ints));

    return EXIT_SUCCESS;
}

static int selftest_kvm_setup_check_check(kvm_ctx_t *ctx, struct test *test, int cpu)
{
    struct kvm_regs regs;

    if (ioctl(ctx->cpu_fd, KVM_GET_REGS, &regs) == -1)
        return -errno;

    if (static_cast<uint16_t>(regs.rdx) != static_cast<uint16_t>(cpu)) {
        log_error("Expected %d got %d\n", static_cast<uint16_t>(cpu),
                      static_cast<uint16_t>(regs.rdx));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static const kvm_config_t kvm_config_real_setup_check = {
    .addr_mode = KVM_ADDR_MODE_REAL_16BIT,
    .ram_size = 2 * 1024 * 1024,
    .payload = &payload_real_setup_check,
    .payload_end = &payload_real_setup_check_end,
    .setup_handler = selftest_kvm_setup_check_setup,
    .check_handler = selftest_kvm_setup_check_check,
};

static const kvm_config_t *selftest_kvm_config_real_setup_check()
{
    return &kvm_config_real_setup_check;
}

BEGIN_ASM_FUNCTION(payload_prot_64bit_fail)
    asm("mov $1, %eax\n"
        "hlt");
END_ASM_FUNCTION()

static const kvm_config_t kvm_config_prot_64bit_fail = {
    .addr_mode = KVM_ADDR_MODE_PROTECTED_64BIT,
    .ram_size = 6 * 1024 * 1024,
    .payload = &payload_prot_64bit_fail,
    .payload_end = &payload_prot_64bit_fail_end
};

static const kvm_config_t *selftest_kvm_config_prot_64bit_fail()
{
    return &kvm_config_prot_64bit_fail;
}

BEGIN_ASM16_FUNCTION(payload_real_16bit_fail)
    asm("mov $1, %ax\n"
        "hlt");
END_ASM_FUNCTION()

static const kvm_config_t kvm_config_real_16bit_fail = {
    .addr_mode = KVM_ADDR_MODE_REAL_16BIT,
    .ram_size = 2 * 1024 * 1024,
    .payload = &payload_real_16bit_fail,
    .payload_end = &payload_real_16bit_fail_end
};

static const kvm_config_t *selftest_kvm_config_real_16bit_fail()
{
    return &kvm_config_real_16bit_fail;
}
#endif // __linux__ && x86-64

const static test_group group_positive = {
    .id = "positive",
    .description = "Self-tests that succeed (positive results)"
};

const static test_group group_fail_test_the_test = {
    .id = "fail_test_the_test",
    .description = "Self-tests that fail --test-tests"
};

const static test_group group_negative = {
    .id = "negative",
    .description = "Self-tests that are expected to fail (negative results)"
};

const static test_group group_random = {
    .id = "random",
    .description = "Self-tests that use random input and may or may not fail"
};

const static test_group group_kvm = {
    .id = "kvm",
    .description = "Self-tests that launch virtual machines"
};

static struct test selftests_array[] = {
{
    .id = "selftest_pass",
    .description = "Just pass",
    .groups = DECLARE_TEST_GROUPS(&group_positive),
    .test_run = selftest_pass_run,
    .desired_duration = -1,
},
{
    .id = "selftest_pass_low_quality",
    .description = "Just pass",
    .groups = DECLARE_TEST_GROUPS(&group_positive),
    .test_run = selftest_pass_run,
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_SKIP,
},
{
    .id = "selftest_timedpass",
    .description = "Loops around usleep() for the regular test time",
    .groups = DECLARE_TEST_GROUPS(&group_positive),
    .test_run = selftest_timedpass_run<10'000>,
},
{
    .id = "selftest_logs",
    .description = "Adds some debug, info and warning messages",
    .groups = DECLARE_TEST_GROUPS(&group_positive),
    .test_init = selftest_logs_init,
    .test_run = selftest_logs_run,
    .desired_duration = -1,
    .max_threads = 3,
},
{
    .id = "selftest_logdata",
    .description = "Logs data for later parsing",
    .groups = DECLARE_TEST_GROUPS(&group_positive),
    .test_run = selftest_logdata_run,
    .desired_duration = -1,
},
{
    .id = "selftest_log_platform",
    .description = "Logs platform messages (not related to the test)",
    .groups = DECLARE_TEST_GROUPS(&group_positive),
    .test_init = selftest_log_platform_init,
    .test_run = selftest_pass_run,
    .desired_duration = -1,
},
{
    .id = "selftest_logs_options",
    .description = "Logs some command-line options",
    .groups = DECLARE_TEST_GROUPS(&group_positive),
    .test_init = selftest_logs_options_init,
    .test_run = selftest_pass_run,
    .desired_duration = -1,
},
{
    .id = "selftest_skip",
    .description = "Skipped test",
    .groups = DECLARE_TEST_GROUPS(&group_positive),
    .test_init = selftest_skip_init,
    .test_run = selftest_skip_run,
    .desired_duration = -1,
},
{
    .id = "selftest_log_skip_init",
    .description = "This test will test the log_skip feature in the init function",
    .groups = DECLARE_TEST_GROUPS(&group_positive),
    .test_init = selftest_log_skip_init,
    .test_run = selftest_log_skip_run,
    .desired_duration = -1,
},
{
    .id = "selftest_log_skip_run_all_threads",
    .description = "This test will test the log_skip feature in the run function where all threads skip",
    .groups = DECLARE_TEST_GROUPS(&group_positive),
    .test_run = selftest_log_skip_run_all_threads,
    .desired_duration = -1,
},
{
    .id = "selftest_log_skip_run_even_threads",
    .description = "This test will test the log_skip feature in the run function where only even numbered threads skip",
    .groups = DECLARE_TEST_GROUPS(&group_positive),
    .test_run = selftest_log_skip_run_even_threads,
    .desired_duration = -1,
},
{
    .id = "selftest_log_skip_newline",
    .description = "This test will test the log_skip feature in the init function where there are newlines in the message",
    .groups = DECLARE_TEST_GROUPS(&group_positive),
    .test_init = selftest_log_skip_newline_init,
    .test_run = selftest_log_skip_newline_run,
    .desired_duration = -1,
},
{
    .id = "selftest_maybe_skip_750ms",
    .description = "Requests to run for 750 ms (could be skipped)",
    .groups = DECLARE_TEST_GROUPS(&group_positive),
    .test_run = selftest_timedpass_run<(7500us).count()>,
    .desired_duration = 750
},

{
    .id = "selftest_timedpass_busywait",
    .description = "Runs for the requested time, but busy-waiting", // or practically so
    .groups = DECLARE_TEST_GROUPS(&group_positive, &group_fail_test_the_test),
    .test_run = selftest_timedpass_run<0>,
    .desired_duration = 200
},
{
    .id = "selftest_timedpass_tooshort",
    .description = "Runs for the requested time, but each loop is too short",
    .groups = DECLARE_TEST_GROUPS(&group_positive, &group_fail_test_the_test),
    .test_run = selftest_timedpass_run<(250us).count()>,
    .desired_duration = 200
},
{
    .id = "selftest_timedpass_toolong",
    .description = "Runs for the requested time, but each loop is too long",
    .groups = DECLARE_TEST_GROUPS(&group_positive, &group_fail_test_the_test),
    .test_run = selftest_timedpass_run<duration_cast<microseconds>(test_the_test_data<true>::MaximumLoopDuration).count() * 2>,
},
{
    .id = "selftest_timedpass_whileloop",
    .description = "Runs for the requested time, but uses a while () loop instead of do {} while ()",
    .groups = DECLARE_TEST_GROUPS(&group_positive, &group_fail_test_the_test),
    .test_run = selftest_timedpass_whileloop_run<10'000>,
    .desired_duration = 200,
},
{
    .id = "selftest_timedpass_noloop",
    .description = "Runs for the requested time, but doesn't loop at all",
    .groups = DECLARE_TEST_GROUPS(&group_positive, &group_fail_test_the_test),
    .test_run = selftest_timedpass_noloop_run<10'000>,
    .desired_duration = 200,
},
{
    .id = "selftest_uses_too_much_mem",
    .description = "Allocates and uses too much memory",
    .groups = DECLARE_TEST_GROUPS(&group_positive, &group_fail_test_the_test),
    .test_run = selftest_uses_too_much_mem_run,
    .desired_duration = -1,
},
{
    .id = "selftest_timedpass_maxthreads1",
    .description = "Runs for the requested time, but on single thread",
    .test_run = selftest_timedpass_noloop_run<(50000us).count()>,
    .max_threads = 1,
},

#if defined(__linux__) && defined(__x86_64__)
{
    .id = "kvm_long_64bit",
    .description = "Runs simple 64-bit KVM workload successfully",
    .groups = DECLARE_TEST_GROUPS(&group_positive, &group_kvm),
    .test_kvm_config = selftest_kvm_config_long_64bit,
    .flags = test_type_kvm,
},
{
    .id = "kvm_real_16bit",
    .description = "Runs simple 16-bit KVM workload successfully",
    .groups = DECLARE_TEST_GROUPS(&group_positive, &group_kvm),
    .test_kvm_config = selftest_kvm_config_real_16bit,
    .flags = test_type_kvm,
},
{
    .id = "kvm_real_setup_check",
    .description = "Checks the setup and check handlers are called correctly",
    .groups = DECLARE_TEST_GROUPS(&group_positive, &group_kvm),
    .test_kvm_config = selftest_kvm_config_real_setup_check,
    .flags = test_type_kvm,
},
#endif // __linux__

    /* Randomly failing tests */

{
    .id = "selftest_randomfail_50pct",
    .description = "Fails about 50% of the time, randomly",
    .groups = DECLARE_TEST_GROUPS(&group_random),
    .test_run = selftest_randomfail_run<std::ratio<1, 2>>,
    .desired_duration = -1,
    .max_threads = 3,
},
{
    .id = "selftest_randomfail_rare",
    .description = "Fails less than 0.1% of the time, randomly",
    .groups = DECLARE_TEST_GROUPS(&group_random),
    .test_run = selftest_randomfail_run<std::ratio<1, 1024>>,
    .desired_duration = -1,
    .max_threads = 3,
},
{
    .id = "selftest_timed_randomfail_25pct",
    .description = "Randomly fails about 25% of the time, every 100 ms",
    .groups = DECLARE_TEST_GROUPS(&group_random),
    .test_run = selftest_timed_randomfail_run<100'000, std::ratio<1, 4>>,
    .fracture_loop_count = 4,
},
{
    .id = "selftest_timed_randomfail_rare",
    .description = "Randomly fails less than 0.1% of the time, every 10 ms",
    .groups = DECLARE_TEST_GROUPS(&group_random),
    .test_run = selftest_timed_randomfail_run<10'000, std::ratio<1, 1024>>,
    .fracture_loop_count = 4,
},

    /* Multi-socket tests */
{
    .id = "selftest_fail_socket1",
    .description = "Fails on any thread of socket 1",
    .groups = nullptr, // positive on single-socket systems, negative on multi-socket
    .test_run = selftest_fail_socket1_run,
    .desired_duration = -1,
},

    /* Negative tests */

{
    .id = "selftest_fail",
    .description = "Fails by way of returning",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_init = selftest_randomprint_init,
    .test_run = selftest_fail_run,
    .desired_duration = -1,
},
{
    .id = "selftest_failinit",
    .description = "Fails in the init function",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_init = selftest_failinit_init,
    .test_run = selftest_failinit_run,
    .desired_duration = -1,
},
{
    .id = "selftest_logerror",
    .description = "Fails by calling log_error()",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_logerror_run,
    .desired_duration = -1,
},
{
    .id = "selftest_reportfail",
    .description = "Fails by calling report_fail()",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_init = selftest_randomprint_init,
    .test_run = selftest_reportfail_run,
    .desired_duration = -1,
},
{
    .id = "selftest_reportfailmsg",
    .description = "Fails by calling report_fail_msg()",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_init = selftest_randomprint_init,
    .test_run = selftest_reportfailmsg_run,
    .desired_duration = -1,
},
#if defined(STATIC) && defined(__GLIBC__)
{
    .id = "selftest_libc_fatal",
    .description = "Calls __libc_fatal",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_libc_fatal_run,
    .desired_duration = -1,
},
#endif

#define DATACOMPARE_TEST(Type, Value)                                   \
{                                                                       \
    .id = "selftest_datacomparefail_" SANDSTONE_STRINGIFY(Type),        \
    .description = "Attempts to compare one " SANDSTONE_STRINGIFY(Type),       \
    .groups = DECLARE_TEST_GROUPS(&group_negative),                     \
    .test_run = selftest_datacomparefail_run<Type>,                     \
    .desired_duration = -1,                                             \
},
FOREACH_DATATYPE(DATACOMPARE_TEST)
#undef DATACOMPARE_TEST

{
    .id = "selftest_cxxthrow",
    .description = "Throws C++ exception",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_cxxthrow_run,
    .desired_duration = -1,
},
{
    .id = "selftest_abort",
    .description = "Aborts",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_crash_run<abort>,
    .desired_duration = -1,
},
{
    .id = "selftest_abortinit",
    .description = "Aborts on init",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_init = selftest_crash_initcleanup<abort>,
    .test_run = selftest_pass_run,
    .desired_duration = -1,
},
{
    .id = "selftest_sigill",
    .description = "Crashes with SIGILL",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_crash_run<cause_sigill>,
    .desired_duration = -1,
},
{
    .id = "selftest_sigfpe",
    .description = "Crashes with SIGFPE",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_crash_run<cause_sigfpe>,
    .desired_duration = -1,
},
{
    .id = "selftest_sigbus",
    .description = "Crashes with SIGBUS",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_crash_run<cause_sigbus>,
    .desired_duration = -1,
},
{
    .id = "selftest_sigsegv_init",
    .description = "Crashes with SIGSEGV (data) on init",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_init = selftest_crash_initcleanup<cause_sigsegv_null>,
    .test_run = selftest_pass_run,
    .desired_duration = -1,
},
{
    .id = "selftest_sigsegv",
    .description = "Crashes with SIGSEGV (data) dereferencing the null page",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_crash_run<cause_sigsegv_null>,
    .desired_duration = -1,
},
{
    .id = "selftest_sigsegv_noncanonical",
    .description = "Crashes with SIGSEGV (data) with a non-canonical address",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_crash_run<cause_sigsegv_noncanonical>,
    .desired_duration = -1,
},
{
    .id = "selftest_sigsegv_kernel",
    .description = "Crashes with SIGSEGV (data) on a kernel address",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_crash_run<cause_sigsegv_kernel>,
    .desired_duration = -1,
},
{
    .id = "selftest_sigsegv_cleanup",
    .description = "Crashes with SIGSEGV (data) on cleanup",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_pass_run,
    .test_cleanup  = selftest_crash_initcleanup<cause_sigsegv_null>,
    .desired_duration = -1,
},
{
    .id = "selftest_sigsegv_instruction",
    .description = "Crashes with SIGSEGV (instruction)",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_crash_run<cause_sigsegv_instruction>,
    .desired_duration = -1,
},
{
    .id = "selftest_sigtrap_int3",
    .description = "Crashes with SIGTRAP (int3 instruction)",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_crash_run<cause_sigtrap_int3>,
    .desired_duration = -1,
},
#ifdef _WIN32
{
    .id = "selftest_fastfail",
    .description = "Executes __fastfail()",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_crash_run<raise_fastfail>,
    .desired_duration = -1,
},
#else
{
    .id = "selftest_sigkill",
    .description = "Raises SIGKILL",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_crash_run<raise_sigkill>,
    .desired_duration = -1,
},
#endif
{
    .id = "selftest_malloc_fail",
    .description = "Attempts to malloc a silly amount of memory",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_malloc_fail,
    .desired_duration = -1,
},
{
    .id = "selftest_oserror",
    .description = "Exits the test with an operating system error",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_oserror_run,
    .desired_duration = -1,
},
{
    .id = "selftest_freeze",
    .description = "Freezes",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_noreturn_run,
    .desired_duration = -1,
},
{
    .id = "selftest_50pct_freeze_fail",
    .description = "Freezes 50% of the time",
    .groups = DECLARE_TEST_GROUPS(&group_negative),
    .test_run = selftest_50pct_freeze_fail_run,
    .desired_duration = -1,
},

#if defined(__linux__) && defined(__x86_64__)
{
    .id = "kvm_prot_64bit_fail",
    .description = "Runs simple 64-bit KVM workload that fails",
    .groups = DECLARE_TEST_GROUPS(&group_negative, &group_kvm),
    .test_kvm_config = selftest_kvm_config_prot_64bit_fail,
    .desired_duration = -1,
    .flags = test_type_kvm,
},
{
    .id = "kvm_real_16bit_fail",
    .description = "Runs simple 16-bit KVM workload that fails",
    .groups = DECLARE_TEST_GROUPS(&group_negative, &group_kvm),
    .test_kvm_config = selftest_kvm_config_real_16bit_fail,
    .desired_duration = -1,
    .flags = test_type_kvm,
}
#endif // __linux__
};

const std::span<struct test> selftests = { std::begin(selftests_array), std::end(selftests_array) };
