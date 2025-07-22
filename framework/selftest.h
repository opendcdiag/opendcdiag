/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SELFTEST_HPP
#define SELFTEST_HPP

#include "sandstone.h"
#include "sandstone_p.h"

#include <cinttypes>


const static test_group group_positive = {
    .id = "positive",
    .description = "Self-tests that succeed (positive results)"
};

const static test_group group_selftest_passes = {
    .id = "selftest_passes",
    .description = "Group for selftest_pass* tests"
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

inline int selftest_log_skip_init(struct test *test)
{
    log_skip(SelftestSkipCategory, "This is a skip in init");
    return EXIT_SUCCESS;
}

inline int selftest_skip_run(struct test *test, int cpu)
{
    log_error("We should not reach here");
    abort();
    return EXIT_FAILURE;
}

inline int selftest_pass_run(struct test *test, int cpu)
{
    printf("# This was printed from the test. YOU SHOULD NOT SEE THIS!\n");
    return EXIT_SUCCESS;
}

inline int selftest_fail_run(struct test *test, int cpu)
{
    return EXIT_FAILURE;
}

inline int selftest_randomprint_init(struct test *test)
{
    log_info("Random number: %#016" PRIx64, random64());
    return EXIT_SUCCESS;
}

inline int selftest_failinit_init(struct test *test)
{
    selftest_randomprint_init(test);
    return EXIT_FAILURE;
}

inline int selftest_noreturn_run(struct test *test, int cpu)
{
    struct timespec forever = { LLONG_MAX, 0 };
    nanosleep(&forever, NULL);
    return EXIT_FAILURE;
}

__attribute__((__no_sanitize_address__))
inline int force_memory_load(uintptr_t ptr)
{
    asm("" ::: "memory");
    //    asm volatile ("movl (%1), %0" : "=r" (result) : "r" (ptr));
    return *reinterpret_cast<volatile int *>(ptr);
}

inline void cause_sigsegv_null()
{
    // not exactly null, but first page
    uintptr_t ptr = rand() & 0xfff;
    int result = force_memory_load(ptr);
    (void) result;
}

template <auto F> inline void run_crashing_function()
{
    F();
    const char *f = strstr(__PRETTY_FUNCTION__, "[with auto F = ");
    log_warning("Crashing function %s did return", f);
}

template <auto F> inline int selftest_crash_initcleanup(struct test *)
{
    run_crashing_function<F>();
    return EXIT_SUCCESS;
}

template <auto F>
inline int selftest_crash_run(struct test *test, int cpu)
{
    if (cpu == 1 || sApp->thread_count == 1) {
        usleep(10000);
        run_crashing_function<F>();
    }

    usleep(250'000);
    return EXIT_SUCCESS;
}

#endif //SELFTEST_HPP
