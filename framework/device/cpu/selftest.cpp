/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "selftest.h"

#include "sandstone.h"
#include "sandstone_p.h"
#ifndef _WIN32
#include "sandstone_asm.h"
#include "sandstone_kvm.h"
#endif // _WIN32

#ifdef __linux__
#include <linux/kvm.h>
#include <sys/ioctl.h>
#endif

#ifdef __x86_64__
#  include "amx_common.h"
#endif

#ifdef _WIN32
#  include <windows.h>
#endif

#include <semaphore.h>

static int get_cpu()
{
    int cpu_number = -1;
#if defined(_WIN32)
    PROCESSOR_NUMBER number;
    GetCurrentProcessorNumberEx(&number);
    // see win32/cpu_affinity.cpp
    cpu_number = number.Group * 64 + number.Number;
#elif defined(__linux__) || defined(__FreeBSD__)
    cpu_number = sched_getcpu();
#else
    errno = ENOSYS;
    log_skip(OSResourceIssueSkipCategory, "OS failed: %m");
    return -1;
#endif
    return cpu_number;
}

static int selftest_logs_getcpu_run(struct test *test, int cpu)
{
    int cpu_number = get_cpu();
    log_info("%d", cpu_number);
    return EXIT_SUCCESS;
}

static int selftest_logs_reschedule_init(struct test *test)
{
    // In order to always get the same result and avoid race conditions,
    // we use semaphores to synchronize the access to reschedule()
    int sem_size = num_cpus() - 1;
    sem_t *reschedule_sem = (sem_t *) calloc(sem_size, sizeof(sem_t));
    for (int i = 0; i < sem_size; i++) {
        sem_init(&reschedule_sem[i], 0, 0);
    }

    test->data = (void *) reschedule_sem;

    return EXIT_SUCCESS;
}

static int selftest_logs_reschedule_run(struct test *test, int cpu)
{
    sem_t *semaphores = (sem_t *) test->data;
    int cpu_number = get_cpu();
    log_info("%d", cpu_number);

    // Let's wait unit previous CPU has finished
    if (cpu > 0)
        sem_wait(&semaphores[cpu-1]);

    reschedule();

    // When we finish, instruct next thread it can proceed
    // unless we are the last one
    if (cpu < num_cpus()-1)
        sem_post(&semaphores[cpu]);

    cpu_number = get_cpu();
    log_info("%d", cpu_number);

    return EXIT_SUCCESS;
}

static int selftest_logs_reschedule_cleanup(struct test *test)
{
    sem_t *reschedule_sem = (sem_t *) test->data;
    for (int i = 0; i < num_cpus() - 1; i++) {
        sem_destroy(&reschedule_sem[i]);
    }
    free (reschedule_sem);
    return EXIT_SUCCESS;
}

template <int PackageId> static int selftest_log_skip_socket_init(struct test *test)
{
    if (num_packages() == 1 && cpu_info[0].package_id == PackageId)
        return selftest_log_skip_init(test);
    return EXIT_SUCCESS;
}

template <int PackageId> static int selftest_log_skip_socket_run(struct test *test, int cpu)
{
    if (num_packages() == 1 && cpu_info[0].package_id == PackageId)
        return selftest_skip_run(test, cpu);
    return EXIT_SUCCESS;
}

static int adjust_cpu_for_isolate_socket(int cpu)
{
    // pretend we're running in test_schedule_isolate_socket
    for (int cpu0 = cpu - 1; cpu0 >= 0; --cpu0) {
        if (cpu_info[cpu0].package_id == cpu_info[cpu].package_id)
            continue;
        return cpu - cpu0 - 1;
    }
    // no adjustment necessary -- we are in test_schedule_isolate_socket
    return cpu;
}

template <auto F> static int selftest_if_socket1_initcleanup(struct test *test)
{
    if (cpu_info[0].package_id == 1)
        return F(test);
    return EXIT_SUCCESS;
}

template <auto F> static int selftest_if_socket1_run(struct test *test, int cpu)
{
    if (cpu_info[cpu].package_id == 1)
        return F(test, adjust_cpu_for_isolate_socket(cpu));
    return EXIT_SUCCESS;
}

#if defined(__linux__) && defined(__x86_64__) && !defined(__clang__)
const static test_group group_kvm = {
    .id = "kvm",
    .description = "Self-tests that launch virtual machines"
};

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
        "fld1\n"
        "pcmpeqb %xmm0, %xmm0\n"                // init SSE state

        "cpuid\n"
        "test $((1 << 27) | (1 << 28)), %ecx\n"
        "mov $2, %eax\n"
        "jz 9f\n"
        "vcmpeqps %ymm1, %ymm1, %ymm1\n"        // init AVX state

        "mov $7, %eax\n"
        "xor %ecx, %ecx\n"
        "cpuid\n"
        "test $(1 << 16), %ebx\n"
        "mov $3, %eax\n"
        "jz 9f\n"
        "vpternlogd $0xff, %zmm16, %zmm16, %zmm16\n"
        "vpcmpeqb %zmm16, %zmm16, %k1\n"        // init AVX512 state

        "mov $7, %eax\n"
        "mov $1, %ecx\n"
        "cpuid\n"
        "test $(1 << 21), %edx\n"
        "mov $4, %eax\n"
        "jz 9f\n"
        ".byte 0xd5, 0x18; inc %eax\n"          // init APX state

        ".align 16\n"
        "9: hlt");
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
        "fld1\n"
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

static struct test selftests_array[] = {
{
    .id = "selftest_logs_getcpu",
    .description = "Logs the getcpu() result",
    .groups = DECLARE_TEST_GROUPS(&group_positive),
    .test_run = selftest_logs_getcpu_run,   // may skip
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_PROD,
},
{
    .id = "selftest_logs_reschedule",
    .description = "Logs the getcpu() result before and after rescheduling",
    .groups = DECLARE_TEST_GROUPS(&group_positive),
    .test_init = selftest_logs_reschedule_init,
    .test_run = selftest_logs_reschedule_run,   // may skip
    .test_cleanup = selftest_logs_reschedule_cleanup,
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_PROD,
},
{
    .id = "selftest_log_skip_init_socket0",
    .description = "Skips using log_skip() in the init function only in socket 0",
    .groups = DECLARE_TEST_GROUPS(&group_positive),
    .test_init = selftest_log_skip_socket_init<0>,
    .test_run = selftest_log_skip_socket_run<0>,
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_PROD,
},
{
    .id = "selftest_log_skip_init_socket1",
    .description = "Skips using log_skip() in the init function only in socket 1",
    .groups = DECLARE_TEST_GROUPS(&group_positive),
    .test_init = selftest_log_skip_socket_init<1>,
    .test_run = selftest_log_skip_socket_run<1>,
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_PROD,
},
#if defined(__linux__) && defined(__x86_64__) && !defined(__clang__)
{
    .id = "kvm_long_64bit",
    .description = "Runs simple 64-bit KVM workload successfully",
    .groups = DECLARE_TEST_GROUPS(&group_positive, &group_kvm),
    .test_kvm_config = selftest_kvm_config_long_64bit,
    .quality_level = TEST_QUALITY_PROD,
    .flags = test_type_kvm,
},
{
    .id = "kvm_real_16bit",
    .description = "Runs simple 16-bit KVM workload successfully",
    .groups = DECLARE_TEST_GROUPS(&group_positive, &group_kvm),
    .test_kvm_config = selftest_kvm_config_real_16bit,
    .quality_level = TEST_QUALITY_PROD,
    .flags = test_type_kvm,
},
{
    .id = "kvm_real_setup_check",
    .description = "Checks the setup and check handlers are called correctly",
    .groups = DECLARE_TEST_GROUPS(&group_positive, &group_kvm),
    .test_kvm_config = selftest_kvm_config_real_setup_check,
    .quality_level = TEST_QUALITY_PROD,
    .flags = test_type_kvm,
},
{
    .id = "kvm_prot_64bit_fail",
    .description = "Runs simple 64-bit KVM workload that fails",
    .groups = DECLARE_TEST_GROUPS(&group_negative, &group_kvm),
    .test_kvm_config = selftest_kvm_config_prot_64bit_fail,
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_PROD,
    .flags = test_type_kvm,
},
{
    .id = "kvm_real_16bit_fail",
    .description = "Runs simple 16-bit KVM workload that fails",
    .groups = DECLARE_TEST_GROUPS(&group_negative, &group_kvm),
    .test_kvm_config = selftest_kvm_config_real_16bit_fail,
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_PROD,
    .flags = test_type_kvm,
},
#endif // __linux__

    /* Multi-socket tests */
{
    .id = "selftest_failinit_socket1",
    .description = "Fails on init for socket 1",
    .groups = nullptr, // positive on single-socket systems, negative on multi-socket
    .test_init = selftest_if_socket1_initcleanup<selftest_failinit_init>,
    .test_run = selftest_pass_run,
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_PROD,
},
{
    .id = "selftest_fail_socket1",
    .description = "Fails on any thread of socket 1",
    .groups = nullptr, // positive on single-socket systems, negative on multi-socket
    .test_run = selftest_if_socket1_run<selftest_fail_run>,
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_PROD,
},
{
    .id = "selftest_freeze_socket1",
    .description = "Freezes on any thread of socket 1",
    .groups = nullptr, // positive on single-socket systems, negative on multi-socket
    .test_run = selftest_if_socket1_run<selftest_noreturn_run>,
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_PROD,
},
{
    .id = "selftest_sigsegv_init_socket1",
    .description = "Crashes with SIGSEGV (data) on init for socket 1",
    .groups = nullptr, // positive on single-socket systems, negative on multi-socket
    .test_init = selftest_if_socket1_initcleanup<selftest_crash_initcleanup<cause_sigsegv_null>>,
    .test_run = selftest_pass_run,
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_PROD,
},
{
    .id = "selftest_sigsegv_socket1",
    .description = "Crashes with SIGSEGV (data) dereferencing the null page for any thread of socket 1",
    .groups = nullptr, // positive on single-socket systems, negative on multi-socket
    .test_run = selftest_if_socket1_run<selftest_crash_run<cause_sigsegv_null>>,
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_PROD,
},
};

extern const std::span<struct test> selftests_device;
const std::span<struct test> selftests_device = { std::begin(selftests_array), std::end(selftests_array) };