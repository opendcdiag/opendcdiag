/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#ifndef __cplusplus
#include <stdbool.h>
#endif
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>
#include "cpu_features.h"
#include "sandstone_p.h"

#ifdef __x86_64__

#ifndef signature_INTEL_ebx     /* cpuid.h lacks include guards */
#  include <cpuid.h>
#endif

static const size_t x86_locator_count = sizeof(x86_locators) / sizeof(x86_locators[0]);

#ifdef __APPLE__
/*
 * Apple's Darwin kernel for MacOS does not enable AVX-512 state-saving by
 * default in the XCR0 register, so it can catch AVX-512-using code via #UD and
 * allocate the state on-demand, per thread. So we need to check if the kernel
 * knows about AVX-512 in the first place.
 *
 * There's currently no released, Open Source code for AMX we can check.
 */

/* from https://github.com/apple/darwin-xnu/blob/xnu-4903.221.2/osfmk/i386/cpu_capabilities.h */
#define        kHasAVX512F                0x0000004000000000ULL
#define _COMM_PAGE32_BASE_ADDRESS        ( 0xffff0000 )                                /* base address of allocated memory */
#define _COMM_PAGE32_START_ADDRESS        ( _COMM_PAGE32_BASE_ADDRESS )        /* address traditional commpage code starts on */
#define _COMM_PAGE64_BASE_ADDRESS        ( 0x00007fffffe00000ULL )   /* base address of allocated memory */
#define _COMM_PAGE64_START_ADDRESS        ( _COMM_PAGE64_BASE_ADDRESS )        /* address traditional commpage code starts on */
#if defined(__i386__)
#define _COMM_PAGE_START_ADDRESS        _COMM_PAGE32_START_ADDRESS
#else
#define _COMM_PAGE_START_ADDRESS        _COMM_PAGE64_START_ADDRESS
#endif
#define _COMM_PAGE_CPU_CAPABILITIES64        (_COMM_PAGE_START_ADDRESS+0x010)        /* uint64_t _cpu_capabilities */

static uint64_t adjusted_xcr0(uint64_t xcr0, uint64_t xcr0_wanted)
{
    if (xcr0_wanted & XSave_Avx512State) {
        uint64_t capab = *(uint64_t *)_COMM_PAGE_CPU_CAPABILITIES64;
        if (capab & kHasAVX512F)
            xcr0 |= XSave_Avx512State;
    }
    return xcr0;
}
#elif defined(__linux__)
#  include <sys/syscall.h>
#  include <asm/prctl.h>
#  ifndef ARCH_GET_XCOMP_SUPP
#    define ARCH_GET_XCOMP_SUPP     0x1021
#    define ARCH_GET_XCOMP_PERM     0x1022
#    define ARCH_REQ_XCOMP_PERM     0x1023
#  endif // ARCH_GET_XCOMP_SUPP
static uint64_t adjusted_xcr0(uint64_t xcr0, uint64_t xcr0_wanted)
{
    static const uint64_t KernelNonDynamicXSave = XSave_Xtilecfg - 1;

    // Linux doesn't hide XCR0 bits
    xcr0 &= xcr0_wanted;

    // Check if we need to make a dynamic XSAVE request
    if ((xcr0_wanted & ~KernelNonDynamicXSave) == 0)
        return xcr0;            // no, XCR0 is accurate

    // dynamic XSAVE support required, ask for everything
    uint64_t feature_nr = 63 - __builtin_clzll(xcr0_wanted);
    if (syscall(SYS_arch_prctl, ARCH_REQ_XCOMP_PERM, feature_nr) == 0)
        return xcr0_wanted;     // we got it

    // Either ARCH_REQ_XCOMP_PERM isn't supported or the kernel doesn't support
    // XSAVE'ing the feature we asked for (and we can't tell from the errno, since
    // it returns EINVAL for both situations). Ask the kernel what it does support.
    uint64_t xcr0_supported;
    if (syscall(SYS_arch_prctl, ARCH_GET_XCOMP_SUPP, &xcr0_supported) == 0) {
        // The call is supported (Linux >= 5.16). Ask for the highest bit that
        // we want and the kernel supports.
        xcr0_wanted &= xcr0_supported;
        feature_nr = 63 - __builtin_clzll(xcr0_wanted);
        if (syscall(SYS_arch_prctl, ARCH_REQ_XCOMP_PERM, feature_nr) == 0)
            return xcr0_wanted;     // we got it
    }

    // Either Linux < 5.16 or the kernel failed to enable what it told us it
    // supported (can happen if something else has installed a sigaltstack()
    // that is too small).
#  ifndef LINUX_COMPAT_PRE_5_16_AMX_SUPPORT
    xcr0 &= KernelNonDynamicXSave;
#  endif
    return xcr0;
}
#else
static uint64_t adjusted_xcr0(uint64_t xcr0, uint64_t xcr0_wanted)
{
    // no adjustments in this OS
    (void)xcr0_wanted;
    return xcr0;
}
#endif

static cpu_features_t parse_register(enum X86CpuidLeaves leaf, uint32_t reg)
{
    size_t i;
    cpu_features_t features = 0;
    for (i = 0; i < x86_locator_count; ++i) {
        uint32_t locator = x86_locators[i];
        if (locator < leaf * 32 || locator >= (leaf + 1) * 32)
            continue;
        if (reg & (1U << (locator % 32)))
            features |= CPU_FEATURE_CONSTANT(i);
    }
    return features;
};

#if SANDSTONE_NO_LOGGING
#  define cpuid_errmsg(msg)             logging_restricted(LOG_LEVEL_QUIET, msg)
#else
#  define cpuid_errmsg(msg)             fputs(msg, stderr)
#endif

__attribute__((cold, noreturn))
static void detect_cpu_not_supported(const char *msg)
{
    cpuid_errmsg(msg);
    exit(EX_CONFIG);
}

__attribute__((noinline))
static cpu_features_t detect_cpu()
{
    uint32_t eax, ebx, ecx, edx;
    uint32_t max_level = 0;
    cpu_features_t features = 0;

    __cpuid(0, max_level, ebx, ecx, edx);

    eax = ebx = ecx = edx = 0;
    __cpuid(1, eax, ebx, ecx, edx);
    features |= parse_register(Leaf01ECX, ecx);
    features |= parse_register(Leaf01EDX, edx);

    bool osxsave = false;
    if (ecx & (1<<26)) {
        // CPU supports XSAVE
        osxsave = true;
        if ((ecx & (1<<27)) == 0)           // OSXSAVE
            detect_cpu_not_supported("This OS did not enable XSAVE support. Cannot run.\n");
    }

    if (max_level >= 7) {
        __cpuid_count(7, 0, eax, ebx, ecx, edx);
        features |= parse_register(Leaf07_00EBX, ebx);
        features |= parse_register(Leaf07_00ECX, ecx);
        features |= parse_register(Leaf07_00EDX, edx);

        if (eax) {
            __cpuid_count(7, 1, eax, ebx, ecx, edx);
            features |= parse_register(Leaf07_01EAX, eax);
            features |= parse_register(Leaf07_01EDX, edx);
        }
    }
    if (max_level >= 0x0d) {
        __cpuid_count(0x0d, 1, eax, ebx, ecx, edx);
        features |= parse_register(Leaf0D_01EAX, eax);
    }
    if (max_level >= 0x1e) {
        __cpuid_count(0x1e, 0, eax, ebx, ecx, edx);
        if (eax) {
            __cpuid_count(0x1e, 1, eax, ebx, ecx, edx);
            features |= parse_register(Leaf1E_01EAX, eax);
        }
    }
    __cpuid(0x80000001, eax, ebx, ecx, edx);
    features |= parse_register(Leaf80000001ECX, ecx);

    if (max_level >= 0x24 && features & cpu_feature_avx10_1) {
        // extract the version number from CPUID
        __cpuid_count(0x24, 0, eax, ebx, ecx, edx);

        int avx10ver = ebx & 0xff;
        if (avx10ver >= 2)
            features |= cpu_feature_avx10_2;
#ifdef cpu_feature_avx10_3
        if (avx10ver >= 3)
            features |= cpu_feature_avx10_3;
#endif
#ifdef cpu_feature_avx10_4
        if (avx10ver >= 4)
            features |= cpu_feature_avx10_4;
#endif
        assert(avx10ver < 5 && "Internal error: update code above!");
    }

    uint64_t xcr0 = 0;
    uint64_t xcr0_wanted = 0;
    for (const XSaveRequirementMapping xsavereq : xsave_requirements) {
        if (features & xsavereq.cpu_features)
            xcr0_wanted |= xsavereq.xsave_state;
    }

    if (xcr0_wanted && osxsave) {
        uint32_t xcr0_low, xcr0_high;
        asm("xgetbv" : "=a" (xcr0_low), "=d" (xcr0_high) : "c" (0));
        xcr0 = xcr0_low;
        if (xcr0_wanted != (uint32_t)xcr0_wanted)
            xcr0 |= (uint64_t)xcr0_high << 32;      // don't discard %edx
        xcr0 = adjusted_xcr0(xcr0, xcr0_wanted);
    }

    // Check what XSAVE features this OS supports and we're allowed to use.
    // We do not support running on AVX or AVX512-capable processors without
    // the corresponding OS support.
    if ((xcr0_wanted & XSave_Avx512State) != (xcr0 & XSave_Avx512State))
        detect_cpu_not_supported("This kernel did not enable necessary AVX state-saving."
                                 " Cannot run.\n");

    // For everything else, gracefully degrade by disabling the feature.
    for (const XSaveRequirementMapping xsavereq : xsave_requirements) {
        if ((xcr0 & xsavereq.xsave_state) != xsavereq.xsave_state)
            features &= ~xsavereq.cpu_features;
    }
    return features;
}

__attribute__((unused))
static void check_missing_features(cpu_features_t features, cpu_features_t minimum_cpu_features)
{
    cpu_features_t missing = minimum_cpu_features & ~features;
    if (!missing)
        return;

    size_t i;
    cpuid_errmsg("Cannot run on this CPU.\n"
                 "This application requires certain features not found in your CPU:");
    for (i = 0; i < x86_locator_count; ++i) {
        if (missing & CPU_FEATURE_CONSTANT(i))
            fputs(features_string + features_indices[i], stderr);
    }
    fputs("\nexit: invalid\n", stderr);
    _exit(EX_CONFIG);
}

#undef cpuid_errmsg

#else // ! x86-64
static cpu_features_t detect_cpu()
{
    return 0;
}

static void check_missing_features(cpu_features_t features, cpu_features_t minimum_cpu_features)
{
    (void) features;
    (void) minimum_cpu_features;
}

#endif // ! x86-64
