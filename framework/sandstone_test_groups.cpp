/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_p.h"

#if SANDSTONE_RESTRICTED_CMDLINE
#  define TEST_GROUP(name, descr)   .id = nullptr, .description = nullptr
#else
#  define TEST_GROUP(name, descr)   .id = name, .description = descr
#endif

constexpr struct test_group group_compression = {
    TEST_GROUP("compression",
               "Tests that drive compression routines in various libraries"),
};

constexpr struct test_group group_math = {
    TEST_GROUP("math",
               "Tests that perform math using, e.g., Eigen"),
};

constexpr struct test_group group_fuzzing = {
    TEST_GROUP("fuzzing",
               "Tests that fuzz framework functions using AFL++ persistent mode"),
};

#if defined(SANDSTONE_DEVICE_CPU) && defined(__x86_64__)
constexpr struct test_group group_kvm = {
    TEST_GROUP("kvm",
               "Tests that create virtual machines using Linux's KVM support"),
    .group_init = group_kvm_init,
};
#endif

#if SANDSTONE_DEVICE_CPU
namespace {
initfunc group_smt_init() noexcept
{
    auto has_smt = []() -> bool {
        for(int idx = 0; idx < thread_count() - 1; idx++) {
            if (cpu_info[idx].core_id == cpu_info[idx + 1].core_id)
                return true;
        }
        return false;
    };

    if (has_smt()) {
        return nullptr;
    }

    return [](struct test *) {
        log_skip(CpuTopologyIssueSkipCategory, "Test requires SMT (hyperthreading)");
        return -EPERM;
    };
}
}

constexpr struct test_group group_smt = {
    TEST_GROUP("smt",
               "Tests that utilize Simultaneous Multi-Threading(SMT)/Hyperthreading(HT)"),
    .group_init = group_smt_init,
};
#endif
