/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdlib.h>

#include "sandstone_kvm.h"

#ifdef __linux__

int kvm_generic_run(struct test *test, int cpu)
{
    return EXIT_FAILURE;
}

int kvm_generic_init(struct test *t)
{
    log_skip(DeviceNotConfiguredSkipCategory, "Virtualization support not implemented on this platform");
    return EXIT_SKIP;
}

int kvm_generic_cleanup(struct test *t)
{
    return EXIT_SUCCESS;
}

#else // !__linux__

int kvm_generic_init(struct test *)
{
    log_skip(OsNotSupportedSkipCategory, "Not supported on this OS");
    return EXIT_SKIP;
}

int kvm_generic_run(struct test *test, int cpu)
{
    __builtin_unreachable();
}

int kvm_generic_cleanup(struct test *)
{
    return EXIT_SUCCESS;
}

#endif

initfunc group_kvm_init(void) __attribute__((nothrow));
initfunc group_kvm_init(void)
{
    return kvm_generic_init;
}
