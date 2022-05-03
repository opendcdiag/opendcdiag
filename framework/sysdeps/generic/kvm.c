/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdlib.h>

#include "sandstone_kvm.h"


int kvm_generic_run(struct test *test, int cpu)
{
    return EXIT_FAILURE;
}

int kvm_generic_init(struct test *t)
{
    log_info("Virtualization support not implemented on this platform");
    return EXIT_SKIP;
}

int kvm_generic_cleanup(struct test *t)
{
    return EXIT_SUCCESS;
}
