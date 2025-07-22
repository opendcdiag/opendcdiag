/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"
#include "sandstone_asm.h"

#ifndef __INCLUDE_GUARD_SANDSTONE_KVM_H_
#define __INCLUDE_GUARD_SANDSTONE_KVM_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    KVM_ADDR_MODE_REAL_16BIT = 1,
    KVM_ADDR_MODE_PROTECTED_64BIT,
} kvm_addr_mode_t;

typedef enum {
    /* The VM exit was handled, we can get back to vmx non-root */
    KVM_EXIT_HANDLED = 1,

    /* The VM exit was not handled, we should call into the framework exit handler */
    KVM_EXIT_UNHANDLED,

    /* The VM exit handler failed, and thus the test failed */
    KVM_EXIT_FAILURE,
} kvm_exit_code_t;

typedef kvm_exit_code_t(*kvmexitfunc)(kvm_ctx_t *ctx, struct test *test, int cpu);

/* Called just before the framework executes the kvm payload.  This
 * callback is optional.  Test writers can use it to initialise the VM
 * state, e.g., set up segment registers, populate memory, before the
 * payload is run.
 */
typedef int (*kvmvcpusetup)(kvm_ctx_t *ctx, struct test *test, int cpu);

/* Called just after the kvm payload finishes executing.  This callback
 * is optional.  Test writers can use it to verify the state of the executed
 * VM is correct.  An error can be signalled by returning a value other than
 * EXIT_SUCCESS.
 */
typedef int (*kvmvcpucheck)(kvm_ctx_t *ctx, struct test *test, int cpu);

struct kvm_config {
    kvm_addr_mode_t addr_mode;
    size_t ram_size;
    const void *payload;
    const void *payload_end;
    kvmexitfunc exit_handler;
    kvmvcpusetup setup_handler;
    kvmvcpucheck check_handler;
};

/* kvm context for 1 thread - 1 vm - 1 cpu topology which each sandstone thread
 * carries around for the duration of the test. */
struct kvm_ctx {
    int vm_fd;
    int cpu_fd;
    const kvm_config_t *config;
    uint8_t *ram;
    struct kvm_run *runs;
    uint32_t ram_sz;
    int run_sz;
};

int kvm_generic_init(struct test *);
int kvm_generic_run(struct test *, int cpu);
int kvm_generic_cleanup(struct test *);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_GUARD_SANDSTONE_KVM_H_ */
