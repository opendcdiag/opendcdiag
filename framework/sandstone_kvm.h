/*
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

typedef kvm_exit_code_t(*kvmexitfunc)(int vcpu_fd, void *kvm_ctx);

struct kvm_config {
    kvm_addr_mode_t addr_mode;
    size_t ram_size;
    const void *payload;
    const void *payload_end;
    kvmexitfunc exit_handler;
};

int kvm_generic_init(struct test *);
int kvm_generic_run(struct test *, int cpu);
int kvm_generic_cleanup(struct test *);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_GUARD_SANDSTONE_KVM_H_ */
