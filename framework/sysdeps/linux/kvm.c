/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include <asm/kvm.h>
#include <asm/processor-flags.h>
#include <linux/kvm.h>

#include "sandstone_kvm.h"

#define KVM_EXIT_X86_RDMSR        29
#define KVM_EXIT_X86_WRMSR        30
#define KVM_EXIT_XEN              34
#define KVM_EXIT_NOTIFY           37

/* KVM_EXIT_FAIL_ENTRY */
struct sandstone_kvm_fail_entry {
    __u64 hardware_entry_failure_reason;
    __u32 cpu;
};

/*KVM_EXIT_X86_RDMSR && KVM_EXIT_X86_WRMSR*/
struct sandstone_kvm_exit_x86_read_write_msr {
    __u8 error;
    __u32 reason;
} msr;

/*KVM_EXIT_XEN*/
struct sandstone_kvm_xen_exit {
       __u32 type;
};

/*KVM_EXIT_NOTIFY*/
struct kvm_notify {
    __u32 flags;
};

int kvm_fd = -1;

#define PAYLOAD_GUEST_ENTRY 0x1000

#define DEFAULT_RAM_SIZE (2 * 1024 * 1024)

#define IOCTL_OR_RET(...) do {          \
        int ret = ioctl(__VA_ARGS__);   \
        if (ret == -1) return -errno;   \
    } while (0)

/* 2MB bit */
#define GUEST_PAGE_BITS    21
#define GUEST_PAGE_SIZE    (1 << GUEST_PAGE_BITS)

/* Max 1GB of memory */
#define GUEST_PAGE_MAX_NUM      512
/* Reserved space at the beginning of guest RAM */
#define GUEST_PAGE_RESERVED     2
#define GUEST_MEM_PROT64_RESERVED   (GUEST_PAGE_RESERVED << GUEST_PAGE_BITS)
/* 1. First page reserved for detecting null-pointer reference */
/* 2. Second page reserved: */
/* 2.1. first half page (1M): for GDT, and page tables */
#define BOOT_GDT       (GUEST_PAGE_SIZE)
#define PML4_ADDR      (GUEST_PAGE_SIZE + 0x1000)
#define PDPT_0_ADDR    (GUEST_PAGE_SIZE + 0x2000)
#define PDT_0_ADDR     (GUEST_PAGE_SIZE + 0x3000)
/* 2.1. second half page (1M): for payload */
#define PAYLOAD_ADDR_PROT64    (GUEST_PAGE_SIZE + GUEST_PAGE_SIZE/2)

#define BOOT_GDT_NULL   0
#define BOOT_GDT_CODE   1
#define BOOT_GDT_DATA   2
#define BOOT_GDT_MAX    3

/*
 * We need to build a kvm_segment struct to represent each
 * of the GDT entries we've created. These macros help keep
 * the entries consistent by automatically building the
 * struct based on the gdt fields
 */
#define GDT_GET_BASE(x) \
        (( (x) & 0xFF00000000000000) >> 32) |       \
        (( (x) & 0x000000FF00000000) >> 16) |       \
        (( (x) & 0x00000000FFFF0000) >> 16)

#define GDT_GET_LIMIT(x) (uint32_t)(                \
        (( (x) & 0x000F000000000000) >> 32) |       \
        (( (x) & 0x000000000000FFFF)))

#define GDT_GET_G(x)   (uint8_t)(( (x) & 0x0080000000000000) >> 55)
#define GDT_GET_DB(x)  (uint8_t)(( (x) & 0x0040000000000000) >> 54)
#define GDT_GET_L(x)   (uint8_t)(( (x) & 0x0020000000000000) >> 53)
#define GDT_GET_AVL(x) (uint8_t)(( (x) & 0x0010000000000000) >> 52)
#define GDT_GET_P(x)   (uint8_t)(( (x) & 0x0000800000000000) >> 47)
#define GDT_GET_DPL(x) (uint8_t)(( (x) & 0x0000600000000000) >> 45)
#define GDT_GET_S(x)   (uint8_t)(( (x) & 0x0000100000000000) >> 44)
#define GDT_GET_TYPE(x)(uint8_t)(( (x) & 0x00000F0000000000) >> 40)

/* Constructor for a conventional segment GDT (or LDT) entry */
/* This is a macro so it can be used in initializers */
#define GDT_ENTRY(flags, base, limit)              \
    ((((base) & UINT64_C(0xff000000)) << (56-24)) | \
    (((flags) & UINT64_C(0x0000f0ff)) << 40) |      \
    (((limit) & UINT64_C(0x000f0000)) << (48-16)) | \
    (((base)  & UINT64_C(0x00ffffff)) << 16) |      \
    (((limit) & UINT64_C(0x0000ffff))))


static int kvm_generic_create_vm(int kvm_fd)
{
    return ioctl(kvm_fd, KVM_CREATE_VM, 0);
}

static int kvm_generic_reset_vcpu(kvm_ctx_t *ctx, struct kvm_regs *regs)
{
    struct kvm_regs lregs;
    if (!regs) {
        IOCTL_OR_RET(ctx->cpu_fd, KVM_GET_REGS, &lregs);
        regs = &lregs;
    }

    /* bit 1 must be always set in eflags */
    regs->rflags = 0x2;
    regs->rdx = 0x600;

    switch (ctx->config->addr_mode) {
        case KVM_ADDR_MODE_REAL_16BIT:
            regs->rip = PAYLOAD_GUEST_ENTRY;
            break;
        case KVM_ADDR_MODE_PROTECTED_64BIT:
            // TODO: any other states need to be reset?
            regs->rip = PAYLOAD_ADDR_PROT64;
            regs->rsp = ctx->ram_sz - 0x1000;
            regs->rbp = regs->rsp;
            memset(ctx->ram + GUEST_MEM_PROT64_RESERVED, 0,
                    ctx->ram_sz - GUEST_MEM_PROT64_RESERVED);
            break;
        default:
            log_warning("Unsupported vcpu mode in KVM test %d.\n", ctx->config->addr_mode);
            return EXIT_FAILURE;
    }

    IOCTL_OR_RET(ctx->cpu_fd, KVM_SET_REGS, regs);
    return EXIT_SUCCESS;
}

static int kvm_generic_add_vcpu(kvm_ctx_t *ctx)
{
    int cpu_fd = -1;

    ctx->run_sz = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (ctx->run_sz == -1) {
        return -errno;
    }

    cpu_fd = ioctl(ctx->vm_fd, KVM_CREATE_VCPU, 0);
    if (cpu_fd == -1) {
        return -errno;
    }

    ctx->runs = mmap(NULL, ctx->run_sz, PROT_READ | PROT_WRITE, MAP_SHARED, cpu_fd, 0);
    if (ctx->runs == MAP_FAILED) {
        ctx->runs = NULL;
        close(cpu_fd);
        return -errno;
    }

    return cpu_fd;
}

static int kvm_real16_setup_ram(kvm_ctx_t *ctx)
{
    struct kvm_userspace_memory_region region;

    if (!ctx->ram_sz)
        ctx->ram_sz = DEFAULT_RAM_SIZE;

    ctx->ram = mmap(NULL, ctx->ram_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (ctx->ram == MAP_FAILED) {
        ctx->ram = NULL;
        return -errno;
    }

    memset(&region, 0, sizeof(region));
    region.slot = 0;
    region.flags = 0;
    region.guest_phys_addr = 0;
    region.memory_size = ctx->ram_sz;
    region.userspace_addr = (uintptr_t)ctx->ram;

    IOCTL_OR_RET(ctx->vm_fd, KVM_SET_USER_MEMORY_REGION, &region);

    ptrdiff_t payload_size = (const uint8_t *)ctx->config->payload_end - (const uint8_t *)ctx->config->payload;
    memcpy(ctx->ram + PAYLOAD_GUEST_ENTRY, ctx->config->payload, payload_size);

    return 0;
}

static int kvm_real16_setup_sregs(struct kvm_sregs *sregs, kvm_ctx_t *ctx)
{
    sregs->cs.base = 0;
    sregs->cs.selector = 0;
    IOCTL_OR_RET(ctx->cpu_fd, KVM_SET_SREGS, sregs);

    return 0;
}

static uint64_t kvm_prot64_check_ram_size(uint64_t config_ram_size)
{
    uint64_t ret = config_ram_size;
    uint64_t guest_page_num = ret >> GUEST_PAGE_BITS;

    if (guest_page_num == 0) {
        guest_page_num = GUEST_PAGE_RESERVED + 1;
        ret = guest_page_num << GUEST_PAGE_BITS;
        return ret;
    }

    if ((guest_page_num >= GUEST_PAGE_MAX_NUM) || (guest_page_num <= GUEST_PAGE_RESERVED)) {
        guest_page_num = GUEST_PAGE_RESERVED + 1;
        ret = guest_page_num << GUEST_PAGE_BITS;

        log_warning("Invalid config: 'ram_size' is either too big (>= 1GB) or too small (<= %uMB). \n"
                "Now using default RAM size of %luMB.\n", GUEST_PAGE_RESERVED * 2, guest_page_num * 2);
    }

    if (ret & (GUEST_PAGE_SIZE - 1)) {
        guest_page_num += 1;
        ret = guest_page_num << GUEST_PAGE_BITS;

        log_warning("Invalid config: 'ram_size' is rounded-up to be a multiple of 2MB for prot64 mode.\n"
                "Now using RAM size of %luMB.\n", guest_page_num * 2);
    }

    return ret;
}

// Allocate a single guest memory bank starting from physical address 0
static void *kvm_prot64_setup_ram(kvm_ctx_t *ctx)
{
    uint64_t phys_size = ctx->ram_sz;

    void *p = mmap(NULL, phys_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        log_warning("kvm_prot64_setup_ram(): mmap failed\n");
        return NULL;
    }
    memset(p, 0, phys_size);

    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .guest_phys_addr = 0,
        .memory_size = phys_size,
        .userspace_addr = (uint64_t)p,
    };

    int ret = ioctl(ctx->vm_fd, KVM_SET_USER_MEMORY_REGION, &region);
    if (ret == -1) {
        log_warning("kvm_prot64_setup_ram(): KVM_SET_USER_MEMORY_REGION failed\n");
        return NULL;
    }

    return p;
}

static void gdt_to_kvm_segment(struct kvm_segment *seg, uint64_t *gdt_table, uint8_t sel)
{
    uint64_t gdt_ent = gdt_table[sel];
    seg->base = GDT_GET_BASE(gdt_ent);
    seg->limit = GDT_GET_LIMIT(gdt_ent);
    seg->selector = sel * 8;
    seg->type = GDT_GET_TYPE(gdt_ent);
    seg->present = GDT_GET_P(gdt_ent);
    seg->dpl = GDT_GET_DPL(gdt_ent);
    seg->db = GDT_GET_DB(gdt_ent);
    seg->s = GDT_GET_S(gdt_ent);
    seg->l = GDT_GET_L(gdt_ent);
    seg->g = GDT_GET_G(gdt_ent);
    seg->avl = GDT_GET_AVL(gdt_ent);
}

static void kvm_prot64_setup_segmentation(struct kvm_sregs *sregs,
        uint8_t *guest_ram_base)
{
    // Flags: | G |D/B| L |AVL|-| P |DPL| S |TYPE|
    // 0xA-9B | 1 | 0 | 1 | 0 |-| 1 |00 | 1 |1011|
    // 0xC-93 | 1 | 1 | 0 | 0 |-| 1 |00 | 1 |0011|
    uint64_t gdt[BOOT_GDT_MAX] = { /* flags, base, limit */
        [BOOT_GDT_NULL] = GDT_ENTRY(0, 0, 0),
        [BOOT_GDT_CODE] = GDT_ENTRY(0xA09B, 0, 0xFFFFF),
        [BOOT_GDT_DATA] = GDT_ENTRY(0xC093, 0, 0xFFFFF),
     };

    struct kvm_segment data_seg, code_seg;
    memset(&data_seg, 0, sizeof(data_seg));
    memset(&code_seg, 0, sizeof(code_seg));

    gdt_to_kvm_segment(&code_seg, gdt, BOOT_GDT_CODE);
    gdt_to_kvm_segment(&data_seg, gdt, BOOT_GDT_DATA);

    void *p = guest_ram_base + BOOT_GDT;
    memcpy(p, gdt, sizeof(gdt));
    sregs->gdt.base = BOOT_GDT;
    sregs->gdt.limit = sizeof(gdt)-1;

    sregs->cs = code_seg;
    sregs->ds = data_seg;
    sregs->es = data_seg;
    sregs->ss = data_seg;
}

static void kvm_prot64_setup_paging(struct kvm_sregs *sregs, kvm_ctx_t *ctx)
{
    uint64_t i;
    uint64_t guest_page_num = ctx->ram_sz >> GUEST_PAGE_BITS;

    // Setup paging: now we use 1:1 identity map
    uint64_t *p = (uint64_t *)(ctx->ram + PML4_ADDR);
    p[0] = PDPT_0_ADDR | 3;

    p = (uint64_t *)(ctx->ram + PDPT_0_ADDR);
    p[0] = PDT_0_ADDR | 3;

    p = (uint64_t *)(ctx->ram + PDT_0_ADDR);
    for (i = 0; i < GUEST_PAGE_RESERVED; ++i) {
        p[i] = (i * GUEST_PAGE_SIZE)
               | 0x81;  // enable PS (bit 7), and P (bit 0), but not writable
    }
    for (; i < guest_page_num; ++i) {
        p[i] = (i * GUEST_PAGE_SIZE)
               | 0x83;  // enable PS (bit 7), R/W (bit 1), and P (bit 0)
    }

    sregs->cr3 = PML4_ADDR;
    sregs->cr0 |= X86_CR0_PG;
    sregs->cr4 |= X86_CR4_PAE;
}

#define EFER_LME        (1<<8)  /* Long mode enable */
#define EFER_LMA        (1<<10) /* Long mode active (read-only) */

static int kvm_prot64_setup_sregs(int cpu_fd, struct kvm_sregs *sregs)
{
    // Enable 64-bit protected mode
    sregs->cr0 |= X86_CR0_PE;
    sregs->efer |= EFER_LMA;
    sregs->efer |= EFER_LME;

    int ret = ioctl(cpu_fd, KVM_SET_SREGS, sregs);
    if (ret < 0) {
        log_warning("kvm_prot64_setup_sregs: KVM_SET_SREGS failed");
    }

    return ret;
}

static int kvm_prot64_setup_payload(kvm_ctx_t *ctx)
{
    ptrdiff_t payload_size = (const uint8_t *)ctx->config->payload_end - (const uint8_t *)ctx->config->payload;
    if (payload_size + PAYLOAD_ADDR_PROT64 > ctx->ram_sz) {
        log_warning("kvm_prot64_setup_payload(): invalid input\n");
        return -1;
    }

    void *payload_dst = ctx->ram + PAYLOAD_ADDR_PROT64;
    memcpy(payload_dst, ctx->config->payload, payload_size);

    return 0;
}

static int kvm_generic_setup_cpuid(kvm_ctx_t *ctx)
{
    struct {
        struct kvm_cpuid2 header;
        struct kvm_cpuid_entry2 entries[80];
    } cpuid;
    cpuid.header.nent = sizeof(cpuid.entries) / sizeof(cpuid.entries[0]);
    IOCTL_OR_RET(kvm_fd, KVM_GET_SUPPORTED_CPUID, &cpuid);
    IOCTL_OR_RET(ctx->cpu_fd, KVM_SET_CPUID2, &cpuid);
    return EXIT_SUCCESS;
}

static int kvm_generic_setup_vcpu(kvm_ctx_t *ctx)
{
    struct kvm_sregs sregs;

    int ret = kvm_generic_setup_cpuid(ctx);
    if (ret < 0)
        return EXIT_FAILURE;

    IOCTL_OR_RET(ctx->cpu_fd, KVM_GET_SREGS, &sregs);

    switch (ctx->config->addr_mode) {
        case KVM_ADDR_MODE_REAL_16BIT:
            ctx->ram_sz = ctx->config->ram_size;
            if (kvm_real16_setup_ram(ctx)) {
                return EXIT_FAILURE;
            }
            ret = kvm_real16_setup_sregs(&sregs, ctx);
            if (ret < 0)
                return EXIT_FAILURE;
            return EXIT_SUCCESS;
        case KVM_ADDR_MODE_PROTECTED_64BIT:
            ctx->ram_sz = kvm_prot64_check_ram_size(ctx->config->ram_size);
            ctx->ram = kvm_prot64_setup_ram(ctx);
            if (!ctx->ram) {
                return EXIT_FAILURE;
            }
            kvm_prot64_setup_paging(&sregs, ctx);

            kvm_prot64_setup_segmentation(&sregs, ctx->ram);
            ret = kvm_prot64_setup_sregs(ctx->cpu_fd, &sregs);
            if (ret < 0)
                return EXIT_FAILURE;

            ret = kvm_prot64_setup_payload(ctx);
            if (ret < 0)
                return EXIT_FAILURE;

            return EXIT_SUCCESS;
        default:
            log_warning("Unsupported vcpu mode in KVM test %d.\n", ctx->config->addr_mode);
            return EXIT_FAILURE;
    }
}

static void kvm_log_registers(const char *log_level, const struct kvm_regs *gprs)
{
    static const struct FlagMapping {
        uint32_t bit;
        char name[4];
    } mapping[] = {
        { X86_EFLAGS_CF, "CF " },
        { X86_EFLAGS_PF, "PF " },
        { X86_EFLAGS_AF, "AF " },
        { X86_EFLAGS_ZF, "ZF " },
        { X86_EFLAGS_SF, "SF " },
        //{ X86_EFLAGS_TF, "TF " },
        { X86_EFLAGS_DF, "DF " },
        { X86_EFLAGS_OF, "OF " },
        //{ X86_EFLAGS_NT, "NT " },
        //{ X86_EFLAGS_RF, "RF " },
        //{ X86_EFLAGS_VM, "VM " },
        { X86_EFLAGS_AC, "AC " },
        //{ X86_EFLAGS_ID, "ID " },
    };
    char flags[(sizeof(mapping) / sizeof(mapping[0])) * 3 + 1];
    char *ptr = flags;
    *ptr = '\0';
    for (unsigned i = 0; i < sizeof(mapping) / sizeof(mapping[0]); ++i) {
        if ((gprs->rflags & mapping[i].bit) == 0)
            continue;
        memcpy(ptr, mapping->name, 3);
        ptr += 3;
    }
    if (ptr != flags)
        ptr[-1] = '\0';

    log_message(thread_num, SANDSTONE_LOG_INFO "%sRegister dump:\n"
                            "rax = 0x%016llx rbx = 0x%016llx rcx = 0x%016llx rdx = 0x%016llx\n"
                            "rsi = 0x%016llx rdi = 0x%016llx rsp = 0x%016llx rbp = 0x%016llx\n"
                            "r8  = 0x%016llx r9  = 0x%016llx rcx = 0x%016llx r11 = 0x%016llx\n"
                            "r12 = 0x%016llx r13 = 0x%016llx r14 = 0x%016llx r15 = 0x%016llx\n"
                            "rip = 0x%016llx rflags = 0x%016llx [%s]", log_level,
                gprs->rax, gprs->rbx, gprs->rcx, gprs->rdx,
                gprs->rsi, gprs->rdi, gprs->rsp, gprs->rbp,
                gprs->r8, gprs->r9, gprs->rcx, gprs->r11,
                gprs->r12, gprs->r13, gprs->r14, gprs->r15,
                gprs->rip, gprs->rflags, flags);
}

#ifndef MADV_COLD
#define MADV_COLD 20
#endif

static inline const char *convert_kvm_exit_code_to_string(int kvm_exit_code)
{
    static const char *code_to_string[] = {
        "KVM_EXIT_UNKNOWN",
        "KVM_EXIT_EXCEPTION",
        "KVM_EXIT_IO",
        "KVM_EXIT_HYPERCALL",
        "KVM_EXIT_DEBUG",
        "KVM_EXIT_HLT",
        "KVM_EXIT_MMIO",
        "KVM_EXIT_IRQ_WINDOW_OPEN",
        "KVM_EXIT_SHUTDOWN",
        "KVM_EXIT_FAIL_ENTRY",
        "KVM_EXIT_INTR",
        "KVM_EXIT_SET_TPR",
        "KVM_EXIT_TPR_ACCESS",
        "KVM_EXIT_S390_SIEIC",
        "KVM_EXIT_S390_RESET",
        "KVM_EXIT_DCR",
        "KVM_EXIT_NMI",
        "KVM_EXIT_INTERNAL_ERROR",
        "KVM_EXIT_OSI",
        "KVM_EXIT_PAPR_HCALL",
        "KVM_EXIT_S390_UCONTROL",
        "KVM_EXIT_WATCHDOG",
        "KVM_EXIT_S390_TSCH",
        "KVM_EXIT_EPR",
        "KVM_EXIT_SYSTEM_EVENT",
        "KVM_EXIT_S390_STSI",
        "KVM_EXIT_IOAPIC_EOI",
        "KVM_EXIT_HYPERV",
        "KVM_EXIT_ARM_NISV",
        "KVM_EXIT_X86_RDMSR",
        "KVM_EXIT_X86_WRMSR",
        "KVM_EXIT_DIRTY_RING_FULL",
        "KVM_EXIT_AP_RESET_HOLD",
        "KVM_EXIT_X86_BUS_LOCK",
        "KVM_EXIT_XEN",
        "KVM_EXIT_RISCV_SBI",
        "KVM_EXIT_RISCV_CSR",
        "KVM_EXIT_NOTIFY"
    };


    if (kvm_exit_code >= 0 && kvm_exit_code < (sizeof(code_to_string) / sizeof(*code_to_string)))
        return  code_to_string[kvm_exit_code];
    return "UNKNOWN_KVM_EXIT";
}

int kvm_generic_run(struct test *test, int cpu)
{
    int result = EXIT_SUCCESS;
    kvm_ctx_t ctx;
    struct kvm_regs init_regs;
    int stop;

    memset(&ctx, 0, sizeof(kvm_ctx_t));
    ctx.vm_fd = -1;
    ctx.cpu_fd = -1;
    ctx.config = test->test_kvm_config();

    /* check the config is sane */
    if (!ctx.config->payload || !ctx.config->payload_end) {
        log_error("Test '%s' does not provide proper KVM payload.", test->id);
        return EXIT_FAILURE;
    }

    __auto_type fail_entry = (struct sandstone_kvm_fail_entry *) ctx.runs->padding;
    __auto_type msr = (struct sandstone_kvm_exit_x86_read_write_msr *) ctx.runs->padding;
    __auto_type xen = (struct sandstone_kvm_xen_exit *) ctx.runs->padding;
    __auto_type notify = (struct kvm_notify *) ctx.runs->padding;

    int count = 0;
    do {
        /* Every 16 loops reset the A bit for the memory */
        if (count && (count % 16 == 0)) {
                madvise(ctx.ram, ctx.ram_sz, MADV_COLD);
        }
        /* Recycle VM every 128-th time. There's an issue with KVM running and
         * resetting RIP: on 129-th run it would not function properly. */
        if (count % 127 == 0) {
            if (count) {
                close(ctx.vm_fd);
                close(ctx.cpu_fd);
                munmap(ctx.runs, ctx.run_sz);
                munmap(ctx.ram, ctx.ram_sz);
                ctx.vm_fd = -1;
                ctx.cpu_fd = -1;
                ctx.runs = NULL;
                ctx.ram = NULL;
            }

            ctx.vm_fd = kvm_generic_create_vm(kvm_fd);
            if (ctx.vm_fd < 0) {
                if (errno == EBUSY) {
                    log_skip(OSResourceIssueSkipCategory, "Cannot create VM: device busy");
                    result = EXIT_SKIP;
                    goto epilogue;
                }
                result = EXIT_FAILURE;
                goto epilogue;
            }

            ctx.cpu_fd = kvm_generic_add_vcpu(&ctx);
            if (ctx.cpu_fd < 0) {
                result = EXIT_FAILURE;
                goto epilogue;
            }

            result = kvm_generic_setup_vcpu(&ctx);
            if (result != EXIT_SUCCESS) {
                goto epilogue;
            }

            IOCTL_OR_RET(ctx.cpu_fd, KVM_GET_REGS, &init_regs);
        }

        stop = 0;
        if (kvm_generic_reset_vcpu(&ctx, &init_regs) != EXIT_SUCCESS) {
            result = EXIT_FAILURE;
            goto epilogue;
        }

        if (ctx.config->setup_handler != NULL) {
                result = ctx.config->setup_handler(&ctx, test, cpu);
                if (result != EXIT_SUCCESS)
                        goto epilogue;
        }

        do {
            if (ioctl(ctx.cpu_fd, KVM_RUN, 0) == -1) {
                result = EXIT_FAILURE;
                goto epilogue;
            }

            if (ctx.config->exit_handler != NULL) {
                switch (ctx.config->exit_handler(&ctx, test, cpu)) {
                case KVM_EXIT_FAILURE:
                    result = EXIT_FAILURE;
                    log_error("KVM exit handler for VM-Exit %d failed", ctx.runs->exit_reason);
                    goto epilogue;
                case KVM_EXIT_UNHANDLED:
                    break;
                case KVM_EXIT_HANDLED:
                    continue;
                }
            }

            stop = 1;
            result = EXIT_FAILURE;

            switch (ctx.runs->exit_reason) {
                case KVM_EXIT_HLT:
                    {
                        struct kvm_regs cregs;

                        stop = 1;
                        result = EXIT_SUCCESS;
                        IOCTL_OR_RET(ctx.cpu_fd, KVM_GET_REGS, &cregs);
                        switch (cregs.rax) {
                            case 0:
                                break;
                            default:
                                kvm_log_registers(SANDSTONE_LOG_INFO, &cregs);
                                log_error("KVM test reported exit code %lld", cregs.rax);
                                result = EXIT_FAILURE;
                                break;
                        }
                    }
                    break;
                case KVM_EXIT_UNKNOWN:
                    log_error("KVM exit reason: %s, Hardware exit reason: 0x%llx",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->hw.hardware_exit_reason);
                    break;
                case KVM_EXIT_FAIL_ENTRY:
                    log_error("KVM exit reason: %s, Hardware entry exit reason: 0x%llx, cpu:%u",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            fail_entry->hardware_entry_failure_reason,
                            fail_entry->cpu);
                    break;
                case KVM_EXIT_EXCEPTION:
                    log_error("KVM exit reason: %s, Exception code: 0x%x, error_code: 0x%x",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->ex.exception,
                            ctx.runs->ex.error_code);
                    break;
                case KVM_EXIT_IO:
                    log_error("KVM exit reason: %s, io.direction: 0x%x, io.size: 0x%x, io.port: io.0x%x, io.count: 0x%x, io.data_offset: 0x%llx",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->io.direction,
                            ctx.runs->io.size,
                            ctx.runs->io.port,
                            ctx.runs->io.count,
                            ctx.runs->io.data_offset);
                    break;
#ifdef __x86_64__
                case KVM_EXIT_DEBUG:
                    log_error("KVM exit reason: %s, debug.arch.exception: 0x%x, debug.arch.pad: 0x%x, debug.arch.pc: 0x%llx, debug.arch.dr6: 0x%llx, debug.arch.dr7: 0x%llx",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->debug.arch.exception,
                            ctx.runs->debug.arch.pad,
                            ctx.runs->debug.arch.pc,
                            ctx.runs->debug.arch.dr6,
                            ctx.runs->debug.arch.dr7);
                    break;
                case KVM_EXIT_X86_RDMSR:
                    log_error("KVM exit reason: %s, msr.error: 0x%x, msr.reason: 0x%x",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            msr->error,
                            msr->reason);
                    break;
                case KVM_EXIT_X86_WRMSR:
                    log_error("KVM exit reason: %s, msr.error: 0x%x, msr.reason: 0x%x",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            msr->error,
                            msr->reason);
                    break;
#endif
                case KVM_EXIT_MMIO:
                    log_error("KVM exit reason: %s, mmio.phys_addr: 0x%llx, mmio.len: 0x%x, mmio.is_write: 0x%x",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->mmio.phys_addr,
                            ctx.runs->mmio.len,
                            ctx.runs->mmio.is_write);
                    break;
                case KVM_EXIT_HYPERCALL:
                    log_error("KVM exit reason: %s, hypercall.nr: 0x%llx, hypercall.ret: 0x%llx",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->hypercall.nr,
                            ctx.runs->hypercall.ret);
                    break;
                case KVM_EXIT_TPR_ACCESS:
                    log_error("KVM exit reason: %s, tpr_access.rip: 0x%llx, tpr_access.is_write: 0x%x tpr_access.pad: 0x%x",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->tpr_access.rip,
                            ctx.runs->tpr_access.is_write,
                            ctx.runs->tpr_access.pad);
                    break;
#ifdef __s390__
                case KVM_EXIT_S390_SIEIC:
                    log_error("KVM exit reason: %s, s390_sieic.icptcode: 0x%x, s390_sieic.ipa: 0x%x, s390_sieic.ipb: 0x%x",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->s390_sieic.icptcode,
                            ctx.runs->s390_sieic.ipa,
                            ctx.runs->s390_sieic.ipb);
                    break;
                case KVM_EXIT_S390_RESET:
                    log_error("KVM exit reason: %s, s390_reset_flags: 0x%llx",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->s390_reset_flags);
                    break;
                case KVM_EXIT_S390_UCONTROL:
                    log_error("KVM exit reason: %s, s390_ucontrol.trans_exc_code: 0x%llx, s390_ucontrol.pgm_code: 0x%x",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->s390_ucontrol.trans_exc_code,
                            ctx.runs->s390_ucontrol.pgm_code);
                    break;
                case KVM_EXIT_S390_TSCH:
                    log_error("KVM exit reason: %s, s390_tsch.subchannel_id: 0x%x, subchannel_nr: 0x%x, io_int_parm: 0x%x, io_int_word: 0x%x, ipb: 0x%x, dequeued: 0x%x",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->s390_tsch.subchannel_id,
                            ctx.runs->s390_tsch.subchannel_nr,
                            ctx.runs->s390_tsch.io_int_parm,
                            ctx.runs->s390_tsch.io_int_word,
                            ctx.runs->s390_tsch.ipb,
                            ctx.runs->s390_tsch.dequeued);
                    break;
                case KVM_EXIT_S390_STSI:
                    log_error("KVM exit reason: %s, s390_stsi.addr: 0x%llx, s390_stsi.ar: 0x%x, s390_stsi.reserved: 0x%x, s390_stsi.fc: 0x%x, s390_stsi.sel1: 0x%x, s390_stsi.sel2: 0x%x",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->s390_stsi.addr,
                            ctx.runs->s390_stsi.ar,
                            ctx.runs->s390_stsi.reserved,
                            ctx.runs->s390_stsi.fc,
                            ctx.runs->s390_stsi.sel1,
                            ctx.runs->s390_stsi.sel2);
                    break;
#endif
                case KVM_EXIT_DCR:
                    log_error("KVM exit reason: %s, dcr.dcrn: 0x%x, dcr.data: 0x%x, dcr.is_write: 0x%x",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->dcr.dcrn,
                            ctx.runs->dcr.data,
                            ctx.runs->dcr.is_write);
                    break;
                case KVM_EXIT_INTERNAL_ERROR:
                    log_error("KVM exit reason: %s, internal.suberror: 0x%x, internal.ndata: 0x%x",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->internal.suberror,
                            ctx.runs->internal.ndata);
                    break;
                case KVM_EXIT_OSI:
                    log_error("KVM exit reason: %s, Please have a look at GPRs",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason));
                    break;
#ifdef __powerpc__
                case KVM_EXIT_PAPR_HCALL:
                    log_error("KVM exit reason: %s, papr_hcall.nr: 0x%llx, papr_hcall.ret: 0x%llx",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->papr_hcall.nr,
                            ctx.runs->papr_hcall.ret);
                    break;
                case KVM_EXIT_EPR:
                    log_error("KVM exit reason: %s, epr.epr: 0x%x",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->epr.epr);
                    break;
#endif
                case KVM_EXIT_SYSTEM_EVENT:
                    log_error("KVM exit reason: %s, system_event.type: 0x%x",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->system_event.type);
                    break;
                case KVM_EXIT_HYPERV:
                    log_error("KVM exit reason: %s, hyperv.type: 0x%x",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->hyperv.type);
                    break;
#ifdef __aarch64__
                case KVM_EXIT_ARM_NISV:
                    log_error("KVM exit reason: %s, arm_nisv.esr_iss: 0x%llx, arm_nisv.fault_ipa: 0x%llx",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->arm_nisv.esr_iss,
                            ctx.runs->arm_nisv.fault_ipa);
                    break;
#endif
                case KVM_EXIT_XEN:
                    log_error("KVM exit reason: %s, xen.type: 0x%x",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            xen->type);
                    break;
#ifdef __riscv__
                case KVM_EXIT_RISCV_SBI:
                    log_error("KVM exit reason: %s, riscv_sbi.extension_id: 0x%lx, riscv_sbi.function_id: 0x%lx",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->riscv_sbi.extension_id,
                            ctx.runs->riscv_sbi.function_id);
                    break;
                case KVM_EXIT_RISCV_CSR:
                    log_error("KVM exit reason: %s, riscv_sbi.csr_num: 0x%lx, riscv_sbi.new_value: 0x%lx, riscv_csr.write_mask: 0x%lx, riscv_csr.ret_value: 0x%lx",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            ctx.runs->riscv_csr.csr_num,
                            ctx.runs->riscv_csr.new_value,
                            ctx.runs->riscv_csr.write_mask,
                            ctx.runs->riscv_csr.ret_value);
                    break;
#endif
                case KVM_EXIT_NOTIFY:
                    log_error("KVM exit reason: %s, notify.flags: 0x%x",
                            convert_kvm_exit_code_to_string(ctx.runs->exit_reason),
                            notify->flags);
                    break;
                default:
                    log_error("Unexpected exit reason: %d.\n", ctx.runs->exit_reason);
                    break;
            }
        } while (!stop);

        if ((result == EXIT_SUCCESS) && (ctx.config->check_handler != NULL))
                result = ctx.config->check_handler(&ctx, test, cpu);

        count++;

    } while (result == EXIT_SUCCESS && test_time_condition(test));

epilogue:
    if (ctx.vm_fd >= 0) close(ctx.vm_fd);
    if (ctx.cpu_fd >= 0) close(ctx.cpu_fd);
    if (ctx.runs) munmap(ctx.runs, ctx.run_sz);
    if (ctx.ram) munmap(ctx.ram, ctx.ram_sz);

    return result;
}

int kvm_generic_init(struct test *t)
{
    int ret;

    if (!t->test_kvm_config) {
        log_info("Test '%s' does not define KVM test configuration.", t->id);
        return EXIT_FAILURE;
    }

    kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm_fd < 0) {
        log_info("Failed to open /dev/kvm.");
        return -errno;
    }

    ret = ioctl(kvm_fd, KVM_GET_API_VERSION, NULL);
    if (ret == -1) {
        log_info("Failed to retrieve KVM version.");
        ret = -errno;
        goto skip;
    }
    if (ret != 12) {
        log_info("KVM version 12 is required. Got %d.\n", ret);
        ret = -errno;
        goto skip;
    }

    ret = ioctl(kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
    if (ret < 0) {
        log_info("KVM_CHECK_EXTENSION for KVM_CAP_USER_MEMORY failed.\n");
        ret = -errno;
        goto skip;
    }
    if (!ret) {
        log_skip(DeviceNotFoundSkipCategory, "KVM_CAP_USER_MEMORY is not available, but required.\n");
        ret = EXIT_SKIP;
        goto skip;
    }

    return EXIT_SUCCESS;

skip:
    close(kvm_fd);
    kvm_fd = -1;
    return ret;
}

int kvm_generic_cleanup(struct test *t)
{
    if (kvm_fd != -1) {
        close(kvm_fd);
        kvm_fd = -1;
    }
    return EXIT_SUCCESS;
}
