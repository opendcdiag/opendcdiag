// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause-Clear
//
// AArch64 CPU vendor and part number identification using Main ID
// Register (MIDR_EL1).
// Reference:
//   https://developer.arm.com/documentation/ddi0601/2025-03/AArch64-Registers/MIDR-EL1--Main-ID-Register

#ifndef INC_CPU_FEATURES_AARCH64_H
#define INC_CPU_FEATURES_AARCH64_H

#include <stddef.h>      // size_t, NULL
#include <stdint.h>

typedef unsigned __int128 device_features_t;
static const device_features_t device_compiler_features = 0;

// Not an ARM feature: kept for build compatibility with x86.
// The logging code uses this flag to detect whether it’s running in a VM.
// An equivalent ARM VM-detection mechanism is required, but that work is
// out of scope for now. detect_cpu() (cpuid_internal.h) packs AT_HWCAP into
// bits 0-63 and AT_HWCAP2 into bits 64-127, so bit 63 falls inside the
// AT_HWCAP window, and the Linux kernel guarantees bits 62 and 63 of
// AT_HWCAP are always returned as 0 (see the arm64 ELF hwcaps
// documentation, "Unused AT_HWCAP bits"). detect_cpu() therefore never sets
// it, making device_has_feature(cpu_feature_hypervisor) always false (bare
// metal). Keep this bit in the AT_HWCAP half: the reserved-as-zero
// guarantee does not extend to AT_HWCAP2, which already reaches bit 62.
#define cpu_feature_hypervisor  (((device_features_t) 1) << 63)

//  MIDR_EL1
//
//  Bit # |31         24|23     20|19          16|15          4|3        0|
//  Value | Implementer | Variant | Architecture | Part Number | Revision |

#define MIDR_EL1_IMPLEMENTER(midr_el1)  ((uint8_t) (((uint32_t)(midr_el1) & 0xFF000000U) >> 24))
#define MIDR_EL1_VARIANT(midr_el1)      ((uint8_t) (((uint32_t)(midr_el1) & 0x00F00000U) >> 20))
// The ARCHITECTURE value is not used in the code. It is included for completeness.
// #define MIDR_EL1_ARCHITECTURE(midr_el1) ((uint8_t) (((uint32_t)(midr_el1) & 0x000F0000U) >> 16))
#define MIDR_EL1_PART_NUM(midr_el1)     ((uint16_t)(((uint32_t)(midr_el1) & 0x0000FFF0U) >>  4))
#define MIDR_EL1_REVISION(midr_el1)     ((uint8_t) (((uint32_t)(midr_el1) & 0x0000000FU)      ))

// Instantiate this for each implementer
struct VendorParts {
    uint16_t part_num;
    const char *name;
};

// Qualcomm parts
static const struct VendorParts qcomm_parts[] = {
    { 0x001, "Oryon(TM) CPU (Gen 1/Gen 2)" },
    { 0x002, "Oryon(TM) CPU (Gen 3)" },
    { 0x003, "Oryon(TM) CPU (Gen 4)" },
    { 0x004, "Oryon(TM) CPU (Gen 5)" },
};

struct Vendor {
    uint8_t id;
    const char *name;
    const struct VendorParts *parts;
    size_t num_parts;
};

static const struct Vendor aarch64_vendors[] = {
    { 0x00, "Reserved for software use", NULL, 0 },
    { 0x41, "Arm Limited", NULL, 0 },
    { 0x42, "Broadcom Corporation", NULL, 0 },
    { 0x43, "Cavium Inc.", NULL, 0 },
    { 0x44, "Digital Equipment Corporation", NULL, 0 },
    { 0x46, "Fujitsu Ltd.", NULL, 0 },
    { 0x49, "Infineon Technologies AG", NULL, 0 },
    { 0x4D, "Motorola or Freescale Semiconductor Inc.", NULL, 0 },
    { 0x4E, "NVIDIA Corporation", NULL, 0 },
    { 0x50, "Applied Micro Circuits Corporation", NULL, 0 },
    { 0x51, "Qualcomm Inc.", qcomm_parts, sizeof(qcomm_parts) / sizeof(qcomm_parts[0]) },
    { 0x56, "Marvell International Ltd.", NULL, 0 },
    { 0x69, "Intel Corporation", NULL, 0 },
    { 0xC0, "Ampere Computing", NULL, 0 }
};

#endif /* INC_CPU_FEATURES_AARCH64_H */
