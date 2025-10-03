/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_CPU_DEVICE_H
#define INC_CPU_DEVICE_H

#include "cpu_features.h"

#ifdef __cplusplus
#include <string>
#endif
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/// can be used in the clobber list of inline assembly to indicate
/// that all the R registers have been modified by the assembly code.
#define RCLOBBEREDLIST "r8",\
                       "r9",\
                       "r10",\
                       "r11",\
                       "r12",\
                       "r13",\
                       "r14",\
                       "r15"

/// can be used in the clobber list of inline assembly to indicate
/// that all the MMX registers have been modified by the assembly code.
#define MMCLOBBEREDLIST "mm0",\
                        "mm1",\
                        "mm2",\
                        "mm3",\
                        "mm4",\
                        "mm5",\
                        "mm6",\
                        "mm7"

/// can be used in the clobber list of inline assembly to indicate
/// that all the XMM registers have been modified by the assembly code.
#define XMMCLOBBEREDLIST "xmm0",\
                         "xmm1",\
                         "xmm2",\
                         "xmm3",\
                         "xmm4",\
                         "xmm5",\
                         "xmm6",\
                         "xmm7",\
                         "xmm8",\
                         "xmm9",\
                         "xmm10",\
                         "xmm11",\
                         "xmm12",\
                         "xmm13",\
                         "xmm14",\
                         "xmm15"

/// can be used in the clobber list of inline assembly to indicate
/// that all the YMM registers have been modified by the assembly code.
#define YMMCLOBBEREDLIST "ymm0",\
                         "ymm1",\
                         "ymm2",\
                         "ymm3",\
                         "ymm4",\
                         "ymm5",\
                         "ymm6",\
                         "ymm7",\
                         "ymm8",\
                         "ymm9",\
                         "ymm10",\
                         "ymm11",\
                         "ymm12",\
                         "ymm13",\
                         "ymm14",\
                         "ymm15"

/// can be used in the clobber list of inline assembly to indicate
/// that all the ZMM registers have been modified by the assembly code.
#define ZMMCLOBBEREDLIST "zmm0",\
                         "zmm1",\
                         "zmm2",\
                         "zmm3",\
                         "zmm4",\
                         "zmm5",\
                         "zmm6",\
                         "zmm7",\
                         "zmm8",\
                         "zmm9",\
                         "zmm10",\
                         "zmm11",\
                         "zmm12",\
                         "zmm13",\
                         "zmm14",\
                         "zmm15",\
                         "zmm16",\
                         "zmm17",\
                         "zmm18",\
                         "zmm19",\
                         "zmm20",\
                         "zmm21",\
                         "zmm22",\
                         "zmm23",\
                         "zmm24",\
                         "zmm25",\
                         "zmm26",\
                         "zmm27",\
                         "zmm28",\
                         "zmm29",\
                         "zmm30",\
                         "zmm31"

/// can be used in the clobber list of inline assembly to indicate
/// that all the K registers have been modified by the assembly code.
#define KMASKCLOBBEREDLIST "k0","k1","k2","k3","k4","k5","k6","k7"

/// used to determine whether one or more CPU features are available at runtime.  f is a bitmask
/// of cpu features as defined in the auto-generated cpu_features.h file.  For example, a test
/// may call cpu_has_feature(cpu_feature_avx512f) to determine whether AVX-512 is available.
/// Normally, cpuid detection is handle automatically by the framework via test's minimum_cpu field.
/// This macro is provided in case tests need more fine grained control.
#define cpu_has_feature(f)      ((device_compiler_features & (f)) == (f) || (device_features & (f)) == (f))

/// used as follows: if instruction cache, only cache_instruction is valid; if
/// data, only data is valid; if unified, both are set to the same value. In all
/// the cases the value is the cache size in bytes.  A field is valid if it
/// contains a value >= 0.  Fields with negative values are invalid.
/// TODO: consider changing this, with L1D & L1I being the same size, they are
/// indistinguishable from a unified cache.
struct cache_info
{
    int cache_instruction;
    int cache_data;
};

/// cpu_info contains information about a logical CPU
struct cpu_info
{
    uint64_t microcode;     ///! Microcode version read from /sys

    /// Logical OS processor number.
    /// On Unix systems, this is a sequential ID; on Windows, it encodes
    /// 64 * ProcessorGroup + ProcessorNumber
    int cpu_number;

    /// Thread ID inside a core, usually 0 or 1 (-1 if not known).
    int16_t thread_id;
    /// Core ID inside of a package, -1 if not known.
    int16_t core_id;
    /// Module ID inside of a package, -1 if not known.
    int16_t module_id;
    /// Tile ID inside of a package, -1 if not known. May combine with the die ID.
    int16_t tile_id;
    /// NUMA node ID in the system, -1 if not known.
    int16_t numa_id;
    /// Package ID in the system, -1 if not known.
    int16_t package_id;

    /// On x86, it's the APICID or x2APICID, if known; -1 if not.
    int hwid;

    struct cache_info cache[3]; ///! Cache info from OS

#ifdef __cplusplus
    int cpu() const;        ///! Internal CPU number
#endif
};

// Alias for use in common framework code
typedef struct cpu_info device_info;

/// cpu_info is an array of cpu_info structures.  Each element of the array
/// contains information about a logical CPU that will be used to
/// execute a test's test_run function.  The size of this array is
/// equal to the value returned by num_cpus().
extern struct cpu_info *cpu_info;

#ifdef __cplusplus
inline int cpu_info::cpu() const
{
    return this - ::cpu_info;
}

std::string device_features_to_string(device_features_t f);

extern "C" {
#endif // __cplusplus

/// Keep num_cpus() defined for legacy reasons
int num_cpus() __attribute__((pure));

/// Returns the number of physical CPU packages (a.k.a. sockets) available to a
/// test.
int num_packages() __attribute__((pure));

#ifdef __cplusplus
}
#endif

#endif // INC_CPU_DEVICE_H
