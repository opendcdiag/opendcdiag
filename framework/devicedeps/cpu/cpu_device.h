/*
 * Copyright 2024 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_CPU_DEVICE_H
#define INC_CPU_DEVICE_H

#ifdef SANDSTONE_DEVICE_CPU

#include "devicedeps/cpu/cpu_features.h"

#ifdef __cplusplus
#include <string>
#endif
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_HWTHREADS_PER_CORE  4

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

extern uint64_t cpu_features;
/// used to determine whether one or more CPU features are available at runtime.  f is a bitmask
/// of cpu features as defined in the auto-generated cpu_features.h file.  For example, a test
/// may call cpu_has_feature(cpu_feature_avx512f) to determine whether AVX-512 is available.
/// Normally, cpuid detection is handle automatically by the framework via test's minimum_cpu field.
/// This macro is provided in case tests need more fine grained control.
#define cpu_has_feature(f)      ((_compilerCpuFeatures & (f)) == (f) || (cpu_features & (f)) == (f))

/// used as follows: if instruction cache, only cache_instruction is valid; if
/// data, only data is valid; if unified, both are set to the same value. In all
/// the cases the value is the cache size in bytes.  A field is valid if it
/// contains a value >= 0.  Fields with negative values are invalid.
/// TODO: consider changing this, with L1D & L1I being the same size, they are
/// indistinguishable from a unified cache.
struct cache_info {
    int cache_instruction;
    int cache_data;
};

/// cpu_info contains information about a logical CPU
struct cpu_info {
    uint64_t ppin;          ///! Processor ID read from MSR
    uint64_t microcode;     ///! Microcode version read from /sys
    int cpu_number;         ///! Logical processor number as seen by OS
    int thread_id;          ///! Topology info from APIC
    int core_id;            ///! Topology info from APIC
    int package_id;         ///! Topology info from APIC
    struct cache_info cache[3]; ///! Cache info from OS
    uint8_t family;         ///! CPU family (usually 6)
    uint8_t stepping;       ///! CPU stepping
    uint16_t model;         ///! CPU model

#ifdef __cplusplus
    int cpu() const;        ///! Internal CPU number
#endif
};

#ifdef __cplusplus
using device_info = struct cpu_info;
#endif

/// cpu_info is an array of cpu_info structures.  Each element of the array
/// contains information about a logical CPU that will be used to
/// execute a test's test_run function.  The size of this array is
/// equal to the value returned by num_cpus().
extern struct cpu_info *cpu_info;

#ifdef __cplusplus
inline int cpu_info::cpu() const {
    return this - ::cpu_info;
}
std::string cpu_features_to_string(uint64_t f);

extern "C" {
#else
#define thread_local _Thread_local
#endif

void dump_cpu_info(int verbosity);

/// reads the value of the MSR, specified by msr, of CPU cpu.
/// The value is returned in the value parameter.  The function
/// returns true if the value can be read and false otherwise.
/// This function is only supported on Linux and requires root
/// privileges.
bool read_msr(int cpu, uint32_t msr, uint64_t *value);

/// writes the value specified by value to the MSR, specified by msr,
/// of CPU cpu.  The function returns true if the value can be written
/// and false otherwise.   This function is only supported on Linux and
/// requires root privileges.
bool write_msr(int cpu, uint32_t msr, uint64_t value);

/// Returns the number of hardware threads (logical CPUs) available to a
/// test.  It is equal to the number of test threads the framework runs.
/// Normally, this value is equal to the number of CPU threads in the
/// device under test but the value can be lower if --cpuset option
/// is used, the tests specifies a value for test.max_threads or the OS
/// restricts the number of CPUs sandstone can see.
int num_cpus() __attribute__((pure));

/// Returns the number of physical CPU packages (a.k.a. sockets) available to a
/// test.
int num_packages() __attribute__((pure));

/// retrieves the physical address of a given pointer.  Currently
/// this function is only supported on Linux and requires root
/// privileges.
uint64_t retrieve_physical_address(const volatile void *ptr);
#ifdef __cplusplus
}
#endif

/// thread_num always contains the integer identifier for the executing
/// thread.  It can be used to index the cpu_info array and is equivalent
/// to the cpu parameter in the test_run function.
#ifdef __llvm__
extern thread_local int thread_num;
#else
extern __thread int thread_num __attribute__((tls_model("initial-exec")));
#endif
#endif
#endif // INC_CPU_DEVICE_H
