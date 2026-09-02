/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_IDXD_FEATURES_H
#define INC_IDXD_FEATURES_H

#include <stdint.h>

typedef unsigned __int128 device_features_t;
#define IDXD_FEATURE_CONSTANT(bit) (((device_features_t) 1) << (bit))

// Generic type-presence bits indicate that at least one device of that family
// exists in the system.
#define device_feature_dsa      IDXD_FEATURE_CONSTANT(0)
#define device_feature_iax      IDXD_FEATURE_CONSTANT(1)

// Type-specific version bits avoid false positives on mixed systems such as
// DSA V1 plus IAX V2.
#define device_feature_dsa_v1   IDXD_FEATURE_CONSTANT(2)
#define device_feature_dsa_v2   IDXD_FEATURE_CONSTANT(3)
#define device_feature_dsa_v3   IDXD_FEATURE_CONSTANT(4)
#define device_feature_iax_v1   IDXD_FEATURE_CONSTANT(5)
#define device_feature_iax_v2   IDXD_FEATURE_CONSTANT(6)
#define device_feature_iax_v3   IDXD_FEATURE_CONSTANT(7)

// Operation capability bits from accfg_device_get_op_cap().
// They indicate that at least one visible accelerator reports support
// for the given opcode. Common operations are split by device type since
// they may have different support levels.

// DSA common operations
#define device_feature_dsa_op_noop          IDXD_FEATURE_CONSTANT(8)
#define device_feature_dsa_op_batch         IDXD_FEATURE_CONSTANT(9)
#define device_feature_dsa_op_drain         IDXD_FEATURE_CONSTANT(10)

// DSA-specific operations
#define device_feature_op_memmove           IDXD_FEATURE_CONSTANT(11)
#define device_feature_op_fill              IDXD_FEATURE_CONSTANT(12)
#define device_feature_op_compare           IDXD_FEATURE_CONSTANT(13)
#define device_feature_op_compare_pat       IDXD_FEATURE_CONSTANT(14)
#define device_feature_op_crc_gen           IDXD_FEATURE_CONSTANT(15)
#define device_feature_op_copy_with_crc_gen IDXD_FEATURE_CONSTANT(16)
#define device_feature_op_dif_check         IDXD_FEATURE_CONSTANT(17)
#define device_feature_op_dif_insert        IDXD_FEATURE_CONSTANT(18)
#define device_feature_op_dif_strip         IDXD_FEATURE_CONSTANT(19)
#define device_feature_op_dif_update        IDXD_FEATURE_CONSTANT(20)
#define device_feature_op_cache_flush       IDXD_FEATURE_CONSTANT(21)
#define device_feature_op_crc64             IDXD_FEATURE_CONSTANT(22)

// IAX common operations
#define device_feature_iax_op_noop          IDXD_FEATURE_CONSTANT(23)
#define device_feature_iax_op_batch         IDXD_FEATURE_CONSTANT(24)
#define device_feature_iax_op_drain         IDXD_FEATURE_CONSTANT(25)

// IAX-specific operations
#define device_feature_op_dual_cast     IDXD_FEATURE_CONSTANT(26)
#define device_feature_op_create_delta  IDXD_FEATURE_CONSTANT(27)
#define device_feature_op_apply_delta   IDXD_FEATURE_CONSTANT(28)
#define device_feature_op_scan          IDXD_FEATURE_CONSTANT(29)
#define device_feature_op_extract       IDXD_FEATURE_CONSTANT(30)
#define device_feature_op_select        IDXD_FEATURE_CONSTANT(31)
#define device_feature_op_expand        IDXD_FEATURE_CONSTANT(32)
#define device_feature_op_compress      IDXD_FEATURE_CONSTANT(33)
#define device_feature_op_decompress    IDXD_FEATURE_CONSTANT(34)

#define IDXD_FEATURE_SIZE  35

#ifdef __cplusplus
static constexpr const char* features_names[IDXD_FEATURE_SIZE] = {
    "dsa", "iax",
    "dsa_v1", "dsa_v2", "dsa_v3",
    "iax_v1", "iax_v2", "iax_v3",
    "dsa_op_noop", "dsa_op_batch", "dsa_op_drain",
    "op_memmove", "op_fill", "op_compare", "op_compare_pat",
    "op_crc_gen", "op_copy_with_crc_gen", "op_dif_check", "op_dif_insert",
    "op_dif_strip", "op_dif_update", "op_cache_flush", "op_crc64",
    "iax_op_noop", "iax_op_batch", "iax_op_drain",
    "op_dual_cast", "op_create_delta", "op_apply_delta", "op_scan",
    "op_extract", "op_select", "op_expand", "op_compress", "op_decompress",
};
#endif

// CPU-specific features
#define cpu_feature_bmi                 IDXD_FEATURE_CONSTANT(75)
#define cpu_feature_waitpkg             IDXD_FEATURE_CONSTANT(76)
#define cpu_feature_enqcmd              IDXD_FEATURE_CONSTANT(77)
#define cpu_feature_amx_int8            IDXD_FEATURE_CONSTANT(78)

// Further features can describe additional capabilities or type-specific ones.

// In this case, compiler features are in fact CPU-features.
static const device_features_t device_compiler_features = 0
#ifdef __BMI__
         | cpu_feature_bmi
#endif
#ifdef __WAITPKG__
         | cpu_feature_waitpkg
#endif
#ifdef __ENQCMD__
         | cpu_feature_enqcmd
#endif
#ifdef __AMX_INT8__
         | cpu_feature_amx_int8
#endif
        ;

#endif // INC_IDXD_FEATURES_H
