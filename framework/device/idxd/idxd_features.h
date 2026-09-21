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
#define device_feature_dsa      IDXD_FEATURE_CONSTANT(3)
#define device_feature_iax      IDXD_FEATURE_CONSTANT(4)

// Type-specific version bits avoid false positives on mixed systems such as
// DSA V1 plus IAX V2.
#define device_feature_dsa_v1   IDXD_FEATURE_CONSTANT(16)
#define device_feature_dsa_v2   IDXD_FEATURE_CONSTANT(17)
#define device_feature_dsa_v3   IDXD_FEATURE_CONSTANT(18)
#define device_feature_iax_v1   IDXD_FEATURE_CONSTANT(32)
#define device_feature_iax_v2   IDXD_FEATURE_CONSTANT(33)
#define device_feature_iax_v3   IDXD_FEATURE_CONSTANT(34)

// Operation capability bits from accfg_device_get_op_cap().
// They indicate that at least one visible accelerator reports support
// for the given opcode. Common operations are split by device type since
// they may have different support levels.

// DSA common operations
#define device_feature_dsa_op_noop          IDXD_FEATURE_CONSTANT(48)
#define device_feature_dsa_op_batch         IDXD_FEATURE_CONSTANT(49)
#define device_feature_dsa_op_drain         IDXD_FEATURE_CONSTANT(50)

// DSA-specific operations
#define device_feature_op_memmove           IDXD_FEATURE_CONSTANT(51)
#define device_feature_op_fill              IDXD_FEATURE_CONSTANT(52)
#define device_feature_op_compare           IDXD_FEATURE_CONSTANT(53)
#define device_feature_op_compare_pat       IDXD_FEATURE_CONSTANT(54)
#define device_feature_op_crc_gen           IDXD_FEATURE_CONSTANT(55)
#define device_feature_op_copy_with_crc_gen IDXD_FEATURE_CONSTANT(56)
#define device_feature_op_dif_check         IDXD_FEATURE_CONSTANT(57)
#define device_feature_op_dif_insert        IDXD_FEATURE_CONSTANT(58)
#define device_feature_op_dif_strip         IDXD_FEATURE_CONSTANT(59)
#define device_feature_op_dif_update        IDXD_FEATURE_CONSTANT(60)
#define device_feature_op_cache_flush       IDXD_FEATURE_CONSTANT(61)
#define device_feature_op_crc64             IDXD_FEATURE_CONSTANT(62)

// IAX common operations
#define device_feature_iax_op_noop          IDXD_FEATURE_CONSTANT(63)
#define device_feature_iax_op_batch         IDXD_FEATURE_CONSTANT(64)
#define device_feature_iax_op_drain         IDXD_FEATURE_CONSTANT(65)

// IAX-specific operations
#define device_feature_op_dual_cast     IDXD_FEATURE_CONSTANT(66)
#define device_feature_op_create_delta  IDXD_FEATURE_CONSTANT(67)
#define device_feature_op_apply_delta   IDXD_FEATURE_CONSTANT(68)
#define device_feature_op_scan          IDXD_FEATURE_CONSTANT(69)
#define device_feature_op_extract       IDXD_FEATURE_CONSTANT(70)
#define device_feature_op_select        IDXD_FEATURE_CONSTANT(71)
#define device_feature_op_expand        IDXD_FEATURE_CONSTANT(72)
#define device_feature_op_compress      IDXD_FEATURE_CONSTANT(73)
#define device_feature_op_decompress    IDXD_FEATURE_CONSTANT(74)

// Further features can describe additional capabilities or type-specific ones.

// IDXD features are runtime-detected only; there are no compile-time feature bits.
static const device_features_t device_compiler_features = 0;

#endif // INC_IDXD_FEATURES_H
