/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ze_utils.h"

#include "level_zero/ze_api.h"
#include "level_zero/zes_api.h"

const char* to_string(ze_result_t value)
{
    switch (value) {
#define CASE(X) case ZE_RESULT_ ## X: return #X
    CASE(SUCCESS);
    CASE(NOT_READY);
    CASE(ERROR_DEVICE_LOST);
    CASE(ERROR_OUT_OF_HOST_MEMORY);
    CASE(ERROR_OUT_OF_DEVICE_MEMORY);
    CASE(ERROR_MODULE_BUILD_FAILURE);
    CASE(ERROR_MODULE_LINK_FAILURE);
    CASE(ERROR_DEVICE_REQUIRES_RESET);
    CASE(ERROR_DEVICE_IN_LOW_POWER_STATE);
    CASE(EXP_ERROR_DEVICE_IS_NOT_VERTEX);
    CASE(EXP_ERROR_VERTEX_IS_NOT_DEVICE);
    CASE(EXP_ERROR_REMOTE_DEVICE);
    CASE(EXP_ERROR_OPERANDS_INCOMPATIBLE);
    CASE(EXP_RTAS_BUILD_RETRY);
    CASE(EXP_RTAS_BUILD_DEFERRED);
    CASE(ERROR_INSUFFICIENT_PERMISSIONS);
    CASE(ERROR_NOT_AVAILABLE);
    CASE(ERROR_DEPENDENCY_UNAVAILABLE);
    CASE(WARNING_DROPPED_DATA);
    CASE(ERROR_UNINITIALIZED);
    CASE(ERROR_UNSUPPORTED_VERSION);
    CASE(ERROR_UNSUPPORTED_FEATURE);
    CASE(ERROR_INVALID_ARGUMENT);
    CASE(ERROR_INVALID_NULL_HANDLE);
    CASE(ERROR_HANDLE_OBJECT_IN_USE);
    CASE(ERROR_INVALID_NULL_POINTER);
    CASE(ERROR_INVALID_SIZE);
    CASE(ERROR_UNSUPPORTED_SIZE);
    CASE(ERROR_UNSUPPORTED_ALIGNMENT);
    CASE(ERROR_INVALID_SYNCHRONIZATION_OBJECT);
    CASE(ERROR_INVALID_ENUMERATION);
    CASE(ERROR_UNSUPPORTED_ENUMERATION);
    CASE(ERROR_UNSUPPORTED_IMAGE_FORMAT);
    CASE(ERROR_INVALID_NATIVE_BINARY);
    CASE(ERROR_INVALID_GLOBAL_NAME);
    CASE(ERROR_INVALID_KERNEL_NAME);
    CASE(ERROR_INVALID_FUNCTION_NAME);
    CASE(ERROR_INVALID_GROUP_SIZE_DIMENSION);
    CASE(ERROR_INVALID_GLOBAL_WIDTH_DIMENSION);
    CASE(ERROR_INVALID_KERNEL_ARGUMENT_INDEX);
    CASE(ERROR_INVALID_KERNEL_ARGUMENT_SIZE);
    CASE(ERROR_INVALID_KERNEL_ATTRIBUTE_VALUE);
    CASE(ERROR_INVALID_MODULE_UNLINKED);
    CASE(ERROR_INVALID_COMMAND_LIST_TYPE);
    CASE(ERROR_OVERLAPPING_REGIONS);
    CASE(WARNING_ACTION_REQUIRED);
    CASE(ERROR_INVALID_KERNEL_HANDLE);
#undef CASE
    case ZE_RESULT_ERROR_UNKNOWN:
    case ZE_RESULT_FORCE_UINT32:
    default:
        break;
    }
    return "ERROR_UNKNOWN";
}

const char* to_string(zes_mem_type_t value)
{
    switch (value) {
    case ZES_MEM_TYPE_HBM: return "HBM";
    case ZES_MEM_TYPE_DDR: return "DDR";
    case ZES_MEM_TYPE_DDR3: return "DDR3";
    case ZES_MEM_TYPE_DDR4: return "DDR4";
    case ZES_MEM_TYPE_DDR5: return "DDR5";
    case ZES_MEM_TYPE_LPDDR: return "LPDDR";
    case ZES_MEM_TYPE_LPDDR3: return "LPDDR3";
    case ZES_MEM_TYPE_LPDDR4: return "LPDDR4";
    case ZES_MEM_TYPE_LPDDR5: return "LPDDR5";
    case ZES_MEM_TYPE_SRAM: return "SRAM";
    case ZES_MEM_TYPE_L1: return "L1";
    case ZES_MEM_TYPE_L3: return "L3";
    case ZES_MEM_TYPE_GRF: return "GRF";
    case ZES_MEM_TYPE_SLM: return "SLM";
    case ZES_MEM_TYPE_GDDR4: return "GDDR4";
    case ZES_MEM_TYPE_GDDR5: return "GDDR5";
    case ZES_MEM_TYPE_GDDR5X: return "GDDR5X";
    case ZES_MEM_TYPE_GDDR6: return "GDDR6";
    case ZES_MEM_TYPE_GDDR6X: return "GDDR6X";
    case ZES_MEM_TYPE_GDDR7: return "GDDR7";
    case ZES_MEM_TYPE_FORCE_UINT32:
        break;
    }
    return "MEM_TYPE_UNKNOWN";
}

const char* to_string(zes_mem_loc_t value)
{
    switch (value) {
    case ZES_MEM_LOC_SYSTEM: return "system";
    case ZES_MEM_LOC_DEVICE: return "device";
    case ZES_MEM_LOC_FORCE_UINT32:
        break;
    }
    return "MEM_LOC_UNKNOWN";
}

const char* to_string(zes_ras_error_type_t value)
{
    switch (value) {
    case ZES_RAS_ERROR_TYPE_CORRECTABLE: return "correctable";
    case ZES_RAS_ERROR_TYPE_UNCORRECTABLE: return "uncorrectable";
    case ZES_RAS_ERROR_TYPE_FORCE_UINT32:
        break;
    }
    return "ERROR_TYPE_UNKNOWN";
}

const char* to_string(zes_engine_group_t value)
{
    switch (value) {
    case ZES_ENGINE_GROUP_ALL: return "all";
    case ZES_ENGINE_GROUP_COMPUTE_ALL: return "compute_all";
    case ZES_ENGINE_GROUP_MEDIA_ALL: return "media_all";
    case ZES_ENGINE_GROUP_COPY_ALL: return "copy_all";
    case ZES_ENGINE_GROUP_COMPUTE_SINGLE: return "compute_single";
    case ZES_ENGINE_GROUP_RENDER_SINGLE: return "render_single";
    case ZES_ENGINE_GROUP_MEDIA_DECODE_SINGLE: return "media_decode_single";
    case ZES_ENGINE_GROUP_MEDIA_ENCODE_SINGLE: return "media_encode_single";
    case ZES_ENGINE_GROUP_COPY_SINGLE: return "copy_single";
    case ZES_ENGINE_GROUP_MEDIA_ENHANCEMENT_SINGLE: return "media_enhancement_single";
    case ZES_ENGINE_GROUP_3D_SINGLE: return "3d_single";
    case ZES_ENGINE_GROUP_3D_RENDER_COMPUTE_ALL: return "3d_render_compute_all";
    case ZES_ENGINE_GROUP_RENDER_ALL: return "render_all";
    case ZES_ENGINE_GROUP_3D_ALL: return "3d_all";
    case ZES_ENGINE_GROUP_MEDIA_CODEC_SINGLE: return "media_codec_single";
    case ZES_ENGINE_GROUP_FORCE_UINT32:
        break;
    }
    return "ENGINE_GROUP_UNKNOWN";
}

const char* to_string(zes_device_ecc_state_t value)
{
    switch (value) {
    case ZES_DEVICE_ECC_STATE_UNAVAILABLE: return "unavailable";
    case ZES_DEVICE_ECC_STATE_ENABLED: return "enabled";
    case ZES_DEVICE_ECC_STATE_DISABLED: return "disabled";
    case ZES_DEVICE_ECC_STATE_FORCE_UINT32:
        break;
    }
    return "ECC_STATE_UNKNOWN";
}

const char* to_string(zes_device_action_t value)
{
    switch (value) {
    case ZES_DEVICE_ACTION_NONE: return "none";
    case ZES_DEVICE_ACTION_WARM_CARD_RESET: return "warm_card_reset";
    case ZES_DEVICE_ACTION_COLD_CARD_RESET: return "cold_card_reset";
    case ZES_DEVICE_ACTION_COLD_SYSTEM_REBOOT: return "cold_system_reboot";
    case ZES_DEVICE_ACTION_FORCE_UINT32:
        break;
    }
    return "ACTION_UNKNOWN";
}
