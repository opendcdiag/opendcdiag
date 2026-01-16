/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ze_utils.h"

#include "level_zero/ze_api.h"
#include "level_zero/zes_api.h"

#include <unordered_map>

static constexpr auto UNKNOWN_RESOURCE_TYPE = "UNKNOWN";

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
    CASE(EXT_RTAS_BUILD_RETRY);
    CASE(EXT_RTAS_BUILD_DEFERRED);
    CASE(EXT_ERROR_OPERANDS_INCOMPATIBLE);
    CASE(ERROR_SURVIVABILITY_MODE_DETECTED);
#undef CASE
    case ZE_RESULT_ERROR_UNKNOWN:
    case ZE_RESULT_FORCE_UINT32:
        break;
    }
    return "ERROR_UNKNOWN";
}

const char* to_string(zes_mem_type_t value)
{
    static const std::unordered_map<zes_mem_type_t, const char*> map = {
        {ZES_MEM_TYPE_HBM, "HBM"},
        {ZES_MEM_TYPE_DDR, "DDR"},
        {ZES_MEM_TYPE_DDR3, "DDR3"},
        {ZES_MEM_TYPE_DDR4, "DDR4"},
        {ZES_MEM_TYPE_DDR5, "DDR5"},
        {ZES_MEM_TYPE_LPDDR, "LPDDR"},
        {ZES_MEM_TYPE_LPDDR3, "LPDDR3"},
        {ZES_MEM_TYPE_LPDDR4, "LPDDR4"},
        {ZES_MEM_TYPE_LPDDR5, "LPDDR5"},
        {ZES_MEM_TYPE_SRAM, "SRAM"},
        {ZES_MEM_TYPE_L1, "L1"},
        {ZES_MEM_TYPE_L3, "L3"},
        {ZES_MEM_TYPE_GRF, "GRF"},
        {ZES_MEM_TYPE_SLM, "SLM"},
        {ZES_MEM_TYPE_GDDR4, "GDDR4"},
        {ZES_MEM_TYPE_GDDR5, "GDDR5"},
        {ZES_MEM_TYPE_GDDR5X, "GDDR5X"},
        {ZES_MEM_TYPE_GDDR6, "GDDR6"},
        {ZES_MEM_TYPE_GDDR6X, "GDDR6X"},
        {ZES_MEM_TYPE_GDDR7, "GDDR7"},
    };
    auto found = map.find(value);
    return found != map.end() ? found->second : UNKNOWN_RESOURCE_TYPE;
}

const char* to_string(zes_mem_loc_t value)
{
    if (value == ZES_MEM_LOC_SYSTEM) {
        return "system";
    } else {
        return "device";
    }
}

const char* to_string(zes_ras_error_type_t value)
{
    if (value == ZES_RAS_ERROR_TYPE_CORRECTABLE) {
        return "correctable";
    } else {
        return "uncorrectable";
    }
}

const char* to_string(zes_engine_group_t value)
{
    static const std::unordered_map<zes_engine_group_t, const char*> map = {
        {ZES_ENGINE_GROUP_ALL, "all"},
        {ZES_ENGINE_GROUP_COMPUTE_ALL, "compute_all"},
        {ZES_ENGINE_GROUP_MEDIA_ALL, "media_all"},
        {ZES_ENGINE_GROUP_COPY_ALL, "copy_all"},
        {ZES_ENGINE_GROUP_COMPUTE_SINGLE, "compute_single"},
        {ZES_ENGINE_GROUP_RENDER_SINGLE, "render_single"},
        {ZES_ENGINE_GROUP_MEDIA_DECODE_SINGLE, "media_decode_single"},
        {ZES_ENGINE_GROUP_MEDIA_ENCODE_SINGLE, "media_encode_single"},
        {ZES_ENGINE_GROUP_COPY_SINGLE, "copy_single"},
        {ZES_ENGINE_GROUP_MEDIA_ENHANCEMENT_SINGLE, "media_enhancement_single"},
        {ZES_ENGINE_GROUP_3D_SINGLE, "3d_single"},
        {ZES_ENGINE_GROUP_3D_RENDER_COMPUTE_ALL, "3d_render_compute_all"},
        {ZES_ENGINE_GROUP_RENDER_ALL, "render_all"},
        {ZES_ENGINE_GROUP_3D_ALL, "3d_all"},
        {ZES_ENGINE_GROUP_MEDIA_CODEC_SINGLE, "media_codec_single"},
    };
    auto found = map.find(value);
    return found != map.end() ? found->second : UNKNOWN_RESOURCE_TYPE;
}

const char* to_string(zes_device_ecc_state_t value)
{
    static const std::unordered_map<zes_device_ecc_state_t, const char*> map = {
        {ZES_DEVICE_ECC_STATE_UNAVAILABLE, "unavailable"},
        {ZES_DEVICE_ECC_STATE_ENABLED, "enabled"},
        {ZES_DEVICE_ECC_STATE_DISABLED, "disabled"},
    };
    auto found = map.find(value);
    return found != map.end() ? found->second : UNKNOWN_RESOURCE_TYPE;
}

const char* to_string(zes_device_action_t value)
{
    static const std::unordered_map<zes_device_action_t, const char*> map = {
        {ZES_DEVICE_ACTION_NONE, "none"},
        {ZES_DEVICE_ACTION_WARM_CARD_RESET, "warm_card_reset"},
        {ZES_DEVICE_ACTION_COLD_CARD_RESET, "cold_card_reset"},
        {ZES_DEVICE_ACTION_COLD_SYSTEM_REBOOT, "cold_system_reboot"},
    };
    auto found = map.find(value);
    return found != map.end() ? found->second : UNKNOWN_RESOURCE_TYPE;
}
