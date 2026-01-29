/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_ZE_KERNEL_H
#define INC_ZE_KERNEL_H

#include "ze_check.h"
#include "ze_utils.h"

#include "level_zero/ze_api.h"

#include <memory>

/// Function returning level-zero kernel handle from compiled binary source.
inline ze_kernel_handle_t get_ze_kernel(ze_context_handle_t context, ze_device_handle_t device, const uint8_t* source, const size_t source_size, const char* name)
{
    assert(logging_in_test);

    ze_module_handle_t ze_module = nullptr;
    ze_kernel_handle_t ze_kernel = nullptr;

    ze_module_desc_t desc = {};
    ze_module_build_log_handle_t build_log;
#ifdef SPIRV_KERNELS_FORMAT
    desc.format = ZE_MODULE_FORMAT_IL_SPIRV;
#else
    desc.format = ZE_MODULE_FORMAT_NATIVE;
#endif
    desc.pInputModule = source;
    desc.inputSize = source_size;
    desc.pBuildFlags = "";

    auto ret = zeModuleCreate(context, device, &desc, &ze_module, &build_log);
    if (ret != ZE_RESULT_SUCCESS) {
        // try to print log
        size_t log_size = 0;
        ret = zeModuleBuildLogGetString(build_log, &log_size, nullptr);
        if (ret != ZE_RESULT_SUCCESS) {
            return nullptr; // give up
        }
        std::unique_ptr<char[]> string_log(new char[log_size]);
        ret = zeModuleBuildLogGetString(build_log, &log_size, string_log.get());
        if (ret != ZE_RESULT_SUCCESS) {
            return nullptr;
        }
        log_debug("zeModuleCreate ret: %s (0x%x) zeModuleCreate log: %s", to_string(ret), ret, string_log.get());
        return nullptr;
    }

    ret = zeModuleBuildLogDestroy(build_log);
    if (ret != ZE_RESULT_SUCCESS) {
        log_debug("L0 API call zeModuleBuildLogDestroy failed with %s (0x%x)", to_string(ret), ret);
        // TODO: shall we return from here? It does not seem to be a serious problem.
    }

    ze_kernel_desc_t kernelDesc = {.stype = ZE_STRUCTURE_TYPE_KERNEL_DESC};
    kernelDesc.pKernelName = name;
    ret = zeKernelCreate(ze_module, &kernelDesc, &ze_kernel);
    if (ret != ZE_RESULT_SUCCESS) {
        log_debug("L0 API call zeKernelCreate failed with %s (0x%x)", to_string(ret), ret);
        return nullptr; // isn't ze_kernel a nullptr anyway?
    }

    return ze_kernel;
}

#endif // INC_ZE_KERNEL_H
