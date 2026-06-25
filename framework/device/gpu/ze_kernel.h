/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_ZE_KERNEL_H
#define INC_ZE_KERNEL_H

#include "sandstone.h"
#include "ze_check.h"
#include "ze_utils.h"

#include <level_zero/ze_api.h>

#include <cassert>
#include <memory>

struct ZeKernelDeleter
{
    ze_module_handle_t module;
    void operator()(ze_kernel_handle_t kernel) {
        zeKernelDestroy(kernel);
        zeModuleDestroy(module);
    }
};

using ZeKernelPtr = std::unique_ptr<_ze_kernel_handle_t, ZeKernelDeleter>;

inline void maybe_destroy_log(ze_module_build_log_handle_t build_log)
{
    if (build_log) {
        IGNORE_RETVAL(zeModuleBuildLogDestroy(build_log));
    }
}

/// Function emitting skip reason - if possible, with build log gathered from zeModuleBuildLogGetString.
[[gnu::cold]] inline void emit_skip_reason(ze_module_build_log_handle_t build_log, ze_result_t create_ret)
{
    // Gather the build log first, then emit a single log_skip message.
    const char *build_log_str = nullptr;
    std::unique_ptr<char[]> owned_log;
    if (build_log) {
        size_t log_size = 0;
        auto ret = zeModuleBuildLogGetString(build_log, &log_size, nullptr);
        if (ret == ZE_RESULT_SUCCESS && log_size > 0) {
            owned_log.reset(new char[log_size + 1]);
            size_t buffer_size = log_size;
            ret = zeModuleBuildLogGetString(build_log, &buffer_size, owned_log.get());
            if (ret == ZE_RESULT_SUCCESS) {
                owned_log[log_size] = '\0';
                build_log_str = owned_log.get();
            }
        }
    }

    if (build_log_str) {
        log_skip(RuntimeSkipCategory, "L0 API call zeModuleCreate failed with %s; build log: %s", to_string(create_ret), build_log_str);
    } else {
        log_skip(RuntimeSkipCategory, "L0 API call zeModuleCreate failed with %s", to_string(create_ret));
    }
}

/// Function returning an RAII wrapper owning a level-zero kernel (and its module) created from compiled binary source.
inline ZeKernelPtr get_ze_kernel(ze_context_handle_t context, ze_device_handle_t device, const uint8_t* source, const size_t source_size, const char* name)
{
    assert(logging_in_test);

    ze_module_handle_t ze_module = nullptr;
    ze_kernel_handle_t ze_kernel = nullptr;

    ze_module_desc_t desc = {};
    ze_module_build_log_handle_t build_log = nullptr;
#ifdef SPIRV_KERNELS_FORMAT
    desc.format = ZE_MODULE_FORMAT_IL_SPIRV;
#else
    desc.format = ZE_MODULE_FORMAT_NATIVE;
#endif
    desc.pInputModule = source;
    desc.inputSize = source_size;
    desc.pBuildFlags = "";

    auto ret = zeModuleCreate(context, device, &desc, &ze_module, &build_log);
    if (ret != ZE_RESULT_SUCCESS) [[unlikely]] {
        emit_skip_reason(build_log, ret);
        maybe_destroy_log(build_log);
        return nullptr;
    }

    maybe_destroy_log(build_log);

    ze_kernel_desc_t kernelDesc = {.stype = ZE_STRUCTURE_TYPE_KERNEL_DESC};
    kernelDesc.pKernelName = name;
    ret = zeKernelCreate(ze_module, &kernelDesc, &ze_kernel);
    if (ret != ZE_RESULT_SUCCESS) [[unlikely]] {
        IGNORE_RETVAL(zeModuleDestroy(ze_module));
        log_skip(RuntimeSkipCategory, "L0 API call zeKernelCreate failed with %s", to_string(ret));
        return nullptr; // isn't ze_kernel a nullptr anyway?
    }

    return { ze_kernel, { ze_module } };
}

#endif // INC_ZE_KERNEL_H
