/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_ZE_WRAPPERS_H
#define INC_ZE_WRAPPERS_H

#include "sandstone.h"
#include "ze_utils.h"

#include <level_zero/ze_api.h>

#include <cassert>
#include <memory>
#include <utility>

extern bool logging_in_test;

/// Use for non-critical paths (like cleanup): log the failure but do not mark test as skipped.
#define ZE_CHECK_AND_LOG(...) \
    do { \
        assert(logging_in_test); \
        auto result = (__VA_ARGS__); \
        if (result != ZE_RESULT_SUCCESS) { \
            log_warning("L0 API call failed with status %s", to_string(result)); \
        } \
    } while (0)

/// Use for critical setup paths (like constructors/factories): log_skip marks thread as skipped,
/// but the macro still continues. Caller must validate the handle and return on null (see CHECK_NULL below).
#define ZE_CHECK_AND_SKIP(...) \
    do { \
        assert(logging_in_test); \
        auto result = (__VA_ARGS__); \
        if (result != ZE_RESULT_SUCCESS) { \
            log_skip(RuntimeSkipCategory, "L0 API call failed with status %s", to_string(result)); \
        } \
    } while (0)

/// Macro for call sites. Returns skip if constructed handle is null. Error should've
/// already been printed by ZE_CHECK_AND_LOG/SKIP macros, so here we just return.
#define CHECK_NULL(handle) \
    do { \
        if (!(handle)) { \
            return EXIT_SKIP; \
        } \
    } while (0)

class NonCopyable
{
public:
    NonCopyable() = default;
    NonCopyable(const NonCopyable&) = delete;
    NonCopyable& operator=(const NonCopyable&) = delete;
    NonCopyable(NonCopyable&&) = default;
    NonCopyable& operator=(NonCopyable&&) = default;
};

/// Wrappers being classes. They require getters to return ref, which std::unique_ptr won't allow.
class ZeDeviceDataPtr : public NonCopyable
{
public:
    ZeDeviceDataPtr(
        ze_context_handle_t context,
        size_t size,
        ze_device_handle_t device,
        const ze_device_mem_alloc_desc_t& desc = { .stype = ZE_STRUCTURE_TYPE_DEVICE_MEM_ALLOC_DESC },
        size_t alignment = 1
    ) :
        context{context}
    {
        ZE_CHECK_AND_SKIP(zeMemAllocDevice(context, &desc, size, alignment, device, &data));
    }

    ZeDeviceDataPtr(ZeDeviceDataPtr&& other) noexcept :
        NonCopyable{std::move(other)},
        data{std::exchange(other.data, nullptr)},
        context{std::exchange(other.context, nullptr)}
    {}

    ZeDeviceDataPtr& operator=(ZeDeviceDataPtr&& other) {
        if (this != &other) {
            if (data) {
                ZE_CHECK_AND_LOG(zeMemFree(context, data));
            }
            data = std::exchange(other.data, nullptr);
            context = std::exchange(other.context, nullptr);
        }
        return *this;
    }

    ~ZeDeviceDataPtr() {
        if (data) {
            ZE_CHECK_AND_LOG(zeMemFree(context, data));
        }
    }

    // zeKernelSetArgumentValue requires ref
    void*& get() noexcept { return data; }
    const void* get() const noexcept { return data; }

    explicit operator bool() const noexcept { return data != nullptr; }

private:
    void* data = nullptr;
    ze_context_handle_t context{};
};

class ZeCmdListPtr : public NonCopyable
{
public:
    ZeCmdListPtr(ze_context_handle_t context, ze_device_handle_t device, const ze_command_list_desc_t& desc) {
        ZE_CHECK_AND_SKIP(zeCommandListCreate(context, device, &desc, &cmd_list));
    }

    ZeCmdListPtr(ZeCmdListPtr&& other) noexcept:
        NonCopyable{std::move(other)},
        cmd_list{std::exchange(other.cmd_list, nullptr)}
    {}

    ZeCmdListPtr& operator=(ZeCmdListPtr&& other) {
        if (this != &other) {
            if (cmd_list) {
                ZE_CHECK_AND_LOG(zeCommandListDestroy(cmd_list));
            }
            cmd_list = std::exchange(other.cmd_list, nullptr);
        }
        return *this;
    }

    ~ZeCmdListPtr() {
        if (cmd_list)
            ZE_CHECK_AND_LOG(zeCommandListDestroy(cmd_list));
    }

    // zeCommandQueueExecuteCommandLists takes _ze_command_list_handle_t** as argument
    ze_command_list_handle_t& get() noexcept { return cmd_list; }

    explicit operator bool() const noexcept { return cmd_list != nullptr; }

private:
    ze_command_list_handle_t cmd_list{};
};

/// Wrappers being std::unique_ptrs with custom deleters.
struct ZeHostDataPtrDeleter
{
    ze_context_handle_t context;
    void operator()(void* data) {
        ZE_CHECK_AND_LOG(zeMemFree(context, data));
    }
};

struct ZeFenceDeleter
{
    void operator()(ze_fence_handle_t fence) {
        ZE_CHECK_AND_LOG(zeFenceDestroy(fence));
    }
};

struct ZeCmdQueueDeleter
{
    void operator()(ze_command_queue_handle_t cmd_queue) {
        ZE_CHECK_AND_LOG(zeCommandQueueDestroy(cmd_queue));
    }
};

struct ZeContextDeleter
{
    void operator()(ze_context_handle_t context) {
        ZE_CHECK_AND_LOG(zeContextDestroy(context));
    }
};

using ZeHostDataPtr = std::unique_ptr<void, ZeHostDataPtrDeleter>;
using ZeCmdQueuePtr = std::unique_ptr<_ze_command_queue_handle_t, ZeCmdQueueDeleter>;
using ZeFencePtr = std::unique_ptr<_ze_fence_handle_t, ZeFenceDeleter>;
using ZeContextPtr = std::unique_ptr<_ze_context_handle_t, ZeContextDeleter>;

/// Factory functions.
inline ZeHostDataPtr ze_alloc_host(ze_context_handle_t context, size_t size,
        const ze_host_mem_alloc_desc_t& desc = { .stype = ZE_STRUCTURE_TYPE_HOST_MEM_ALLOC_DESC },
        size_t alignment = 1)
{
    ZeHostDataPtrDeleter deleter{context};
    void* data = nullptr;
    ZE_CHECK_AND_SKIP(zeMemAllocHost(context, &desc, size, alignment, &data));
    return {data, deleter};
}

inline ZeDeviceDataPtr ze_alloc_device(ze_context_handle_t context, size_t size, ze_device_handle_t device,
        const ze_device_mem_alloc_desc_t& desc = { .stype = ZE_STRUCTURE_TYPE_DEVICE_MEM_ALLOC_DESC  },
        size_t alignment = 1)
{
    return {context, size, device, desc, alignment};
}

inline ZeHostDataPtr ze_alloc_shared(ze_context_handle_t context, size_t size, ze_device_handle_t device,
        const ze_device_mem_alloc_desc_t& device_desc = { .stype = ZE_STRUCTURE_TYPE_DEVICE_MEM_ALLOC_DESC },
        const ze_host_mem_alloc_desc_t& host_desc = { .stype = ZE_STRUCTURE_TYPE_HOST_MEM_ALLOC_DESC },
        size_t alignment = 1)
{
    ZeHostDataPtrDeleter deleter{context};
    void* data = nullptr;
    ZE_CHECK_AND_SKIP(zeMemAllocShared(context, &device_desc, &host_desc, size, alignment, device, &data));
    return {data, deleter};
}

inline ZeCmdListPtr ze_create_cmd_list(ze_context_handle_t context, ze_device_handle_t device, const ze_command_list_desc_t& desc)
{
    return {context, device, desc};
}

inline ZeCmdQueuePtr ze_create_cmd_queue(ze_context_handle_t context, ze_device_handle_t device, const ze_command_queue_desc_t& desc)
{
    ZeCmdQueueDeleter deleter{};
    ze_command_queue_handle_t cmd_queue{};
    ZE_CHECK_AND_SKIP(zeCommandQueueCreate(context, device, &desc, &cmd_queue));
    return {cmd_queue, deleter};
}

inline ZeFencePtr ze_create_fence(ze_command_queue_handle_t cmd_queue, const ze_fence_desc_t& desc)
{
    ZeFenceDeleter deleter{};
    ze_fence_handle_t fence{};
    ZE_CHECK_AND_SKIP(zeFenceCreate(cmd_queue, &desc, &fence));
    return {fence, deleter};
}

inline ZeContextPtr ze_create_context(ze_driver_handle_t driver, const ze_context_desc_t& desc = { .stype = ZE_STRUCTURE_TYPE_CONTEXT_DESC })
{
    ZeContextDeleter deleter{};
    ze_context_handle_t context{};
    ZE_CHECK_AND_SKIP(zeContextCreate(driver, &desc, &context));
    return {context, deleter};
}

#endif // INC_ZE_WRAPPERS_H
