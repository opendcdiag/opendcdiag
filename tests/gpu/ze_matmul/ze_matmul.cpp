/**
 * @file
 *
 * @copyright
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b ze_matmul
 * @parblock
 * Perform an element-wise matrix multiply a*b=c using the L0 API.
 * Multiplication is done on device by OpenCL kernel. Golden result
 * is computed in init() function, by the first device. Then all devices
 * (threads) compare against it in their run() functions.
 * @endparblock
 */

#include "sandstone.h"

#include "multi_slice_gpu.h"
#include "test_class_gpu.hpp"
#include "ze_kernel.h"
#include "ze_wrappers.h"

#include "matmul_source.h" // auto generated file

#include <level_zero/ze_api.h>

namespace {
class ZeMatmulTest : public SandstoneTest::Gpu
{
public:
    static constexpr auto groups = DECLARE_TEST_GROUPS(&group_math); // TODO: is it?
    static constexpr auto quality_level = TestQuality::Production;
    static constexpr char description[] = "Element-wise matrix multiply a*b=c on GPU";

    int init(struct test* test)
    {
        memset_random(a_bytes, SIZE_BYTES);
        memset_random(b_bytes, SIZE_BYTES);

        return EXIT_SUCCESS;
    }

    int run(struct test* test, const Device& device)
    {
        MultiSliceGpu msg{
            .gpu_number = device_info[device.id].gpu_number,
            .device_index = device_info[device.id].device_index,
            .subdevice_index = device_info[device.id].subdevice_index
        };

        const auto& info = device_info[device.id];

        auto& handles = ze_handles.at(msg);

        // setup
        auto context = ze_create_context(handles.driver);
        auto cmd_queue = ze_create_cmd_queue(context.get(), handles.ze_handle, {.stype = ZE_STRUCTURE_TYPE_COMMAND_QUEUE_DESC, .ordinal = 0, .index = 0, .mode = ZE_COMMAND_QUEUE_MODE_ASYNCHRONOUS,});
        auto cmd_list = ze_create_cmd_list(context.get(), handles.ze_handle, {.stype = ZE_STRUCTURE_TYPE_COMMAND_LIST_DESC, .commandQueueGroupOrdinal = 0});

        // data prep & copy
        auto a_bytes_host = ze_alloc_host(context.get(), SIZE_BYTES);
        auto b_bytes_host = ze_alloc_host(context.get(), SIZE_BYTES);
        auto golden_bytes_host = ze_alloc_host(context.get(), SIZE_BYTES);
        memcpy(a_bytes_host.get(), a_bytes, SIZE_BYTES);
        memcpy(b_bytes_host.get(), b_bytes, SIZE_BYTES);
        memset(golden_bytes_host.get(), 0xfe, SIZE_BYTES); // initalize with non-zeros so that we'd know that all-zeros after memcpy is a problem

        auto a_bytes_device = ze_alloc_device(context.get(), SIZE_BYTES, handles.ze_handle);
        auto b_bytes_device = ze_alloc_device(context.get(), SIZE_BYTES, handles.ze_handle);
        auto out_bytes_device = ze_alloc_device(context.get(), SIZE_BYTES, handles.ze_handle);

        ZE_CHECK(zeCommandListAppendMemoryCopy(cmd_list.get(), a_bytes_device.get(), a_bytes_host.get(), SIZE_BYTES, nullptr, 0, nullptr)); // host -> device
        ZE_CHECK(zeCommandListAppendMemoryCopy(cmd_list.get(), b_bytes_device.get(), b_bytes_host.get(), SIZE_BYTES, nullptr, 0, nullptr));
        // ZE_CHECK(zeCommandListAppendMemoryCopy(cmd_list.get(), out_bytes_device.get(), golden_bytes_host.get(), SIZE_BYTES, nullptr, 0, nullptr)); // TODO: should we initialize device buffer with something as well?
        ZE_CHECK(zeCommandListAppendBarrier(cmd_list.get(), nullptr, 0, nullptr));

        // kernel dispatch
        auto kernel = get_ze_kernel(context.get(), handles.ze_handle, matmul::kernel_source, matmul::kernel_size, "mxm");
        if (!kernel) {
            log_skip(RuntimeSkipCategory, "Kernel instantiation failure");
            return EXIT_SKIP;
        }

        ZE_CHECK(zeKernelSetArgumentValue(kernel, 0, SIZE_BYTES, &a_bytes_device.get()));
        ZE_CHECK(zeKernelSetArgumentValue(kernel, 1, SIZE_BYTES, &b_bytes_device.get()));
        ZE_CHECK(zeKernelSetArgumentValue(kernel, 2, SIZE_BYTES, &out_bytes_device.get()));

        uint32_t groupSizeX = std::min(info.compute_properties.maxGroupSizeX, info.compute_properties.maxTotalGroupSize / 64); // TODO: 64 is a magic number here...
        uint32_t groupSizeY = info.compute_properties.maxTotalGroupSize / groupSizeX;
        uint32_t groupSizeZ = 1;
        ZE_CHECK(zeKernelSetGroupSize(kernel, groupSizeX, groupSizeY, groupSizeZ));

        ze_group_count_t dispatch;
        if (ROWS % groupSizeX || COLS % groupSizeY) {
            log_skip(RuntimeSkipCategory, "Wrong data dimension to utilize HW");
        }
        dispatch.groupCountX = ROWS / groupSizeX;
        dispatch.groupCountY = COLS / groupSizeY;
        dispatch.groupCountZ = 1;
        ZE_CHECK(zeCommandListAppendLaunchKernel(cmd_list.get(), kernel, &dispatch, nullptr, 0, nullptr));
        ZE_CHECK(zeCommandListAppendBarrier(cmd_list.get(), nullptr, 0, nullptr));
        ZE_CHECK(zeCommandListAppendMemoryCopy(cmd_list.get(), golden_bytes_host.get(), out_bytes_device.get(), SIZE_BYTES, nullptr, 0, nullptr));
        ZE_CHECK(zeCommandListClose(cmd_list.get()));

        ZE_CHECK(zeCommandQueueExecuteCommandLists(cmd_queue.get(), 1, &cmd_list.get(), nullptr));
        ZE_CHECK(zeCommandQueueSynchronize(cmd_queue.get(), std::numeric_limits<uint64_t>::max()));

        test_loop<1>([&] {
            auto out_bytes_host = ze_alloc_host(context.get(), SIZE_BYTES);
            memset(out_bytes_host.get(), 0xdd, SIZE_BYTES); // initialize with non-zero data (other than golden)
            ZE_CHECK_THROW(zeCommandListReset(cmd_list.get()));

            ZE_CHECK_THROW(zeCommandListAppendLaunchKernel(cmd_list.get(), kernel, &dispatch, nullptr, 0, nullptr));
            ZE_CHECK_THROW(zeCommandListAppendBarrier(cmd_list.get(), nullptr, 0, nullptr));
            ZE_CHECK_THROW(zeCommandListAppendMemoryCopy(cmd_list.get(), out_bytes_host.get(), out_bytes_device.get(), SIZE_BYTES, nullptr, 0, nullptr));
            ZE_CHECK_THROW(zeCommandListClose(cmd_list.get()));

            ZE_CHECK_THROW(zeCommandQueueExecuteCommandLists(cmd_queue.get(), 1, &cmd_list.get(), nullptr));
            ZE_CHECK_THROW(zeCommandQueueSynchronize(cmd_queue.get(), std::numeric_limits<uint64_t>::max()));

            for (auto i = 0; i < std::min<decltype(SIZE)>(10, SIZE); i++) {
                log_debug("%d: a %d b %d golden %d out %d", i, ((int*)a_bytes)[i], ((int*)b_bytes)[i], ((int*)golden_bytes_host.get())[i], ((int*)out_bytes_host.get())[i]);
            }

            memcmp_or_fail((int*)out_bytes_host.get(), (int*)golden_bytes_host.get(), SIZE, "Data in ze_matmul");
        });

        return EXIT_SUCCESS;
    }

private:
    static constexpr auto ROWS = 1024;
    static constexpr auto COLS = 1024;
    static constexpr auto SIZE = ROWS * COLS;
    static constexpr auto SIZE_BYTES = ROWS * COLS * sizeof(int);

    uint8_t a_bytes[SIZE_BYTES]; // TODO: unique ptr?
    uint8_t b_bytes[SIZE_BYTES];
    uint8_t golden_bytes[SIZE_BYTES]; // TODO: for cross compare?
};
} // end anonymous namespace

DECLARE_TEST_CLASS(ze_matmul, ZeMatmulTest);
