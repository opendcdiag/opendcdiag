/**
 * @file
 *
 * @copyright
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b ze_matmul
 * @parblock
 * Test runs matrix multiplication kernel (elementwise). Each workgroup
 * operates on the same data. Matrix is of size of maxTotalGroupSize.
 * @endparblock
 */

#include "sandstone.h"

#include "multi_slice_gpu.h"
#include "ze_check.h"
#include "ze_enumeration.h"
#include "ze_kernel.h"
#include "ze_wrappers.h"

#include "matmul_source.h" // auto generated file

#include <algorithm>
#include <limits>
#include <vector>

namespace {
static constexpr uint32_t INTERNAL_LOOP_COUNT = 2048;

struct ze_matmul_data
{
    // TODO: to be put in the common part for each L0 test
    ze_driver_handle_t ze_driver{};
    std::vector<ze_device_handle_t> ze_handles;

    ZeContextPtr context;
    ZeHostDataPtr a;
    ZeHostDataPtr b;

    size_t max_group_size;
    size_t group_count;

    size_t rows;
    uint32_t cols;
    size_t size;
    size_t size_bytes;
};

int ze_matmul_init(struct test* test)
{
    auto data = new ze_matmul_data;

    // TODO: to be put in the common part for each L0 test
    for_each_ze_device_within_topo([&](ze_device_handle_t device_handle, ze_driver_handle_t driver, const MultiSliceGpu& indices) {
        data->ze_handles.emplace_back(device_handle);
        data->ze_driver = driver;
        return EXIT_SUCCESS;
    });

    // We assume homogenous topology
    const auto& info = device_info[0];

    data->max_group_size = info.compute_properties.maxTotalGroupSize;
    if (data->max_group_size % 16 != 0) {
        log_skip(RuntimeSkipCategory, "Cannot construct matrix");
        delete data;
        return EXIT_SKIP;
    }

    data->rows = data->max_group_size / 16;
    data->cols = 16;
    data->size = data->rows * data->cols;
    data->size_bytes = data->size * sizeof(int);

    size_t num_xe_cores = info.device_properties.numSlices * info.device_properties.numSubslicesPerSlice;
    size_t num_hw_threads_per_xe_core = info.device_properties.numEUsPerSubslice * info.device_properties.numThreadsPerEU;
    size_t max_subgroup_size = info.compute_properties.numSubGroupSizes > 0
            ? *std::max_element(info.compute_properties.subGroupSizes,
                            info.compute_properties.subGroupSizes + info.compute_properties.numSubGroupSizes)
            : 1;
    data->group_count = num_xe_cores * num_hw_threads_per_xe_core * max_subgroup_size / data->size;
    assert(data->group_count > 0 && data->group_count <= std::numeric_limits<uint32_t>::max());

    data->context = ze_create_context(data->ze_driver);
    data->a = ze_alloc_host(data->context.get(), data->size_bytes);
    data->b = ze_alloc_host(data->context.get(), data->size_bytes);
    memset_random(data->a.get(), data->size_bytes);
    memset_random(data->b.get(), data->size_bytes);

    test->data = data;
    return EXIT_SUCCESS;
}

int ze_matmul_run(struct test* test, int thread)
{
    auto data = static_cast<ze_matmul_data*>(test->data);

    if (thread >= data->ze_handles.size()) {
        log_skip(RuntimeSkipCategory, "no ze_handle for thread");
        return EXIT_SKIP;
    }
    auto device = data->ze_handles[thread];

    auto cmd_queue = ze_create_cmd_queue(data->context.get(), device, {.stype = ZE_STRUCTURE_TYPE_COMMAND_QUEUE_DESC, .ordinal = 0, .index = 0, .mode = ZE_COMMAND_QUEUE_MODE_ASYNCHRONOUS,});
    auto cmd_list = ze_create_cmd_list(data->context.get(), device, {.stype = ZE_STRUCTURE_TYPE_COMMAND_LIST_DESC, .commandQueueGroupOrdinal = 0});

    auto ze_kernel = get_ze_kernel(data->context.get(), device, matmul::kernel_source, matmul::kernel_size, "mxm");
    if (!ze_kernel) {
        log_skip(RuntimeSkipCategory, "Kernel instantiation failure");
        return EXIT_SKIP;
    }

    // Kernel thread-dispatch
    ze_group_count_t dispatch;
    assert(data->group_count <= std::numeric_limits<uint32_t>::max());
    dispatch.groupCountX = data->group_count;
    dispatch.groupCountY = 1;
    dispatch.groupCountZ = 1;

    // Prepare buffers
    auto a_device = ze_alloc_device(data->context.get(), data->size_bytes, device);    // in
    auto b_device = ze_alloc_device(data->context.get(), data->size_bytes, device);    // in
    auto out_device = ze_alloc_device(data->context.get(), data->size_bytes * data->group_count, device);  // out; for golden & output
    auto out_initial = ze_alloc_host(data->context.get(), data->size_bytes * data->group_count);
    auto golden = ze_alloc_host(data->context.get(), data->size_bytes * data->group_count);
    memset(out_initial.get(), 0xfe, data->size_bytes * data->group_count);
    memset(golden.get(), 1, data->size_bytes * data->group_count);
    auto output = ze_alloc_host(data->context.get(), data->size_bytes * data->group_count);

    uint32_t groupSizeX = data->rows;
    uint32_t groupSizeY = data->cols;
    uint32_t groupSizeZ = 1;
    ZE_CHECK(zeKernelSetGroupSize(ze_kernel.get(), groupSizeX, groupSizeY, groupSizeZ));

    // Push arguments
    ZE_CHECK(zeKernelSetArgumentValue(ze_kernel.get(), 0, sizeof(a_device.get()), &a_device.get()));     // a
    ZE_CHECK(zeKernelSetArgumentValue(ze_kernel.get(), 1, sizeof(b_device.get()), &b_device.get()));     // b
    ZE_CHECK(zeKernelSetArgumentValue(ze_kernel.get(), 2, sizeof(out_device.get()), &out_device.get())); // out
    ZE_CHECK(zeKernelSetArgumentValue(ze_kernel.get(), 3, sizeof(data->cols), &data->cols));  // cols
    ZE_CHECK(zeKernelSetArgumentValue(ze_kernel.get(), 4, sizeof(INTERNAL_LOOP_COUNT), &INTERNAL_LOOP_COUNT));  // internal_loops_n

    // Copy data
    ZE_CHECK(zeCommandListAppendMemoryCopy(cmd_list.get(), a_device.get(), data->a.get(), data->size_bytes, nullptr, 0, nullptr)); // host -> device
    ZE_CHECK(zeCommandListAppendMemoryCopy(cmd_list.get(), b_device.get(), data->b.get(), data->size_bytes, nullptr, 0, nullptr));
    ZE_CHECK(zeCommandListAppendMemoryCopy(cmd_list.get(), out_device.get(), out_initial.get(), data->size_bytes * data->group_count, nullptr, 0, nullptr));
    ZE_CHECK(zeCommandListAppendBarrier(cmd_list.get(), nullptr, 0, nullptr));

    // Launch kernel on the GPU
    ZE_CHECK(zeCommandListAppendLaunchCooperativeKernel(cmd_list.get(), ze_kernel.get(), &dispatch, nullptr, 0, nullptr));

    // Calc golden
    ZE_CHECK(zeCommandListAppendBarrier(cmd_list.get(), nullptr, 0, nullptr));
    ZE_CHECK(zeCommandListAppendMemoryCopy(cmd_list.get(), golden.get(), out_device.get(), data->size_bytes * data->group_count, nullptr, 0, nullptr));

    ZE_CHECK(zeCommandListClose(cmd_list.get()));
    ZE_CHECK(zeCommandQueueExecuteCommandLists(cmd_queue.get(), 1, &cmd_list.get(), nullptr));
    ZE_CHECK(zeCommandQueueSynchronize(cmd_queue.get(), std::numeric_limits<uint64_t>::max()));

    TEST_LOOP(test, 64) {
        ZE_CHECK(zeCommandListReset(cmd_list.get()));

        ZE_CHECK(zeCommandListAppendMemoryCopy(cmd_list.get(), out_device.get(), out_initial.get(), data->size_bytes * data->group_count, nullptr, 0, nullptr));
        ZE_CHECK(zeCommandListAppendBarrier(cmd_list.get(), nullptr, 0, nullptr));

        ZE_CHECK(zeCommandListAppendLaunchCooperativeKernel(cmd_list.get(), ze_kernel.get(), &dispatch, nullptr, 0, nullptr));
        ZE_CHECK(zeCommandListAppendBarrier(cmd_list.get(), nullptr, 0, nullptr));
        ZE_CHECK(zeCommandListAppendMemoryCopy(cmd_list.get(), output.get(), out_device.get(), data->size_bytes * data->group_count, nullptr, 0, nullptr));

        ZE_CHECK(zeCommandListClose(cmd_list.get()));
        ZE_CHECK(zeCommandQueueExecuteCommandLists(cmd_queue.get(), 1, &cmd_list.get(), nullptr));
        ZE_CHECK(zeCommandQueueSynchronize(cmd_queue.get(), std::numeric_limits<uint64_t>::max()));

        memcmp_or_fail(output.get(), golden.get(), data->size_bytes * data->group_count, "ze_matmul data mismatch");
    }

    return EXIT_SUCCESS;
}

int ze_matmul_cleanup(struct test* test)
{
    auto data = static_cast<ze_matmul_data*>(test->data);
    test->data = nullptr;
    delete data;
    return EXIT_SUCCESS;
}

} // end anonymous namespace

DECLARE_TEST(ze_matmul, "Level zero elementwise matrix multiply")
    .test_init = ze_matmul_init,
    .test_run = ze_matmul_run,
    .test_cleanup = ze_matmul_cleanup,
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_BETA,
END_DECLARE_TEST
