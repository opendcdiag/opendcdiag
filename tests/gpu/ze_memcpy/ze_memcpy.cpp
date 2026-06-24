/**
 * @file
 *
 * @copyright
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b ze_memcpy
 * @parblock
 * Test runs trivial memcpy of the buffer between host and device in a tight loop.
 * @endparblock
 */

#include <sandstone.h>

#include <multi_slice_gpu.h>
#include <ze_check.h>
#include <ze_enumeration.h>
#include <ze_wrappers.h>

#include <limits>
#include <vector>

namespace {
constexpr size_t SIZE_BYTES = 1024 * 1024;

struct ze_memcpy_data {
    // TODO: to be put in the common part for each L0 test
    ze_driver_handle_t ze_driver{};
    std::vector<ze_device_handle_t> ze_handles;

    ZeContextPtr context;
    ZeHostDataPtr golden;
};

int ze_memcpy_init(struct test* test)
{
    auto data = new ze_memcpy_data;

    // TODO: to be put in the common part for each L0 test
    int ret = for_each_ze_device_within_topo([&](ze_device_handle_t device_handle, ze_driver_handle_t driver, const MultiSliceGpu&) {
        data->ze_handles.emplace_back(device_handle);
        data->ze_driver = driver;
        return EXIT_SUCCESS;
    });
    if (ret != EXIT_SUCCESS) {
        delete data;
        return ret;
    }

    data->context = ze_create_context(data->ze_driver);
    if (!data->context) {
        delete data;
        return EXIT_SKIP;
    }
    data->golden = ze_alloc_host(data->context.get(), SIZE_BYTES);
    if (!data->golden) {
        delete data;
        return EXIT_SKIP;
    }
    memset_random(data->golden.get(), SIZE_BYTES);

    test->data = data;
    return EXIT_SUCCESS;
}

int ze_memcpy_run(struct test* test, int thread)
{
    auto data = static_cast<ze_memcpy_data*>(test->data);

    if (thread >= data->ze_handles.size()) {
        log_skip(RuntimeSkipCategory, "no ze_handle for thread");
        return EXIT_SKIP;
    }
    auto device = data->ze_handles[thread];

    auto output = ze_alloc_host(data->context.get(), SIZE_BYTES); CHECK_NULL(output);
    auto buffer_device = ze_alloc_device(data->context.get(), SIZE_BYTES, device); CHECK_NULL(buffer_device);

    auto cmd_queue = ze_create_cmd_queue(data->context.get(), device, { .stype = ZE_STRUCTURE_TYPE_COMMAND_QUEUE_DESC, .mode = ZE_COMMAND_QUEUE_MODE_ASYNCHRONOUS });
    CHECK_NULL(cmd_queue);
    auto cmd_list = ze_create_cmd_list(data->context.get(), device, { .stype = ZE_STRUCTURE_TYPE_COMMAND_LIST_DESC });
    CHECK_NULL(cmd_list);
    auto fence = ze_create_fence(cmd_queue.get(), { .stype = ZE_STRUCTURE_TYPE_FENCE_DESC });
    CHECK_NULL(fence);

    TEST_LOOP(test, 128) {
        ZE_CHECK(zeCommandListAppendMemoryCopy(cmd_list.get(), buffer_device.get(), data->golden.get(), SIZE_BYTES, nullptr, 0, nullptr));
        ZE_CHECK(zeCommandListAppendBarrier(cmd_list.get(), nullptr, 0, nullptr));
        ZE_CHECK(zeCommandListAppendMemoryCopy(cmd_list.get(), output.get(), buffer_device.get(), SIZE_BYTES, nullptr, 0, nullptr));
        ZE_CHECK(zeCommandListAppendBarrier(cmd_list.get(), nullptr, 0, nullptr));

        ZE_CHECK(zeCommandListClose(cmd_list.get()));
        ZE_CHECK(zeCommandQueueExecuteCommandLists(cmd_queue.get(), 1, &cmd_list.get(), fence.get()));

        ZE_CHECK(zeFenceHostSynchronize(fence.get(), std::numeric_limits<uint64_t>::max()));

        memcmp_or_fail(output.get(), data->golden.get(), SIZE_BYTES, "ze_memcpy data mismatch");

        ZE_CHECK(zeFenceReset(fence.get()));
        ZE_CHECK(zeCommandListReset(cmd_list.get()));
    }

    return EXIT_SUCCESS;
}

int ze_memcpy_cleanup(struct test* test)
{
    auto data = static_cast<ze_memcpy_data*>(test->data);
    test->data = nullptr;
    delete data;
    return EXIT_SUCCESS;
}

} // end anonymous namespace

DECLARE_TEST(ze_memcpy, "Level zero memcpy test")
    .test_init = ze_memcpy_init,
    .test_run = ze_memcpy_run,
    .test_cleanup = ze_memcpy_cleanup,
    .desired_duration = -1,
    .quality_level = TEST_QUALITY_BETA,
END_DECLARE_TEST
