/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_TEST_CLASS_GPU_H
#define INC_TEST_CLASS_GPU_H

#include "test_base.hpp"
#include "topology_gpu.h"
#include "ze_enumeration.h"

namespace SandstoneTest {

/// Check return value of an L0 API call and throw Skipped if not a success. Useful in run's test_loop lambda.
#define ZE_CHECK_THROW(...) \
    do { \
        auto result = (__VA_ARGS__); \
        if (result != ZE_RESULT_SUCCESS) { \
            throw Skipped{RuntimeSkipCategory, "L0 API call failed with status %s", to_string(result)}; \
        } \
    } while (0)

class Gpu : public Base
{
public:
    using BaseClass = Gpu;

    explicit Gpu(struct test* test)
    {
        auto ret = for_each_ze_device_within_topo([&](ze_device_handle_t device_handle, ze_driver_handle_t driver, const MultiSliceGpu& indices) {
            ze_handles.emplace(indices, ZeDeviceCtx{ .driver = driver, .ze_handle = device_handle });
            return EXIT_SUCCESS;
        });
        if (ret != EXIT_SUCCESS) {
            throw Skipped{RuntimeSkipCategory, "Could not initialize test"};
        }

        if (test->flags | test_requires_sysman) {
            ret = for_each_zes_device_within_topo([&](zes_device_handle_t device_handle, ze_driver_handle_t, const MultiSliceGpu& indices) {
                if (!ze_handles.count(indices)) {
                    return EXIT_FAILURE;
                }
                ze_handles.at(indices).zes_handle = device_handle;
                return EXIT_SUCCESS;
            });
            if (ret != EXIT_SUCCESS) {
                throw Skipped{RuntimeSkipCategory, "Could not initialize test"};
            }
        }
    }

protected:
    /// Handles required to be reinitialized after fork.
    GpusSet ze_handles;

private:
    friend class Base;
    template <TestClass T>
    static constexpr void _apply_parameters(struct test *test)
    {
        Base::_apply_parameters_base<T>(test);
    }
};
} // namespace SandstoneTest

#endif // INC_TEST_CLASS_GPU_H
