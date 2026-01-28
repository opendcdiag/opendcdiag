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

class Gpu : public Base
{
public:
    using BaseClass = Gpu;

    explicit Gpu()
    {
        auto ret = for_each_ze_device_within_topo([&](ze_device_handle_t device_handle, ze_driver_handle_t driver, const MultiSliceGpu& indices) {
            ze_handles.emplace(indices, ZeDeviceCtx{ .driver = driver, .ze_handle = device_handle });
            return EXIT_SUCCESS;
        });
        if (ret != EXIT_SUCCESS) {
            throw Skipped{RuntimeSkipCategory, "Could not initialize test"};
        }

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
