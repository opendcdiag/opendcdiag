/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ze_enumeration.h"
#include "gpu_device.h"
#include "multi_slice_gpu.h"
#include "topology_gpu.h"

#include "level_zero/ze_api.h"
#include "level_zero/zes_api.h"

#include <type_traits>

/// ZE API allows for nested enumeration of devices and their subdevices,
/// depending on the ZE_FLAT_DEVICE_HIERARCHY env var value.
int for_each_ze_device(std::function<int(ze_device_handle_t, ze_driver_handle_t, const MultiSliceGpu&)> func)
{
    uint32_t n_drivers = 0;
    ze_init_driver_type_desc_t init_desc = { .stype = ZE_STRUCTURE_TYPE_DRIVER_PROPERTIES, .flags = ZE_INIT_DRIVER_TYPE_FLAG_GPU };
    ZE_CHECK(zeInitDrivers(&n_drivers, nullptr, &init_desc));
    std::vector<ze_driver_handle_t> drivers(n_drivers);
    ZE_CHECK(zeInitDrivers(&n_drivers, drivers.data(), &init_desc));

    int gpu_number = 0;
    for (auto ze_driver: drivers) {
        uint32_t n_devices = 0;
        ZE_CHECK(zeDeviceGet(ze_driver, &n_devices, nullptr));
        std::vector<ze_device_handle_t> devices(n_devices);
        ZE_CHECK(zeDeviceGet(ze_driver, &n_devices, devices.data()));

        for (int i = 0; i < (int)devices.size(); i++) {
            ze_device_properties_t device_properties = { .stype = ZE_STRUCTURE_TYPE_DEVICE_PROPERTIES };
            ZE_CHECK(zeDeviceGetProperties(devices[i], &device_properties));
            if (device_properties.type == ZE_DEVICE_TYPE_GPU) {
                uint32_t n_subdevices = 0;
                ZE_CHECK(zeDeviceGetSubDevices(devices[i], &n_subdevices, nullptr));
                if (n_subdevices == 0) {
                    CHECK_SANDSTONE(func(devices[i], ze_driver, MultiSliceGpu{gpu_number++, i, -1})); // subdevice_index is -1 (undefined)
                } else {
                    std::vector<ze_device_handle_t> subdevices(n_subdevices);
                    ZE_CHECK(zeDeviceGetSubDevices(devices[i], &n_subdevices, subdevices.data()));
                    for (int sub_i = 0; sub_i < (int)subdevices.size(); sub_i++) {
                        CHECK_SANDSTONE(func(subdevices[sub_i], ze_driver, MultiSliceGpu{gpu_number++, i, sub_i}));
                    }
                }
            }
        }
    }
    return EXIT_SUCCESS;
}

/// ZES API ignores ZE_FLAT_DEVICE_HIERARCHY and will always enumerate, for example, 6 root devices, instead of 12.
/// Properties queried with this API will always contain data for all subdevices. For distinction there is subdeviceId
/// field in ZES properties structs. func should accomodate for that.
int for_each_zes_device(std::function<int(zes_device_handle_t, ze_driver_handle_t, const MultiSliceGpu&)> func)
{
    ZE_CHECK(zesInit(zes_init_flags_t{}));
    uint32_t n_zes_drivers = 0;
    ZE_CHECK(zesDriverGet(&n_zes_drivers, nullptr));
    std::vector<zes_driver_handle_t> zes_drivers(n_zes_drivers);
    ZE_CHECK(zesDriverGet(&n_zes_drivers, zes_drivers.data()));

    int gpu_number = 0;
    for (auto zes_driver: zes_drivers) {
        uint32_t n_zes_devices = 0;
        ZE_CHECK(zesDeviceGet(zes_driver, &n_zes_devices, nullptr));
        std::vector<zes_device_handle_t> zes_devices(n_zes_devices);
        ZE_CHECK(zesDeviceGet(zes_driver, &n_zes_devices, zes_devices.data()));

        for (int i = 0; i < (int)zes_devices.size(); i++) {
            zes_device_properties_t device_prop = { .stype = ZES_STRUCTURE_TYPE_DEVICE_PROPERTIES };
            ZE_CHECK(zesDeviceGetProperties(zes_devices[i], &device_prop));
            if (device_prop.core.type == ZE_DEVICE_TYPE_GPU) {
                if (device_prop.numSubdevices == 0) {
                    CHECK_SANDSTONE(func(zes_devices[i], zes_driver, MultiSliceGpu{ gpu_number++, i, -1 }));
                } else {
                    for (int sub_i = 0; sub_i < (int)device_prop.numSubdevices; sub_i++) {
                        // Note the common zes_handle for all subdevices!
                        CHECK_SANDSTONE(func(zes_devices[i], zes_driver, MultiSliceGpu{ gpu_number++, i, sub_i } ));
                    }
                }
            }
        }
    }
    return EXIT_SUCCESS;
}

namespace {
template <typename Map, typename Func>
int find_and_call_func(const gpu_info_t& info, ze_driver_handle_t ze_driver, const Map& map, Func func)
{
    MultiSliceGpu indices{
        .gpu_number = info.gpu_number, .device_index = info.device_index, .subdevice_index = info.subdevice_index
    };
    auto it = map.find(indices);
    if (it != map.cend()) {
        func(it->second, ze_driver, indices);
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}

template <typename DeviceType>
int for_each_device_within_topo_internal(std::function<int(DeviceType, ze_driver_handle_t, const MultiSliceGpu&)> func)
{
    // Collect all handles for easier lookup.
    ze_driver_handle_t ze_driver;
    std::unordered_map<MultiSliceGpu, DeviceType> dev_handles;
    auto emplace_map = [&](DeviceType dev_handle, ze_driver_handle_t driver, const MultiSliceGpu& indices) {
        ze_driver = driver;
        dev_handles.emplace(indices, dev_handle);
        return EXIT_SUCCESS;
    };

    int ret;
    if constexpr (std::is_same_v<DeviceType, ze_device_handle_t>) {
        ret = for_each_ze_device(emplace_map);
    } else {
        ret = for_each_zes_device(emplace_map);
    }
    if (ze_driver == nullptr || ret != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    ret = for_each_topo_device([&](const gpu_info_t& info) {
        return find_and_call_func(info, ze_driver, dev_handles, func);
    });
    if (ret != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
} // end anonymous namespace

int for_each_ze_device_within_topo(std::function<int(ze_device_handle_t, ze_driver_handle_t, const MultiSliceGpu&)> func)
{
    return for_each_device_within_topo_internal<ze_device_handle_t>(func);
}

int for_each_zes_device_within_topo(std::function<int(zes_device_handle_t, ze_driver_handle_t, const MultiSliceGpu&)> func)
{
    return for_each_device_within_topo_internal<zes_device_handle_t>(func);
}
