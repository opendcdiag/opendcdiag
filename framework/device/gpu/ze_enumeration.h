/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_ZE_ENUMERATION_H
#define INC_ZE_ENUMERATION_H

#include "sandstone_p.h"
#include "multi_slice_gpu.h"
#include "ze_check.h"

#include "level_zero/ze_api.h"
#include "level_zero/zes_api.h"

#include <concepts>
#include <functional>
#include <type_traits>

#define CHECK_SANDSTONE(...) \
    if ((__VA_ARGS__) != EXIT_SUCCESS) \
        return EXIT_FAILURE;

/// Functions containing boilerplate code for drivers, devices and subdevices enumeration. Contains level-zero drivers
/// initialization, so can be called as a standalone function anytime. Calls passed function for each found Intel device.
/// In case where a device has its subdevices, passed function is called for each such subdevice.
int for_each_ze_device(std::function<int(ze_device_handle_t, ze_driver_handle_t, const MultiSliceGpu&)> func);
int for_each_zes_device(std::function<int(zes_device_handle_t, ze_driver_handle_t, const MultiSliceGpu&)> func);

/// Same as above, but with additional topology lookup step. Calls passed function for each found Intel device being
/// part of the current Topology.
int for_each_ze_device_within_topo(std::function<int(ze_device_handle_t, ze_driver_handle_t, const MultiSliceGpu&)> func);
int for_each_zes_device_within_topo(std::function<int(zes_device_handle_t, ze_driver_handle_t, const MultiSliceGpu&)> func);

/// Functions for enumerating given resource type. Called inside for_each_* functions.
inline ze_result_t get_ze_handles(zes_device_handle_t device_handle, uint32_t& count, zes_mem_handle_t* vec)
{
    return zesDeviceEnumMemoryModules(device_handle, &count, vec);
}
inline ze_result_t get_ze_handles(zes_device_handle_t device_handle, uint32_t& count, zes_engine_handle_t* vec)
{
    return zesDeviceEnumEngineGroups(device_handle, &count, vec);
}
inline ze_result_t get_ze_handles(zes_device_handle_t device_handle, uint32_t& count, zes_ras_handle_t* vec)
{
    return zesDeviceEnumRasErrorSets(device_handle, &count, vec);
}
inline ze_result_t get_ze_handles(zes_device_handle_t device_handle, uint32_t& count, zes_fabric_port_handle_t* vec)
{
    return zesDeviceEnumFabricPorts(device_handle, &count, vec);
}
inline ze_result_t get_ze_handles(zes_device_handle_t device_handle, uint32_t& count, zes_freq_handle_t* vec)
{
    return zesDeviceEnumFrequencyDomains(device_handle, &count, vec);
}
inline ze_result_t get_ze_handles(zes_device_handle_t device_handle, uint32_t& count, zes_temp_handle_t* vec)
{
    return zesDeviceEnumTemperatureSensors(device_handle, &count, vec);
}

/// Helper struct matching resource type to it's property type and property descriptor.
template <typename ResourceType>
struct ZesTypes;
template <> struct ZesTypes<zes_mem_handle_t>
{
    using PropertyType = zes_mem_properties_t;
    static constexpr _zes_structure_type_t PropertySType = ZES_STRUCTURE_TYPE_MEM_PROPERTIES;
};
template <> struct ZesTypes<zes_engine_handle_t>
{
    using PropertyType = zes_engine_properties_t;
    static constexpr _zes_structure_type_t PropertySType = ZES_STRUCTURE_TYPE_ENGINE_PROPERTIES;
};
template <> struct ZesTypes<zes_ras_handle_t>
{
    using PropertyType = zes_ras_properties_t;
    static constexpr _zes_structure_type_t PropertySType = ZES_STRUCTURE_TYPE_RAS_PROPERTIES;
};
template <> struct ZesTypes<zes_fabric_port_handle_t>
{
    using PropertyType = zes_fabric_port_properties_t;
    static constexpr _zes_structure_type_t PropertySType = ZES_STRUCTURE_TYPE_FABRIC_PORT_PROPERTIES;
};
template <> struct ZesTypes<zes_freq_handle_t>
{
    using PropertyType = zes_freq_properties_t;
    static constexpr _zes_structure_type_t PropertySType = ZES_STRUCTURE_TYPE_FREQ_PROPERTIES;
};
template <> struct ZesTypes<zes_temp_handle_t>
{
    using PropertyType = zes_temp_properties_t;
    static constexpr _zes_structure_type_t PropertySType = ZES_STRUCTURE_TYPE_TEMP_PROPERTIES;
};

/// Functions to query for a property of a concrete resource type.
inline ze_result_t get_ze_properties(zes_mem_handle_t handle, zes_mem_properties_t* props)
{
    return zesMemoryGetProperties(handle, props);
}
inline ze_result_t get_ze_properties(zes_engine_handle_t handle, zes_engine_properties_t* props)
{
    return zesEngineGetProperties(handle, props);
}
inline ze_result_t get_ze_properties(zes_ras_handle_t handle, zes_ras_properties_t* props)
{
    return zesRasGetProperties(handle, props);
}
inline ze_result_t get_ze_properties(zes_fabric_port_handle_t handle, zes_fabric_port_properties_t* props)
{
    return zesFabricPortGetProperties(handle, props);
}
inline ze_result_t get_ze_properties(zes_freq_handle_t handle, zes_freq_properties_t* props)
{
    return zesFrequencyGetProperties(handle, props);
}
inline ze_result_t get_ze_properties(zes_temp_handle_t handle, zes_temp_properties_t* props)
{
    return zesTemperatureGetProperties(handle, props);
}

template<typename Callable>
using return_type_of_t =
    typename decltype(std::function{std::declval<Callable>()})::result_type;

/// Function containing boilerplate code for enumerating resources. It is a common pattern of level-zero API
/// to first get number of resources, and then enumerate them, using the same enumerating function for both tasks.
/// Calls func for each found resource handle.
template <typename DeviceType, typename ResourceType, typename LambdaType> requires
    std::is_same_v<return_type_of_t<LambdaType>, int> &&
    std::is_invocable_v<LambdaType, ResourceType>
inline int for_each_handle(DeviceType device_handle, LambdaType func)
{
    uint32_t count{};
    ZE_CHECK(get_ze_handles(device_handle, count, static_cast<ResourceType*>(nullptr)));
    std::vector<ResourceType> res_handles(count);
    ZE_CHECK(get_ze_handles(device_handle, count, res_handles.data()));
    for (auto& res_handle : res_handles) {
        CHECK_SANDSTONE(func(res_handle));
    }
    return EXIT_SUCCESS;
}

#endif // INC_ZE_ENUMERATION_H
