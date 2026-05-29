/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "logging.h"
#include "gpu_device.h"
#include "ze_enumeration.h"

#include <algorithm>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <vector>

#if !SANDSTONE_NO_LOGGING
namespace {
auto calc_spacing()
{
    // Note: this assumes the topology won't change after the first time this
    // function is called.
    static const auto spacing = []() {
        struct { int gpu, cpu; } result {0, 0};
        auto max_gpu = std::max_element(
            device_info, device_info + thread_count(),
            [](const auto& g1, const auto& g2) { return g1.gpu_number < g2.gpu_number; }
        )->gpu_number;
        auto max_cpu = std::max_element(
            device_info, device_info + thread_count(),
            [](const auto& g1, const auto& g2) { return g1.cpu_number < g2.cpu_number; }
        )->cpu_number;

        do { max_gpu /= 10; result.gpu++; } while (max_gpu != 0);
        do { max_cpu /= 10; result.cpu++; } while (max_cpu != 0);

        return result;
    }();
    return spacing;
}
} // end unnamed namespace

namespace {
std::optional<std::filesystem::path> find_card_for_bdf(const gpu_info_t &info)
{
    namespace fs = std::filesystem;

    static const fs::path drm_sysfs_dir = "/sys/class/drm";
    if (!fs::exists(drm_sysfs_dir) || !fs::is_directory(drm_sysfs_dir)) {
        return std::nullopt;
    }

    const std::string target_slot = std::format("{:04x}:{:02x}:{:02x}.{:01x}",
                                                info.bdf.domain, info.bdf.bus,
                                                info.bdf.device, info.bdf.function);

    for (const auto &entry : fs::directory_iterator(drm_sysfs_dir)) {
        if (!entry.is_directory()) {
            continue;
        }

        const std::string name = entry.path().filename().string();
        if (!name.starts_with("card") || name.find('-') != std::string::npos) {
            continue;
        }

        const fs::path uevent = entry.path() / "device" / "uevent";
        std::ifstream in(uevent);
        if (!in) {
            continue;
        }

        std::string line;
        while (std::getline(in, line)) {
            if (line == "PCI_SLOT_NAME=" + target_slot) {
                return entry.path();
            }
        }
    }

    return std::nullopt;
}

void append_xe_devcoredump(std::string &out, const gpu_info_t &info)
{
    auto card = find_card_for_bdf(info);
    if (!card) {
        return;
    }

    auto devcoredump_data = *card / "device" / "devcoredump" / "data";
    std::error_code ec;
    auto mtime = std::filesystem::last_write_time(devcoredump_data, ec);
    if (ec) {
        return;
    }
    out += "  xe_devcoredump:\n";
    out += std::format("    path: {}\n", devcoredump_data.string());
    out += std::format("    mtime: {:%FT%T}Z\n", mtime);
}

void append_device_state(std::string &out, zes_device_handle_t zes_handle)
{
    zes_device_state_t state = { .stype = ZES_STRUCTURE_TYPE_DEVICE_STATE };
    if (zesDeviceGetState(zes_handle, &state) != ZE_RESULT_SUCCESS) {
        return;
    }
    out += "  dev_state:\n";
    out += std::format("    reset: 0x{:x}\n    repaired: {}\n",
                       state.reset, static_cast<uint32_t>(state.repaired));
}

void append_processes_state(std::string &out, zes_device_handle_t zes_handle)
{
    uint32_t count = 0;
    if (zesDeviceProcessesGetState(zes_handle, &count, nullptr) != ZE_RESULT_SUCCESS) {
        return;
    }

    std::vector<zes_process_state_t> procs(count);
    for (auto &proc : procs) {
        proc.stype = ZES_STRUCTURE_TYPE_PROCESS_STATE;
        proc.pNext = nullptr;
    }

    if (count > 0) {
        ze_result_t res = zesDeviceProcessesGetState(zes_handle, &count, procs.data());
        if (res != ZE_RESULT_SUCCESS) {
            return;
        }
    }
    if (count == 0) {
        out += "  procs: []\n";
        return;
    }

    out += "  procs:\n";
    for (uint32_t i = 0; i < count && i < procs.size(); ++i) {
        const auto &proc = procs[i];
        out += std::format("  - pid: {}\n", proc.processId);
        out += std::format("    resources: {{ mem: {}, shared: {}, engines: 0x{:x} }}\n",
                            proc.memSize, proc.sharedSize, proc.engines);
    }
}

void append_pci_state(std::string &out, zes_device_handle_t zes_handle)
{
    zes_pci_state_t state = { .stype = ZES_STRUCTURE_TYPE_PCI_STATE };
    if (zesDevicePciGetState(zes_handle, &state) != ZE_RESULT_SUCCESS) {
        return;
    }

    out += std::format("  pci: {{ status: {}, qual: 0x{:x}, stab: 0x{:x}, speed: {{ gen: {}, width: {}, bw: {} }} }}\n",
                       static_cast<uint32_t>(state.status), state.qualityIssues,
                       state.stabilityIssues, state.speed.gen, state.speed.width,
                       state.speed.maxBandwidth);
}

void append_ecc_state(std::string &out, zes_device_handle_t zes_handle)
{
    zes_device_ecc_properties_t state = { .stype = ZES_STRUCTURE_TYPE_DEVICE_ECC_PROPERTIES };
    if (zesDeviceGetEccState(zes_handle, &state) != ZE_RESULT_SUCCESS) {
        return;
    }

    out += std::format("  ecc: {{ current: {}, pending: {}, action: {} }}\n",
                       static_cast<uint32_t>(state.currentState),
                       static_cast<uint32_t>(state.pendingState),
                       static_cast<uint32_t>(state.pendingAction));
}

void append_memory_state(std::string &out, zes_device_handle_t zes_handle)
{
    out += "  mem:";
    std::string meminfo = "";
    for_each_handle<zes_mem_handle_t>(zes_handle, [&](zes_mem_handle_t res_handle) {
        zes_mem_properties_t props = { .stype = ZES_STRUCTURE_TYPE_MEM_PROPERTIES };
        if (zesMemoryGetProperties(res_handle, &props) != ZE_RESULT_SUCCESS) {
            return EXIT_SUCCESS;
        }

        zes_mem_state_t state = { .stype = ZES_STRUCTURE_TYPE_MEM_STATE };
        if (zesMemoryGetState(res_handle, &state) != ZE_RESULT_SUCCESS) {
            return EXIT_SUCCESS;
        }

        meminfo += std::format("  - id: {{ type: {}, loc: {}, subdev: {} }}\n",
                           static_cast<uint32_t>(props.type), static_cast<uint32_t>(props.location),
                           props.onSubdevice ? static_cast<int32_t>(props.subdeviceId) : -1);
        meminfo += std::format("    health: {}\n", static_cast<uint32_t>(state.health));
        meminfo += std::format("    free: {}\n", state.free);
        meminfo += std::format("    size: {}\n",  state.size);
        return EXIT_SUCCESS;
    });
    if (meminfo.size()) {
        out += "\n" + meminfo;
    } else {
        out  += " []\n";
    }
}

void append_fabric_state(std::string &out, zes_device_handle_t zes_handle)
{
    out += "  fabrics:";
    std::string fabric_info = "";
    for_each_handle<zes_fabric_port_handle_t>(zes_handle, [&](zes_fabric_port_handle_t res_handle) {
        zes_fabric_port_properties_t props = { .stype = ZES_STRUCTURE_TYPE_FABRIC_PORT_PROPERTIES };
        if (zesFabricPortGetProperties(res_handle, &props) != ZE_RESULT_SUCCESS) {
            return EXIT_SUCCESS;
        }

        zes_fabric_port_state_t state = { .stype = ZES_STRUCTURE_TYPE_FABRIC_PORT_STATE };
        if (zesFabricPortGetState(res_handle, &state) != ZE_RESULT_SUCCESS) {
            return EXIT_SUCCESS;
        }

        fabric_info += std::format("  - id: {{ fabric_id: {}, attach_id: {}, port_id: {} }}\n",
                           props.portId.fabricId, props.portId.attachId, props.portId.portNumber);
        fabric_info += std::format("    info: {{ status: {}, qual: 0x{:x}, fail: 0x{:x}, rx: {}x{}, tx: {}x{} }}\n",
                           static_cast<uint32_t>(state.status), state.qualityIssues, state.failureReasons,
                           state.rxSpeed.bitRate, state.rxSpeed.width,
                           state.txSpeed.bitRate, state.txSpeed.width);
        return EXIT_SUCCESS;
    });
    if (fabric_info.size()) {
        out += "\n" + fabric_info;
    } else {
        out += " []\n";
    }
}

void append_psu_state(std::string &out, zes_device_handle_t zes_handle)
{
    uint32_t count = 0;
    if (zesDeviceEnumPsus(zes_handle, &count, nullptr) != ZE_RESULT_SUCCESS || count == 0) {
        out += "  psus: []\n";
        return;
    }

    std::vector<zes_psu_handle_t> psu_handles(count);
    if (zesDeviceEnumPsus(zes_handle, &count, psu_handles.data()) != ZE_RESULT_SUCCESS) {
        return;
    }

    out += "  psus:\n";
    for (auto psu_handle : psu_handles) {
        zes_psu_properties_t props = { .stype = ZES_STRUCTURE_TYPE_PSU_PROPERTIES };
        if (zesPsuGetProperties(psu_handle, &props) != ZE_RESULT_SUCCESS) {
            continue;
        }

        zes_psu_state_t state = { .stype = ZES_STRUCTURE_TYPE_PSU_STATE };
        if (zesPsuGetState(psu_handle, &state) != ZE_RESULT_SUCCESS) {
            continue;
        }

        out += std::format("  - subdev: {}\n",
                           props.onSubdevice ? static_cast<int32_t>(props.subdeviceId) : -1);
        out += std::format("    values: {{ volt: {}, fan_failed: {}, temp: {}, current: {}mA }}\n",
                           static_cast<uint32_t>(state.voltStatus), state.fanFailed,
                           state.temperature, state.current);
    }
}

void append_fan_state(std::string &out, zes_device_handle_t zes_handle)
{
    uint32_t count = 0;
    if (zesDeviceEnumFans(zes_handle, &count, nullptr) != ZE_RESULT_SUCCESS || count == 0) {
        out += "  fans: []\n";
        return;
    }

    std::vector<zes_fan_handle_t> fan_handles(count);
    if (zesDeviceEnumFans(zes_handle, &count, fan_handles.data()) != ZE_RESULT_SUCCESS) {
        return;
    }
    out += "  fans:\n";
    for (auto fan_handle : fan_handles) {
        zes_fan_properties_t props = { .stype = ZES_STRUCTURE_TYPE_FAN_PROPERTIES };
        if (zesFanGetProperties(fan_handle, &props) != ZE_RESULT_SUCCESS) {
            continue;
        }

        int32_t rpm = -1;
        int32_t pct = -1;
        ze_result_t rpm_res = zesFanGetState(fan_handle, ZES_FAN_SPEED_UNITS_RPM, &rpm);
        ze_result_t pct_res = zesFanGetState(fan_handle, ZES_FAN_SPEED_UNITS_PERCENT, &pct);
        if (rpm_res != ZE_RESULT_SUCCESS && pct_res != ZE_RESULT_SUCCESS) {
            continue;
        }

        out += std::format("  - subdev: {}\n", props.onSubdevice ? static_cast<int32_t>(props.subdeviceId) : -1);
        out += std::format("    values: {{ rpm: {}, pct: {}, max_rpm: {} }}\n", rpm, pct, props.maxRPM);
    }
}

void append_engine_state(std::string &out, zes_device_handle_t zes_handle)
{
    out += "  engines:";
    std::string engines = "";
    for_each_handle<zes_engine_handle_t>(zes_handle, [&](zes_engine_handle_t res_handle) {
        zes_engine_properties_t props = { .stype = ZES_STRUCTURE_TYPE_ENGINE_PROPERTIES };
        if (zesEngineGetProperties(res_handle, &props) != ZE_RESULT_SUCCESS) {
            return EXIT_SUCCESS;
        }

        zes_engine_stats_t stats{};
        if (zesEngineGetActivity(res_handle, &stats) != ZE_RESULT_SUCCESS) {
            return EXIT_SUCCESS;
        }

        engines += std::format("  - engine: {}\n", to_string(props.type));
        engines += std::format("    active: {}\n", stats.activeTime);
        engines += std::format("    ts: {}\n", stats.timestamp);
        return EXIT_SUCCESS;
    });
    if (engines.size()) {
        out += "\n" + engines;
    } else {
        out += " []\n";
    }
}

void append_frequency_state(std::string &out, zes_device_handle_t zes_handle)
{
    out += "  freqs:";
    std::string frequencies = "";
    for_each_handle<zes_freq_handle_t>(zes_handle, [&](zes_freq_handle_t res_handle) {
        zes_freq_properties_t props = { .stype = ZES_STRUCTURE_TYPE_FREQ_PROPERTIES };
        if (zesFrequencyGetProperties(res_handle, &props) != ZE_RESULT_SUCCESS) {
            return EXIT_SUCCESS;
        }

        zes_freq_state_t state = { .stype = ZES_STRUCTURE_TYPE_FREQ_STATE };
        if (zesFrequencyGetState(res_handle, &state) != ZE_RESULT_SUCCESS) {
            return EXIT_SUCCESS;
        }

        frequencies += std::format("  - domain: {}\n", static_cast<uint32_t>(props.type));
        frequencies += std::format("    values: {{ actual: {:.1f}, request: {:.1f}, tdp: {:.1f}, throttle: 0x{:x} }}\n",
                            state.actual, state.request, state.tdp, state.throttleReasons);
        return EXIT_SUCCESS;
    });
    if (frequencies.size()) {
        out += "\n" + frequencies;
    } else {
        out += " []\n";
    }
}

void append_temperature_state(std::string &out, zes_device_handle_t zes_handle)
{
    out += "  temps:";
    std::string temps = "";
    for_each_handle<zes_temp_handle_t>(zes_handle, [&](zes_temp_handle_t res_handle) {
        zes_temp_properties_t props = { .stype = ZES_STRUCTURE_TYPE_TEMP_PROPERTIES };
        if (zesTemperatureGetProperties(res_handle, &props) != ZE_RESULT_SUCCESS) {
            return EXIT_SUCCESS;
        }

        double temp = 0;
        if (zesTemperatureGetState(res_handle, &temp) != ZE_RESULT_SUCCESS) {
            return EXIT_SUCCESS;
        }

        temps += std::format("  - sensor: {}\n    value: {:.1f}C\n", static_cast<uint32_t>(props.type), temp);
        return EXIT_SUCCESS;
    });
    if (temps.size()) {
        out += "\n" + temps;
    } else {
        out += " []\n";
    }
}

void append_ras_state(std::string &out, zes_device_handle_t zes_handle)
{
    out += "  ras:";
    std::string ras = "";
    for_each_handle<zes_ras_handle_t>(zes_handle, [&](zes_ras_handle_t res_handle) {
        zes_ras_properties_t props = { .stype = ZES_STRUCTURE_TYPE_RAS_PROPERTIES };
        if (zesRasGetProperties(res_handle, &props) != ZE_RESULT_SUCCESS) {
            return EXIT_SUCCESS;
        }

        zes_ras_state_t state = { .stype = ZES_STRUCTURE_TYPE_RAS_STATE };
        if (zesRasGetState(res_handle, false, &state) != ZE_RESULT_SUCCESS) {
            return EXIT_SUCCESS;
        }

        uint64_t total = 0;
        for (uint64_t count : state.category) {
            total += count;
        }
        if (total == 0) {
            return EXIT_SUCCESS;
        }

        ras += std::format("  - counter: {}\n    value: {}\n", to_string(props.type), total);
        return EXIT_SUCCESS;
    });
    if (ras.size()) {
        out += "\n" + ras;
    } else {
        out += " []\n";
    }
}
}

void dump_device_state(std::string &out, int thread)
{
    if (thread < 0) {
        return; // no particular thread, no point in printing everything
    }

    const gpu_info_t& target_info = device_info[thread];
    bool dumped = false;

    auto is_target_gpu = [](const gpu_info_t &info, const MultiSliceGpu &indices) {
        return info.gpu_number == indices.gpu_number
                && info.device_index == indices.device_index
                && info.subdevice_index == indices.subdevice_index;
    };

    for_each_zes_device_within_topo([&](zes_device_handle_t zes_handle, ze_driver_handle_t, const MultiSliceGpu &indices) {
        if (!is_target_gpu(target_info, indices)) {
            return EXIT_SUCCESS;
        }

        out += "gpu_runtime_state:\n";

        // Try to ask API for the state
        append_device_state(out, zes_handle);
        append_processes_state(out, zes_handle);
        append_pci_state(out, zes_handle);
        append_ecc_state(out, zes_handle);
        append_memory_state(out, zes_handle);
        append_fabric_state(out, zes_handle);
        append_psu_state(out, zes_handle);
        append_fan_state(out, zes_handle);
        append_engine_state(out, zes_handle);
        append_frequency_state(out, zes_handle);
        append_temperature_state(out, zes_handle);
        append_ras_state(out, zes_handle);

        // Dump XE devcoredump location if exists
        append_xe_devcoredump(out, target_info);

        dumped = true;
        return EXIT_SUCCESS;
    });

    if (!dumped) {
        out += "gpu_runtime_state: unavailable\n";
    }
}

std::string AbstractLogger::thread_id_header_for_device(int thread, LogLevelVerbosity verbosity)
{
    const gpu_info_t *info = device_info + thread;
    std::string line;
    if (info->subdevice_index != -1) {
        line = std::format("{{ gpu_index: {}/{}, gpu_number: {:{}}, ", info->device_index, info->subdevice_index, info->gpu_number, calc_spacing().gpu);
    } else {
        assert(info->device_index == info->gpu_number);
        line = std::format("{{ gpu_number: {:{}}, ", info->gpu_number, calc_spacing().gpu);
    }
    line += std::format("logical_cpu: {:{}}, ", info->cpu_number, calc_spacing().cpu);
    const auto& uuid = info->device_properties.uuid.id;
    line += std::format(
        "uuid: {:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}, ",
        uuid[15], uuid[14], uuid[13], uuid[12], uuid[11], uuid[10], uuid[9], uuid[8],
        uuid[7],  uuid[6],  uuid[5],  uuid[4],  uuid[3],  uuid[2],  uuid[1], uuid[0]
    );
    line += std::format("pci_address: {:04x}:{:02x}:{:02x}.{:01x}, ",
        info->bdf.domain, info->bdf.bus, info->bdf.device, info->bdf.function
    );
    line += std::format("arch: {}.{}.{}, ", (uint32_t)info->gpu_arch.gmd_arch, (uint32_t)info->gpu_arch.gmd_release, (uint32_t)info->gpu_arch.revision_id);
    line += std::format("name: \"{}\"", // no comma
        info->device_properties.name
    );
    line += " }";
    return line;
}

void AbstractLogger::print_thread_header_for_device(int fd, PerThreadData::Test *thr)
{

}

void AbstractLogger::print_fixed_for_device()
{

}

#else
void dump_device_state(std::string&, int)
{}
#endif // !SANDSTONE_NO_LOGGING
