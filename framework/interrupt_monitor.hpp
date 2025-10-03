/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_INTERRUPTS_MONITOR_HPP
#define SANDSTONE_INTERRUPTS_MONITOR_HPP
#include <sandstone.h>

#include <cstdint>
#include <numeric> // for std::accummulate
#include <optional>
#include <vector>

class InterruptMonitor
{
    static constexpr uint32_t MSR_SMI_COUNT = 0x34;
    enum InterruptType {
        MCE,
        Thermal,
    };

    static uint64_t get_total_interrupt_counts(InterruptType type) {
        std::vector<uint32_t> counts = get_interrupt_counts(type);
        return std::accumulate(counts.begin(), counts.end(), uint64_t(0));
    }

    // in sysdeps, if any
    static std::vector<uint32_t> get_interrupt_counts(InterruptType type);

public:
    static std::vector<uint32_t> get_mce_interrupt_counts() {
        return get_interrupt_counts(MCE);
    }

    static uint64_t count_mce_events() {
        return get_total_interrupt_counts(MCE);
    }

    static bool observed_mce_events();

    static uint64_t count_thermal_events() {
        return get_total_interrupt_counts(Thermal);
    }

    static std::optional<uint64_t> count_smi_events(int cpu)
    {
        uint64_t msi_count = 0;
        if (read_msr(cpu, MSR_SMI_COUNT, &msi_count))
            return msi_count;
        return std::nullopt;
    }

    static constexpr bool InterruptMonitorWorks =
#if defined(__linux__) && defined(__x86_64__)
            true;
#else
            false;
#endif
};

#if !defined(__linux__) || !defined(__x86_64__)
inline std::vector<uint32_t> InterruptMonitor::get_interrupt_counts(InterruptType)
{
    static_assert(!InterruptMonitorWorks);
    return {};
}

inline bool InterruptMonitor::observed_mce_events()
{
    return false;
}
#endif

#endif
