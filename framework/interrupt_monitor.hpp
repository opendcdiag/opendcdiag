/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_INTERRUPTS_MONITOR_HPP
#define SANDSTONE_INTERRUPTS_MONITOR_HPP
#include <sandstone.h>
#include <stdint.h>
#include <numeric>      // for std::accummulate
#include <vector>

class InterruptMonitor
{
    static constexpr uint32_t MSR_SMI_COUNT = 0x34;
    enum InterruptType {
        MCE,
        Thermal,
    };
    static uint64_t get_total_interrupt_counts(InterruptType type)
    {
        std::vector<uint32_t> counts = get_interrupt_counts(type);
        return std::accumulate(counts.begin(), counts.end(), uint64_t(0));
    }

    // in sysdeps, if any
    static std::vector<uint32_t> get_interrupt_counts(InterruptType type);

public:
    std::vector<uint32_t> get_mce_interrupt_counts() const
    { return get_interrupt_counts(MCE); }

    uint64_t count_mce_events() const
    { return get_total_interrupt_counts(MCE); }

    uint64_t count_thermal_events() const
    { return get_total_interrupt_counts(Thermal); }

    uint64_t count_smi_events(int cpu) {
        uint64_t msi_count = 0;
        if (read_msr(cpu, MSR_SMI_COUNT, &msi_count))
            return msi_count;
        return 0;
    }

    static constexpr bool InterruptMonitorWorks =
#ifdef __linux__
            true;
#else
            false;
#endif
};

#ifndef __linux__
inline std::vector<uint32_t> InterruptMonitor::get_interrupt_counts(InterruptType)
{
    static_assert(!InterruptMonitorWorks);
    return {};
}
#endif

#endif
