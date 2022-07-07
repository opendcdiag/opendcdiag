/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LINUX_EFFECTIVE_FREQ_HPP
#define LINUX_EFFECTIVE_FREQ_HPP

#ifndef __x86_64__
#  include "../generic/effective_cpu_freq.hpp"
#else

#include <limits>
#include <x86intrin.h>
#include "sandstone_p.h"

class CPUTimeFreqStamp
{
public:
    static constexpr uint32_t APERF_MSR{ 0xe8 };
    static constexpr uint32_t MPERF_MSR{ 0xe7 };

    void Snapshot(const int thread_num)
    {
        cpu_number = cpu_info[thread_num].cpu_number;

        IGNORE_RETVAL(get_monotonic_time_now(&ts));

        tsc = _rdtscp(&tsc_aux);

        if (!read_msr(cpu_number, APERF_MSR, &aperf))
            aperf = 0;

        if (!read_msr(cpu_number, MPERF_MSR, &mperf))
            mperf = 0;
    }

    static double EffectiveFrequencyMHz(const CPUTimeFreqStamp& before, const CPUTimeFreqStamp& after)
    {
        assert(after.cpu_number == before.cpu_number);

        // Case of bogus data when, e.g., OpenDCDiag is run unprivileged
        if (before.mperf >= after.mperf || before.aperf >= after.aperf || before.tsc >= after.tsc)
            return std::numeric_limits<double>::quiet_NaN();

        const double secs = (after.ts.tv_sec - before.ts.tv_sec) + (after.ts.tv_nsec - before.ts.tv_nsec) / 1000000000.0;
        const double tsc_freq = (after.tsc - before.tsc) / secs;
        const double perf_ratio = 1.0 * (after.aperf - before.aperf) / (after.mperf - before.mperf);

        return tsc_freq * perf_ratio / 1000000.0;
    }

private:
    int cpu_number;
    struct timespec ts;
    uint64_t tsc;
    uint32_t tsc_aux;
    uint64_t aperf, mperf;
};

#endif // __x86_64__

#endif // LINUX_EFFECTIVE_FREQ_HPP
