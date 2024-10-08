/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef GENERIC_EFFECTIVE_FREQ_HPP
#define GENERIC_EFFECTIVE_FREQ_HPP

#include <limits>

/*
 * The "do nothing" placeholder version
 */
class CPUTimeFreqStamp
{
public:
    void Snapshot(const int thread_num) { }
    static double EffectiveFrequencyMHz(const CPUTimeFreqStamp& before, CPUTimeFreqStamp& after) { return std::numeric_limits<double>::quiet_NaN(); }
};

#endif //GENERIC_EFFECTIVE_FREQ_HPP
