/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef GENERIC_FREQUENCY_MANAGER_HPP
#define GENERIC_FREQUENCY_MANAGER_HPP

#include <limits>

/*
 * The "do nothing" placeholder version
 */
class FrequencyManager
{
public:
    FrequencyManager() { }
    void alternate_frequency() { }
    void set_fixed_frequency(int cpu_number, int max_freq_i) { }
    void restore_max_frequency(int cpu_number) { }
    int get_min_supported_freq() { }
    int get_max_supported_freq() { }
};

#endif //GENERIC_FREQUENCY_MANAGER_HPP
