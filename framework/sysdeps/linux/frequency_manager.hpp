/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef GENERIC_FREQUENCY_MANAGER_HPP
#define GENERIC_FREQUENCY_MANAGER_HPP

#ifndef __x86_64__
#  include "../generic/frequency_manager.hpp"
#else

#include <limits>
#include <fstream>

#define DEFAULT_SYS_PATH "/sys/devices/system/cpu/"

class FrequencyManager
{
public:
    FrequencyManager()
    {
        /* Discover supported and current frequencies */
    }

    void alternate_frequency()
    {
        /* Based on max current frequency, set low value when current is high,
         * or set high if current is low. */
    }

    void set_fixed_frequency()
    {
        /* Set given frequency as long as it is supported */
    }

    void restore_max_frequency()
    {
        /* Restore frequency to its original value */
    }

    int get_min_supported_freq()
    {
        return min_freq_supported;
    }

    int get_max_supported_freq()
    {
        return max_freq_supported;
    }

private:

    int max_freq_supported;
    int min_freq_supported;
    int max_freq_initial;
    int max_freq_current;
};
#endif
#endif //GENERIC_FREQUENCY_MANAGER_HPP
