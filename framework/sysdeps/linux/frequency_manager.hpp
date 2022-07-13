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
#include <filesystem>
#include <sandstone.h>

#define DEFAULT_SYS_PATH        "/sys/devices/system/cpu/cpu"
#define CPUINFO_MAX_FREQ_F      "cpuinfo_max_freq"
#define CPUINFO_MIN_FREQ_F      "cpuinfo_min_freq"
#define SCALING_MAX_FREQ_P      "/cpufreq/scaling_max_freq"
#define KHZ                     100000

class FrequencyManager
{
public:
    FrequencyManager()
    {
        /* Discover supported and current frequencies */
        std::filesystem::path cpuinfo_max_freq_p = "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq";
        max_freq_supported = get_frequency_from_file(cpuinfo_max_freq_p);

        std::filesystem::path cpuinfo_min_freq_p = "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq";
        min_freq_supported = get_frequency_from_file(cpuinfo_min_freq_p);

        std::filesystem::path scaling_max_freq_p = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq";
        max_freq_initial = get_frequency_from_file(scaling_max_freq_p);
        max_freq_current = max_freq_initial;
    }

    void alternate_frequency(int cpu_number)
    {
        /* Based on max current frequency, set low value when current is high,
         * or set high if current is low. */
        int middle_freq = max_freq_supported;
        int deviation = random32() % 10;
        int alternating_freq;
        if (max_freq_current >= middle_freq)
            alternating_freq = max_freq_supported - deviation;
        else
            alternating_freq = min_freq_supported + deviation;

        set_fixed_frequency(cpu_number, alternating_freq);
    }

    void set_fixed_frequency(int cpu_number, int max_freq_i)
    {
        /* Set given frequency as long as it is supported */
        std::filesystem::path scaling_max_freq_p;

        // Assure required frequency is between min and max
        if (max_freq_i > max_freq_supported || max_freq_i < min_freq_supported)
            return;

        // Convert to KHz and string
        std::string max_freq_s = std::to_string(max_freq_i * KHZ);

        for (int i=0; i< cpu_number; i++)
        {
            // Concatenate path
            scaling_max_freq_p = DEFAULT_SYS_PATH;
            scaling_max_freq_p += std::to_string(i);
            scaling_max_freq_p += SCALING_MAX_FREQ_P;
            
            write_file(scaling_max_freq_p, max_freq_s);
        }
        // Update current freq
        max_freq_current = max_freq_i;
    }

    void restore_max_frequency(int cpu_number)
    {
        /* Restore frequency to its original value */
        set_fixed_frequency(cpu_number, max_freq_initial);
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

    std::string read_file(std::filesystem::path f_path)
    {
        /* Read first line of given file */
        std::string line;
        std::ifstream in_file(f_path.c_str());

        if (in_file.good())
            getline(in_file, line);

        in_file.close();
        return line;
    }

    void write_file(std::filesystem::path f_path, std::string line)
    {
        /* Write first line of given file */
        std::ofstream out_file(f_path, std::ofstream::out);
        if (out_file.good())
            out_file.write(line.c_str(), line.length());

        out_file.close();
    }

    int get_frequency_from_file(std::filesystem::path f_path)
    {
        /* Read and convert value from file */
        int value;
        std::string line = read_file(f_path);

        value = std::stod(line);
        value = value/KHZ;
        return value;
    }

    int max_freq_supported;
    int min_freq_supported;
    int max_freq_initial;
    int max_freq_current;
};
#endif
#endif //GENERIC_FREQUENCY_MANAGER_HPP
