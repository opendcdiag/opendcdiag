/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef FREQUENCY_MANAGER_HPP
#define FREQUENCY_MANAGER_HPP

#include <unordered_set>
#define BASE_CORE_FREQ_PATH    "/sys/devices/system/cpu/cpu"
#define BASE_UNCORE_FREQ_PATH  "/sys/devices/system/cpu/intel_uncore_frequency/package_0"
#define SCALING_GOVERNOR       "/cpufreq/scaling_governor"
#define SCALING_SETSPEED       "/cpufreq/scaling_setspeed"

class FrequencyManager
{
private:

#ifdef __linux__
    // core-frequency variables
    int max_core_frequency_supported = 0;
    int min_core_frequency_supported = 0;
    std::vector<std::string> per_cpu_initial_scaling_governor;
    std::vector<std::string> per_cpu_initial_scaling_setspeed;
    int current_set_frequency = 0;
    std::vector<int> core_frequency_levels;
    int core_frequency_level_idx = 0;
    int total_core_frequency_levels = 0;
    std::string pstate_driver_initial_status = ""; //if framework itself is enabling userspace save the initial state to restore after everything is done

    // uncore-frequency variables
    std::vector<std::pair<int, int>> initial_uncore_frequency;  // initial (min, max) un-core pair for each socket
    std::vector<std::vector<int>> uncore_frequency_levels;  // frequency levels for each socket
    uint16_t total_sockets = 0;
    int uncore_frequency_level_idx = 0;
    int total_uncore_frequency_levels = 0;

    std::string read_file(std::string_view file_path)
    {
        /* Read first line of given file */
        char line[100]; //100 characters should be more than enough
        FILE *file = fopen(file_path.data(), "r");

        if (file == nullptr) {
            fprintf(stderr, "%s: cannot read from file: %s: %m\n", program_invocation_name, file_path.data());
            exit(EX_IOERR);
        }
        fscanf(file, "%s", line);
        fclose(file);
        return std::string(line);
    }

    void write_file(std::string_view file_path, std::string_view line)
    {
        FILE *file = fopen(file_path.data(), "w");

        if (file == nullptr) {
            fprintf(stderr, "%s: cannot write \"%s\" to file \"%s\". Make sure the user is root: %m\n", program_invocation_name, line.data(), file_path.data());
            exit(EXIT_NOPERMISSION);
        }

        fprintf(file, "%s", line.data());
        fclose(file);
    }

    int get_frequency_from_file(std::string_view file_path)
    {
        /* Read frequency value from file */
        int frequency = 0;
        FILE *file = fopen(file_path.data(), "r");

        if (file == nullptr) {
            fprintf(stderr, "%s: cannot read from file: %s: %m\n", program_invocation_name, file_path.data());
            exit(EX_IOERR);
        }
        fscanf(file, "%d", &frequency);
        fclose(file);
        return frequency;
    }

    void populate_frequency_levels(auto &min_max_frequency, bool is_core, int total_frequency_levels)
    {
        std::vector<int> tmp_frequency_levels;
        tmp_frequency_levels.push_back(min_max_frequency.second);
        tmp_frequency_levels.push_back(min_max_frequency.first);
        
        std::vector<int> tmp = tmp_frequency_levels;

        while (tmp_frequency_levels.size() < total_frequency_levels)
        {
            std::sort(tmp.begin(), tmp.end(), std::greater<int>());
            for (int idx = 1; idx < tmp.size(); idx++)
                tmp_frequency_levels.push_back((tmp[idx] + tmp[idx - 1]) / 2);
            tmp = tmp_frequency_levels;
        }

        if (is_core)
            core_frequency_levels = std::move(tmp_frequency_levels);
        else
            uncore_frequency_levels.push_back(std::move(tmp_frequency_levels));
    }

    bool check_if_userspace_present()
    {
        const char *scaling_governor_path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors";
        char read_file[100];
        FILE *file = fopen(scaling_governor_path, "r");

        if (file == nullptr) {
            fprintf(stderr, "%s: cannot read from file: %s: %m\n", program_invocation_name, scaling_governor_path);
            exit(EX_IOERR);
        }

        while (fscanf(file, "%s", read_file) != EOF) {
            if (strcmp(read_file, "userspace") == 0) {
                fclose(file);
                return true;
            }
        }

        return false;
    }

    void check_uncore_frequency_support()
    {
        // check for 0th socket. 0th socket should always be present.
        const char *uncore_path = "/sys/devices/system/cpu/intel_uncore_frequency/package_00_die_00/initial_min_freq_khz";
        FILE *file = fopen(uncore_path, "r");

        if (file == nullptr) {
            fprintf(stderr, "%s: cannot read from file: %s. Please check if intel_uncore_frequency directory is present in the file path /sys/devices/system/cpu: %m\n", program_invocation_name, uncore_path);
            exit(EX_IOERR);
        }
    }

    void enable_disable_userspace(bool should_enable_userspace)
    {
        const char *pstate_driver_file = "/sys/devices/system/cpu/intel_pstate/status";
        if (should_enable_userspace) {
            // enable "userspace"
            pstate_driver_initial_status = read_file(pstate_driver_file);
            write_file(pstate_driver_file, "passive");
        } else {
            // disable "userspace"
            write_file(pstate_driver_file, pstate_driver_initial_status);
        }
    }

#endif

public:
    FrequencyManager() {}

    void initial_core_frequency_setup()
    {
#ifdef __linux__
        /* check if "userspace" frequency governor is available. Not all distributions have it*/
        if (!check_if_userspace_present())
            enable_disable_userspace(true); // if "userspace" not present enable it

        /* record supported max and min frequencies */
        std::string cpuinfo_max_freq_path{"/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"};
        max_core_frequency_supported = get_frequency_from_file(cpuinfo_max_freq_path);

        std::string cpuinfo_min_freq_path{"/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq"};
        min_core_frequency_supported = get_frequency_from_file(cpuinfo_min_freq_path);

        total_core_frequency_levels = std::min(16, (max_core_frequency_supported - min_core_frequency_supported) / 100000);

        // populate different frequencies for each test to run
        std::pair<int, int> min_max_frequency(min_core_frequency_supported, max_core_frequency_supported);
        populate_frequency_levels(min_max_frequency, true, total_core_frequency_levels);

        // save states
        for (int cpu = 0; cpu < num_cpus(); cpu++) {
            //save scaling governor for every cpu
            std::string scaling_governor_path = BASE_CORE_FREQ_PATH;
            scaling_governor_path += std::to_string(cpu_info[cpu].cpu_number);
            scaling_governor_path += SCALING_GOVERNOR;
            per_cpu_initial_scaling_governor.push_back(read_file(scaling_governor_path));

            //save frequency for every cpu
            std::string initial_scaling_setspeed_frequency_path = BASE_CORE_FREQ_PATH;
            initial_scaling_setspeed_frequency_path += std::to_string(cpu_info[cpu].cpu_number);
            initial_scaling_setspeed_frequency_path += SCALING_SETSPEED;
            per_cpu_initial_scaling_setspeed.push_back(read_file(initial_scaling_setspeed_frequency_path));

            //change scaling_governor to userspace in order to set the cores to different frequencies
            write_file(scaling_governor_path, "userspace");
        }
#endif 
    }

    void initial_uncore_frequency_setup()
    {
#ifdef __linux__
        check_uncore_frequency_support();

        auto calculate_total_sockets = [] () {
            std::unordered_set<int> found_socket_ids;
            uint16_t total_sockets = 0;

            for (size_t cpu = 0; cpu < num_cpus(); cpu++) {
                int socket_id = cpu_info[cpu].package_id;
                if (found_socket_ids.count(socket_id) == 0) {
                    total_sockets++;
                    found_socket_ids.insert(socket_id);
                }
            }

            return total_sockets;
        };

        total_sockets = calculate_total_sockets();

        for (size_t socket = 0; socket < total_sockets; socket++) {
            std::pair<int, int> max_min_frequency;
            std::string uncore_frequency_path = BASE_UNCORE_FREQ_PATH;
            uncore_frequency_path += std::to_string(socket);

            std::string min_freq_file = uncore_frequency_path + "_die_00/min_freq_khz";
            max_min_frequency.first = get_frequency_from_file(min_freq_file);

            std::string max_freq_file = uncore_frequency_path + "_die_00/max_freq_khz";
            max_min_frequency.second = get_frequency_from_file(max_freq_file);

            total_uncore_frequency_levels = std::min(8, (max_min_frequency.second - max_min_frequency.first) / 100000);

            populate_frequency_levels(max_min_frequency, false, total_uncore_frequency_levels);
            initial_uncore_frequency.push_back(std::move(max_min_frequency));
        }
#endif
    }

    void change_core_frequency()
    {
#ifdef __linux__
        current_set_frequency = core_frequency_levels[core_frequency_level_idx++ % total_core_frequency_levels];
        
        for (int cpu = 0; cpu < num_cpus(); cpu++) {
            std::string scaling_setspeed = BASE_CORE_FREQ_PATH;
            scaling_setspeed += std::to_string(cpu_info[cpu].cpu_number);
            scaling_setspeed += SCALING_SETSPEED;
            write_file(scaling_setspeed, std::to_string(current_set_frequency));
        }
#endif
    }

    void change_uncore_frequency()
    {
#ifdef __linux__
        for (size_t socket = 0; socket < total_sockets; socket++) {
            std::pair<int, int> max_min_frequency;
            std::string uncore_frequency_path = BASE_UNCORE_FREQ_PATH;
            uncore_frequency_path += std::to_string(socket);

            std::string min_freq_file = uncore_frequency_path + "_die_00/min_freq_khz";
            std::string frequency_to_write = std::to_string(uncore_frequency_levels[socket][uncore_frequency_level_idx++ % total_uncore_frequency_levels]);
            write_file(min_freq_file, frequency_to_write);

            std::string max_freq_file = uncore_frequency_path + "_die_00/max_freq_khz";
            write_file(max_freq_file, frequency_to_write);
        }
#endif
    }

    void restore_core_frequency_initial_state()
    {
#ifdef __linux__
        for (int cpu = 0; cpu < num_cpus(); cpu++) {
            //restore saved scaling governor for every cpu
            std::string scaling_governor_path = BASE_CORE_FREQ_PATH;
            scaling_governor_path += std::to_string(cpu_info[cpu].cpu_number);
            scaling_governor_path += SCALING_GOVERNOR;
            write_file(scaling_governor_path, per_cpu_initial_scaling_governor[cpu]);

            //restore saved frequency for every cpu
            std::string scaling_setspeed_path = BASE_CORE_FREQ_PATH;
            scaling_setspeed_path += std::to_string(cpu_info[cpu].cpu_number);
            scaling_setspeed_path += SCALING_SETSPEED;
            write_file(scaling_setspeed_path, per_cpu_initial_scaling_setspeed[cpu]);
        }

        // Check if "userspace" was enabled by framework. If it was, restore to it's initial state.
        if (pstate_driver_initial_status.size() > 0)
            enable_disable_userspace(false);
#endif
    }

    void restore_uncore_frequency_initial_state()
    {
#ifdef __linux__
        for (size_t socket = 0; socket < total_sockets; socket++) {
            std::pair<int, int> max_min_frequency;
            std::string uncore_frequency_path = BASE_UNCORE_FREQ_PATH;
            uncore_frequency_path += std::to_string(socket);

            std::string min_freq_file = uncore_frequency_path + "_die_00/min_freq_khz";
            std::string frequency_to_write = std::to_string(initial_uncore_frequency[socket].first);
            write_file(min_freq_file, frequency_to_write);

            frequency_to_write = std::to_string(initial_uncore_frequency[socket].second);
            std::string max_freq_file = uncore_frequency_path + "_die_00/max_freq_khz";
            write_file(max_freq_file, frequency_to_write);
        }
#endif
    }

    void reset_frequency_level_idx()
    {
#ifdef __linux__
        core_frequency_level_idx = 0;
        uncore_frequency_level_idx = 0;
#endif
    }

    static constexpr bool FrequencyManagerWorks =
#if defined(__linux__)
            true;
#else
            false;
#endif
};
#endif //FREQUENCY_MANAGER_HPP