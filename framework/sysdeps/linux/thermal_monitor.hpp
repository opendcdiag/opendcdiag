/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_LINUX_THERMAL_MONITOR_HPP
#define SANDSTONE_LINUX_THERMAL_MONITOR_HPP

#include <glob.h>
#include <fstream>


#define DEFAULT_SYS_THERMAL_PATH "/sys/devices/virtual/thermal/"
#define INVALID_TEMPERATURE  -999999

class ThermalMonitor {

    std::vector<std::string> socket_temperature_files;
public:
    explicit ThermalMonitor(const std::string &thermal_path_sys_root = DEFAULT_SYS_THERMAL_PATH) {
        discover_socket_temperature_files(thermal_path_sys_root);
    }


    // Simple static singleton pattern because we only ever want one of these
    // which we use in the static method below which is the primary API
    static ThermalMonitor * get_singleton(){
        static ThermalMonitor  _monitor;
        return &_monitor;
    }


    static std::vector<int> get_all_socket_temperatures(){
        return get_singleton()->get_socket_temperatures();
    }


    void discover_socket_temperature_files(const std::string &thermal_path_sys_root) {
        auto thermal_zone_dirs = glob_directories(thermal_path_sys_root + "/thermal_zone*");

        for (const auto &directory : thermal_zone_dirs) {
            if (is_x86_package_zone(directory))
                add_socket_temperature_file(directory);
        }
    }


    void add_socket_temperature_file(const std::string &directory_path) {
        int socket_num = get_last_int_from(directory_path);
        socket_temperature_files.resize( std::max(socket_num + 1, (int) socket_temperature_files.size()) );

        socket_temperature_files[socket_num] = directory_path + "/temp";
    }


    static bool is_x86_package_zone(const std::string & thermal_zone_dir) {
        std::string zone_type = first_line_of(thermal_zone_dir + "/type");
        return zone_type == "x86_pkg_temp";
    }

    // Returns a vector of the socket temperatures indexed by the physical socket
    // index.  Since the sockets do not have to be contiguously indexed and since
    // other devices can be interspersed, all the non-socket related temperatures
    // are specified as INVALID_TEMPERATURE
    // For example: If only socket 0 and 3 exist and 1 and 2 are disabled or are other devices
    //              then I'd expect this to return something like: {50000, -1, -1, 45000}
    //              which indicates that P0 is 50 degrees and P3 is 45 degrees
    //
    std::vector<int> get_socket_temperatures() {
        std::vector<int> temps;
        for (auto &file_path : socket_temperature_files) {
            if (file_path.empty())
                temps.push_back(INVALID_TEMPERATURE);
            else
                temps.push_back(read_value_from_file(file_path));
        }
        return temps;
    }


    static int read_value_from_file(const std::string &file) {
        return get_last_int_from(first_line_of(file));
    }


    static int get_last_int_from(const std::string &line) {
        auto last_idx = line.find_last_not_of("0123456789");
        std::string number_string = line.substr(last_idx + 1);

        if (number_string.empty()) {
            return INVALID_TEMPERATURE;
        } else {
            return (int) strtol(number_string.c_str(), nullptr, 10);
        }
    }


    static std::string first_line_of(const std::string &file_path) {
        std::string line;
        std::ifstream infile(file_path.c_str());

        if (infile.good())
            getline(infile, line);

        infile.close();

        return line;

    }


    static std::vector<std::string> glob_directories(const std::string &glob_path) {
        std::vector<std::string> return_paths;
        glob_t glob_results;

        auto error = glob(glob_path.c_str(), GLOB_ONLYDIR, nullptr, &glob_results);

        if (!error) {
            for (auto i = 0; i < glob_results.gl_pathc; ++i) {
                return_paths.emplace_back(glob_results.gl_pathv[i]);
            }
        }

        globfree(&glob_results);
        return return_paths;
    }

};

#endif // SANDSTONE_LINUX_THERMAL_MONITOR_HPP
