/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_GENERIC_THERMAL_MONITOR_HPP
#define SANDSTONE_GENERIC_THERMAL_MONITOR_HPP

#define INVALID_TEMPERATURE  -999999

// Placeholder NULL pattern here
class ThermalMonitor {
public:
    static std::vector<int> get_all_socket_temperatures(){
        std::vector<int> temps = {};
        return temps;
    }

};

#endif // SANDSTONE_GENERIC_THERMAL_MONITOR_HPP
