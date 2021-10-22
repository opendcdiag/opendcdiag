/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gtest/gtest.h"
#include <algorithm>
#include "sysdeps/linux/thermal_monitor.hpp"

namespace LinuxTesting {
    class LinuxThermalFixture : public ::testing::Test {
    public:
        std::string fake_thermal_root_dir;

        void setup_fake_thermal_files(std::string dirname, std::string type, std::string temperature) {
            std::string base_dir = fake_thermal_root_dir + dirname;
            std::string type_file = base_dir + "/type";
            std::string temp_file = base_dir + "/temp";

            system(("mkdir -p " + base_dir).c_str());
            system(("echo " + type + " > " + type_file).c_str());
            system(("echo " + temperature + " > " + temp_file).c_str());

        }

        void SetUp() override {
            fake_thermal_root_dir = "/tmp/sandstone_unittest_temps_" + std::to_string(getpid()) + "/";
            system(("rm -rf " + fake_thermal_root_dir).c_str());  // Clean out old results if present
        }

        void TearDown() override {
            system(("rm -rf " + fake_thermal_root_dir).c_str());
        }
    };


    TEST_F(LinuxThermalFixture, testPullingNumberOffString) {
        ASSERT_EQ(ThermalMonitor::get_last_int_from("abc123"), 123);
        ASSERT_EQ(ThermalMonitor::get_last_int_from("abc"), INVALID_TEMPERATURE);
    }


    TEST_F(LinuxThermalFixture, CurrentMachine_TestUsingSingletomTemperaturesOnCurrentMachine) {
        ThermalMonitor therm{};
        auto temps = ThermalMonitor::get_all_socket_temperatures();
        EXPECT_GE(temps.size(), 1);

        int max_temp = *max_element(temps.begin(), temps.end());
        ASSERT_GT(max_temp, 10000);  // 10 degrees C
        ASSERT_LE(max_temp, 199000); // 199 degrees C
    }


    TEST_F(LinuxThermalFixture, CanWeAccessSimpleThermalZone0) {
        setup_fake_thermal_files("thermal_zone0", "x86_pkg_temp", "2000");

        ThermalMonitor therm{fake_thermal_root_dir};
        ASSERT_EQ(therm.get_socket_temperatures(), std::vector({2000}));
    }


    TEST_F(LinuxThermalFixture, GivenANonContiguousZone_ThenWePadTheVectorWithInvalidValues) {
        setup_fake_thermal_files("thermal_zone2", "x86_pkg_temp", "2002");

        ThermalMonitor therm(fake_thermal_root_dir);
        ASSERT_EQ(therm.get_socket_temperatures(), std::vector({INVALID_TEMPERATURE, INVALID_TEMPERATURE, 2002}));
    }


    TEST_F(LinuxThermalFixture, GivenWeHaveANonPackageThermalZone_ThenWeSkipIt) {
        setup_fake_thermal_files("thermal_zone1", "x86_pkg_temp", "2001");
        setup_fake_thermal_files("thermal_zone2", "not_x86_pkg_temp", "2002");
        setup_fake_thermal_files("thermal_zone3", "x86_pkg_temp", "2003");

        ThermalMonitor therm(fake_thermal_root_dir);
        ASSERT_EQ(therm.get_socket_temperatures(), std::vector({INVALID_TEMPERATURE, 2001, INVALID_TEMPERATURE, 2003}));
    }


    TEST_F(LinuxThermalFixture, GivenTwoDigitSocketId_WeGetItToTheTempInTheRightEntry) {
        setup_fake_thermal_files("thermal_zone1", "x86_pkg_temp", "2001");
        setup_fake_thermal_files("thermal_zone10", "x86_pkg_temp", "2010");

        ThermalMonitor therm(fake_thermal_root_dir);
        auto temps = therm.get_socket_temperatures();
        ASSERT_EQ(temps[0], INVALID_TEMPERATURE);
        ASSERT_EQ(temps[1], 2001);
        ASSERT_EQ(temps[10], 2010);
    }


    TEST_F(LinuxThermalFixture, GivenAThermalZoneFileThatDoesNotEndInANumber_ThenWeIgnoreIt) {
        setup_fake_thermal_files("thermal_zone0", "x86_pkg_temp", "2001");
        setup_fake_thermal_files("thermal_zonefoo", "not_x86_pkg_temp", "2010");

        ThermalMonitor therm(fake_thermal_root_dir);
        ASSERT_EQ(therm.get_socket_temperatures(), std::vector({2001}));
    }


    TEST_F(LinuxThermalFixture, GivenNoThermalFilesExist_ThenWeGetAnEmptyList) {
        ThermalMonitor therm(fake_thermal_root_dir);
        ASSERT_EQ(therm.get_socket_temperatures(), std::vector<int>());
    }

}


// Windows build currently has a null object pattern stub in place
// We will populate this when we implement it
namespace WindowsBuild {

#include "sysdeps/windows/thermal_monitor.hpp"

    class WindowsThermalFixture : public ::testing::Test {
    };

    // Calls to get_all_socket_temperatures is not yet implemented for Win32
    // So we return an empty list
    TEST_F(WindowsThermalFixture, AnyCallToGetAllSocketTemperatures_WillReturn_Empty) {
        std::vector<int> temps = ThermalMonitor::get_all_socket_temperatures();
        ASSERT_EQ(temps, std::vector<int>{});
    }
}
