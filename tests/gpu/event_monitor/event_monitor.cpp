/**
 * @file
 *
 * @copyright
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 *
 * @test @b event_monitor
 * @parblock
 * Special test spawning an event listening thread in its preinit.
 * Events are listened for each 150ms, with 10ms timeout.
 * In postcleanup thread is stopped and data collected, per device.
 * In case of no events observed during the entire program execution,
 * nothing is printed.
 * @endparblock
 */

#include "sandstone_p.h"

#include "multi_slice_gpu.h"
#include "ze_enumeration.h"
#include "ze_utils.h"

#include <level_zero/zes_api.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cinttypes>
#include <memory>
#include <thread>
#include <vector>

namespace {
struct test_data
{
    struct
    {
        ze_driver_handle_t driver = nullptr;
        std::vector<zes_device_handle_t> devices;
        std::vector<uint64_t> n_events; // cumulative count of how many times API reported events on device
        std::vector<zes_event_type_flags_t> events; // bitmask of all events observed (ORed), per device
        std::atomic<bool> thread_should_run = true;
    } thread_data; // data used in thread
    std::thread thread;
};

int listener_preinit(struct test* test)
{
    // the thread will be spawned by the main process. Forking from a multi-threaded process in unsafe.
    if (sApp->current_fork_mode() == SandstoneApplication::ForkMode::fork_each_test) {
        log_skip(RuntimeSkipCategory, "event_monitor requires --fork-mode=exec/no");
        return EXIT_SKIP;
    }

    // events that we want to track
    static constexpr zes_event_type_flags_t event_types =
        ZES_EVENT_TYPE_FLAG_DEVICE_DETACH | ZES_EVENT_TYPE_FLAG_FREQ_THROTTLED |
        ZES_EVENT_TYPE_FLAG_TEMP_CRITICAL | ZES_EVENT_TYPE_FLAG_MEM_HEALTH |
        ZES_EVENT_TYPE_FLAG_FABRIC_PORT_HEALTH | ZES_EVENT_TYPE_FLAG_PCI_LINK_HEALTH |
        ZES_EVENT_TYPE_FLAG_RAS_CORRECTABLE_ERRORS | ZES_EVENT_TYPE_FLAG_RAS_UNCORRECTABLE_ERRORS |
        ZES_EVENT_TYPE_FLAG_DEVICE_RESET_REQUIRED;// | ZES_EVENT_TYPE_FLAG_SURVIVABILITY_MODE_DETECTED; // TODO: ZE_RESULT_ERROR_INVALID_ENUMERATION 0xffff < events

    auto td = std::make_unique<test_data>();

    int ret = for_each_zes_device_within_topo([&](zes_device_handle_t device_handle, ze_driver_handle_t driver, const MultiSliceGpu&) {
        if (auto ret = zesDeviceEventRegister(device_handle, event_types); ret != ZE_RESULT_SUCCESS) {
            log_skip(RuntimeSkipCategory, "Unable to create event monitor: %s", to_string(ret));
            return EXIT_SKIP;
        }
        td->thread_data.devices.emplace_back(device_handle);
        td->thread_data.driver = driver;
        return EXIT_SUCCESS;
    });
    if (ret != EXIT_SUCCESS) {
        return ret;
    }

    td->thread_data.n_events.resize(td->thread_data.devices.size());
    td->thread_data.events.resize(td->thread_data.devices.size());

    auto listener_runner = [td = td.get()]() {
        using namespace std::chrono_literals;

        assert(td != nullptr);

        static constexpr uint32_t timeout = 10; // ms

        uint32_t cur_n_events; // the actual number of devices that generated event(s), per call.
        std::vector<zes_event_type_flags_t> cur_events(td->thread_data.devices.size());

        while (td->thread_data.thread_should_run.load()) {
            assert(td->thread_data.driver != nullptr);
            assert(!td->thread_data.devices.empty());
            assert(!td->thread_data.events.empty());
            cur_n_events = 0;
            std::fill(cur_events.begin(), cur_events.end(), zes_event_type_flags_t{});
            auto ret = zesDriverEventListen(
                td->thread_data.driver, timeout,
                td->thread_data.devices.size(), td->thread_data.devices.data(),
                &cur_n_events, cur_events.data()
            );
            if (ret != ZE_RESULT_SUCCESS) {
                continue; // ignore
            }
            if (cur_n_events) {
                for (size_t i = 0; i < td->thread_data.devices.size(); i++) {
                    if (cur_events[i]) {
                        td->thread_data.events[i] |= cur_events[i];
                        td->thread_data.n_events[i]++;
                    }
                }
            }

            std::this_thread::sleep_for(150ms);
        }
    };

    try {
        td->thread = std::thread(listener_runner);
    } catch (...) {
        log_skip(RuntimeSkipCategory, "Unable to start event monitor thread");
        return EXIT_SKIP;
    }

    test->data = td.release();

    return EXIT_SUCCESS;
}

int listener_postcleanup(struct test* test)
{
    // join the thread, log results
    auto td = static_cast<test_data*>(test->data);

    td->thread_data.thread_should_run.store(false);
    td->thread.join();

    bool any_event =
        std::any_of(td->thread_data.n_events.begin(), td->thread_data.n_events.end(), [](auto n) { return n > 0; });

    if (any_event) {
        for (size_t i = 0; i < td->thread_data.devices.size(); i++) {
            if (td->thread_data.n_events[i] > 0) {
                log_info("GPU %zu: %" PRIu64 " event notifications, mask: %#x",
                        i, td->thread_data.n_events[i], td->thread_data.events[i]);
            }
        }
    }

    test->data = nullptr;
    delete td;
    return EXIT_SUCCESS;
}
} // unnamed namespace

#define CONCAT(x, y)    CONCAT2(x, y)
#define CONCAT2(x, y)    x ## y

// event_monitor is a special test.
struct test event_monitor_test = {
    .shortid = CONCAT(0x, TEST_ID_event_monitor),
#if SANDSTONE_NO_TEST_NAMES
    .id = SANDSTONE_STRINGIFY(TEST_ID_event_monitor),
    .description = nullptr,
#else
    .id = "event_monitor",
    .description = "Monitor GPU device events for hardware issues",
#endif // SANDSTONE_NO_TEST_NAMES
    .test_preinit = listener_preinit,
    .test_run = [](struct test*, int) { return EXIT_SUCCESS; },
    .test_postcleanup = listener_postcleanup,
    .desired_duration = -1,
    .fracture_loop_count = -1,
    .quality_level = TEST_QUALITY_PROD,
    .flags = test_in_parent,
};
