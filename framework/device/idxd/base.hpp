/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IDXD_BASE_H
#define IDXD_BASE_H

#include "sandstone.h"
#include "idxd_device.h"
#include "topology_idxd.hpp"

#include <concepts>
#include <cstdlib>
#include <format>
#include <string>

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

struct idxd_wq_handle_t
{
    int fd;
    void* reg;

    void* request;
    void* completion;
};

inline std::string to_string(const wq_info_t* info)
{
    return std::format("wq{}.{}", info->device_id, info->wq_id);
}

inline std::string to_string(accfg_device_type device_type)
{
    switch (device_type) {
    case ACCFG_DEVICE_DSA:
        return "dsa";
    case ACCFG_DEVICE_IAX:
        return "iax";
    default:
        return {};
    }
}

inline std::string to_string(bdf_t bdf)
{
    return std::format("{:04x}:{:02x}:{:02x}.{:01x}", bdf.domain, bdf.bus, (uint8_t)bdf.device, (uint8_t)bdf.function);
}

inline void idxd_log_context(const wq_info_t* info)
{
    const auto& path = info->path;
    const auto& device_topo = Topology::topology().devices[path.device];
    const auto& group_topo = device_topo.groups[path.group];

    /* The strings below require no escaping, as they don't contain the single
     * quote character.
     */
    std::string engine_str;
    if (group_topo.engines.size() == 1) {
        engine_str = std::format("engine: '{}', ", group_topo.engines[0].name);
    }

    log_thread_context("type: %s, bdf: '%s', numa_node: %d, device: '%s', group: '%s', %swq: %s",
                       to_string(info->dev_type).c_str(), to_string(info->bdf).c_str(), device_topo.numa_node, device_topo.name.c_str(),
                       group_topo.name.c_str(), engine_str.c_str(), to_string(info).c_str());
}

// Base test class implementing only run() function, so that it does not have to store handles in vectors.
// On the other hand, we end up with multiple instances of AccfgCtx. Which is better?
class RunBase
{
protected:
    static constexpr int WQ_PORTAL_SIZE = 4096;
    idxd_wq_handle_t portal{ .fd = -1, .reg = MAP_FAILED, .request = nullptr, .completion = nullptr };

private:
    int wq_open(const wq_info_t& info)
    {
        auto device_type = to_string(info.dev_type);
        if (device_type.empty()) {
            log_skip(RuntimeSkipCategory, "Unknown device type");
            return EXIT_SKIP;
        }

        std::string path = std::format("/dev/{}/{}", device_type, to_string(&info));

        portal.fd = open(path.c_str(), O_RDWR);
        if (portal.fd < 0) {
            log_skip(RuntimeSkipCategory, "Cannot open portal");
            return EXIT_SKIP;
        }

        portal.reg = mmap(nullptr, WQ_PORTAL_SIZE, PROT_WRITE, MAP_SHARED | MAP_POPULATE, portal.fd, 0);
        if (portal.reg == MAP_FAILED) {
            (void)close(portal.fd);
            portal.fd = -1;
            log_skip(RuntimeSkipCategory, "Cannot mmap portal");
            return EXIT_SKIP;
        }

        portal.request = nullptr;
        portal.completion = nullptr;

        return EXIT_SUCCESS;
    }

    int wq_close()
    {
        if (portal.reg != MAP_FAILED)
            (void)munmap(portal.reg, WQ_PORTAL_SIZE);
        if (portal.fd >= 0)
            (void)close(portal.fd);

        portal.reg = MAP_FAILED;
        portal.fd = -1;
        free(portal.request);
        portal.request = nullptr;
        free(portal.completion);
        portal.completion = nullptr;

        return EXIT_SUCCESS;
    }

public:
    virtual ~RunBase() = default;

    // to be implemented by tests
    virtual int run(struct test* test, int thread) = 0;

    int run_impl(struct test* test, int thread)
    {
        auto ret = wq_open(device_info[thread]);
        if (ret != EXIT_SUCCESS) {
            return ret;
        }
        ret = run(test, thread);
        wq_close();
        return ret;
    }
};

/// To be used by tests.
template <typename RunClass>
    requires std::derived_from<RunClass, RunBase>
int run_idxd_base(struct test* test, int thread)
{
    RunClass runner{};
    return runner.run_impl(test, thread);
}

#endif // IDXD_BASE_H
