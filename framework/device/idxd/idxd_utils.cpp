/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "idxd_utils.hpp"

#include <format>

std::string to_string(const bdf_t& bdf)
{
    return std::format("{:04x}:{:02x}:{:02x}.{:01x}", bdf.domain, bdf.bus, bdf.device, bdf.function);
}

const char* to_string(accfg_device_type device_type)
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

const char* to_string(accfg_wq_state state)
{
    switch (state) {
    case accfg_wq_state::ACCFG_WQ_DISABLED:
        return "disabled";
    case accfg_wq_state::ACCFG_WQ_ENABLED:
        return "enabled";
    case accfg_wq_state::ACCFG_WQ_QUIESCING:
        return "quiescing";
    case accfg_wq_state::ACCFG_WQ_LOCKED:
        return "locked";
    case accfg_wq_state::ACCFG_WQ_UNKNOWN:
    default:
        return "unknown";
    }
}
