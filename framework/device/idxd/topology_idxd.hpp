/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INC_TOPOLOGY_IDXD_HPP
#define INC_TOPOLOGY_IDXD_HPP

#include <vector>

/// Immutable and unique id of a queue: device_id and wq_id, as in qw<device_id>.<wq_id>.
struct WorkQueueId
{
    int device_id;
    int wq_id;
};

using WorkQueueSet = std::vector<WorkQueueId>;
using EnabledDevices = WorkQueueSet;

class Topology
{
public:
    using Thread = struct wq_info_t;

    // ...
    // ...
    // ...
};

struct HardwareInfo
{};

#endif // INC_TOPOLOGY_IDXD_HPP
