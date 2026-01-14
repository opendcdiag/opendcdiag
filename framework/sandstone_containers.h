/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __INCLUDE_GUARD_SANDSTONE_CONTAINERS_H_
#define __INCLUDE_GUARD_SANDSTONE_CONTAINERS_H_

#include <string>
#include <optional>

/*
 * If running inside of container the returned optional will contain the container's type
 */
std::optional<std::string> detect_running_container();

#endif /* __INCLUDE_GUARD_SANDSTONE_CONTAINERS_H_ */
