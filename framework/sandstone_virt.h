/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __INCLUDE_GUARD_SANDSTONE_VIRT_H_
#define __INCLUDE_GUARD_SANDSTONE_VIRT_H_

#include <string>

/*
 * If running inside of container, will return
 * non-empty string with the container's name
 */
std::string detect_running_container();

/*
 * If running inside a vm, will return
 * non-empty string with the vm's name
 */
std::string detect_running_vm();

#endif /* __INCLUDE_GUARD_SANDSTONE_VIRT_H_ */
