/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WIN32_FCNTL_H
#define WIN32_FCTNL_H

#include_next <fcntl.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Extra POSIX fucntions we need */
int posix_fallocate(int fd, off_t offset, off_t len);

#ifdef __cplusplus
}
#endif

#endif
