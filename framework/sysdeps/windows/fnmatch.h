/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_WIN32_FNMATCH_H
#define SANDSTONE_WIN32_FNMATCH_H

#ifdef __cplusplus
extern "C" {
#endif

int fnmatch(const char *pattern, const char *name, int flags);

#ifdef __cplusplus
};
#endif

#endif // SANDSTONE_WIN32_FNMATCH_H
