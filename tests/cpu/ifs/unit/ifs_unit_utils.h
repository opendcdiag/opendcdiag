/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IFS_UNIT_UTILS_H_INCLUDED
#define IFS_UNIT_UTILS_H_INCLUDED

#include <stddef.h>

#define IFS_UNIT_MAX_FILES 5
#define IFS_MAX_PATH       256

typedef struct {
    const char *file;
    const char *contents;
} ifs_unit_file;

typedef struct {
    const char *name;
    size_t files_sz;
    ifs_unit_file files[IFS_UNIT_MAX_FILES];
} ifs_unit;

int read_sysfs_file(const char *tmp_dir, const char *file, char *contents);
int setup_sysfs_directory(const ifs_unit test);
int setup_sysfs_file(const char *tmp_dir, const char *file, const char *contents);

#endif //IFS_UNIT_UTILS_H
