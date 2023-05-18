/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(__x86_64__) && defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "ifs_unit_utils.h"

int setup_sysfs_file(const char *tmp_dir, const char *file, const char *contents)
{
    // Build full path
    char *file_path = (char *) malloc(strlen(tmp_dir) + strlen(file) + 2);
    sprintf(file_path, "%s/%s", tmp_dir, file);

    // Create file
    FILE *fp = fopen(file_path, "w");
    if (!fp)
        return -errno;

    // Populate file
    int ret = fprintf(fp, "%s\n", contents);
    fclose(fp);
    if (ret < 0)
        return -errno;

    return ret;
}

int read_sysfs_file(const char *tmp_dir, const char *file, char *contents)
{
    // Build full path
    char *file_path = (char *) malloc(strlen(tmp_dir) + strlen(file) + 2);
    sprintf(file_path, "%s/%s", tmp_dir, file);

    // Open file
    FILE *fp = fopen(file_path, "r");
    if (!fp)
        return -errno;

    // Read file
    int ret = fread(contents, sizeof(char), 255, fp);
    fclose(fp);
    if (ret < 0)
        return -errno;

    // Trim new line
    // Files read are one-line only
    if (ret > 0 && contents[ret-1] == '\n')
        contents[ret-1] = '\0';

    return ret;
}

int setup_sysfs_directory(const ifs_unit test)
{
    // Create tmp directory
    int ret = mkdir(test.name, 0700);
    if (ret != 0)
        return ret;

    // Create and populate files
    for (size_t i = 0; i < test.files_sz; i++)
        setup_sysfs_file(test.name, test.files[i].file, test.files[i].contents);

    return ret;
}

#endif
