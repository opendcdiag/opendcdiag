/*
 * Copyright 2022-2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_IFS_H_INCLUDED
#define SANDSTONE_IFS_H_INCLUDED

#define PATH_SYS_IFS_BASE "/sys/devices/virtual/misc/"
#define DEFAULT_TEST_ID   1

#define BUFLEN 256 // kernel module prints at most a 64bit value

/* from linux/ifs/ifs.h: */
/*
 * Driver populated error-codes
 * 0xFD: Test timed out before completing all the chunks.
 * 0xFE: not all scan chunks were executed. Maximum forward progress retries exceeded.
 */
#define IFS_SW_TIMEOUT                          0xFD
#define IFS_SW_PARTIAL_COMPLETION               0xFE
#define IFS_SW_SCAN_CANNOT_START                0x6

#define IFS_EXIT_CANNOT_START                   -2

typedef struct {
    const char *sys_dir;
    bool image_support;
    char image_id[BUFLEN];
    char image_version[BUFLEN];
} ifs_test_t;

bool compare_error_codes(unsigned long long code, unsigned long long expected);
bool write_file(int dfd, const char *filename, const char* value);
int open_sysfs_ifs_base(const char *sys_path);
ssize_t read_file(int dfd, const char *filename, char buf[BUFLEN]);
ssize_t read_file_fd(int fd, char buf[BUFLEN]);

#endif /* SANDSTONE_IFS_H_INCLUDED */
