/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IDXD_BASE_H
#define IDXD_BASE_H

#include "sandstone.h"
#include "idxd_device.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#define WQ_PORTAL_SIZE   4096

struct idxd_wq_handle_t
{
    int fd;
    void* reg;

    void* request;
    void* completion;
};
typedef struct idxd_wq_handle_t idxd_wq_handle_t;

static inline int wq_open(struct idxd_wq_handle_t* handle, const struct wq_info_t* info)
{
    const char* device_type;
    switch (info->dev_type) {
    case ACCFG_DEVICE_DSA:
        device_type = "dsa";
        break;
    case ACCFG_DEVICE_IAX:
        device_type = "iax";
        break;
    default:
        log_skip(RuntimeSkipCategory, "Unknown device type");
        return EXIT_SKIP;
    }

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/dev/%s/wq%d.%d", device_type, info->device_id, info->wq_id);

    handle->fd = open(path, O_RDWR);
    if (handle->fd < 0) {
        log_skip(RuntimeSkipCategory, "Cannot open portal");
        return EXIT_SKIP;
    }

    handle->reg = mmap(NULL, WQ_PORTAL_SIZE, PROT_WRITE, MAP_SHARED | MAP_POPULATE, handle->fd, 0);
    if (handle->reg == MAP_FAILED) {
        (void)close(handle->fd);
        handle->fd = -1;
        log_skip(RuntimeSkipCategory, "Cannot mmap portal");
        return EXIT_SKIP;
    }

    handle->request = NULL;
    handle->completion = NULL;

    return EXIT_SUCCESS;
}

static inline int wq_close(struct idxd_wq_handle_t* handle)
{
    if (handle->reg != MAP_FAILED)
        (void)munmap(handle->reg, WQ_PORTAL_SIZE);
    if (handle->fd >= 0)
        (void)close(handle->fd);
    handle->reg = MAP_FAILED;
    handle->fd = -1;

    free(handle->request);
    handle->request = NULL;
    free(handle->completion);
    handle->completion = NULL;

    return EXIT_SUCCESS;
}

#endif // IDXD_BASE_H
