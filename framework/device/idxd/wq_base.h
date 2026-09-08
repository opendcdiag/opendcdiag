/*
 * Copyright 2026 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WQ_BASE_H
#define WQ_BASE_H

#include "idxd_device.h"

#define WQ_PORTAL_SIZE   4096

struct idxd_wq_handle_t
{
    int fd;
    void* reg;

    void* request;
    void* completion;
};
typedef struct idxd_wq_handle_t idxd_wq_handle_t;

#ifdef __cplusplus
extern "C" {
#endif

int wq_open(struct idxd_wq_handle_t* handle, const struct wq_info_t* info);
int wq_close(struct idxd_wq_handle_t* handle);

#ifdef __cplusplus
}
#endif

#endif // WQ_BASE_H
