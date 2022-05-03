/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WIN32_SYS_UIO_H
#define WIN32_SYS_UIO_H

#include <io.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct iovec {
    void  *iov_base;    /* Starting address */
    size_t iov_len;     /* Number of bytes to transfer */
};

static inline ssize_t writev(int fildes, const struct iovec *iov, int iovcnt)
{
    ssize_t total = -1;
    for (int i = 0; i < iovcnt; ++i) {
        ssize_t n = _write(fildes, iov[i].iov_base, iov[i].iov_len);
        if (n < 0)
            return total;
        if (total < 0)
            total = n;
        else
            total += n;
    }
    return total;
}

#ifdef __cplusplus
}
#endif

#endif
