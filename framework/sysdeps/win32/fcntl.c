/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fcntl.h"

#include <errno.h>
#include <io.h>
#include <stdint.h>
#include <windows.h>

int posix_fallocate(int fd, off_t offset, off_t len)
{
    int ret = 0;
    int64_t cur, newend;
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE)
        return EBADF;

    /* get current position */
    cur = _lseeki64(fd, 0, SEEK_CUR);
    if (cur < 0)
        return errno;

    /* extend the file */
    newend = offset;
    newend += len;
    if (_lseeki64(fd, newend, SEEK_SET) < 0)
        return errno;

    /* allocate space */
    if (!SetEndOfFile(h))
        ret = ENOSPC;       /* we assume... */

    /* restore the position */
    _lseeki64(fd, cur, SEEK_SET);
    return ret;
}
