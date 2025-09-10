/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>

#include <algorithm>
#include <compare>

#include <windows.h>

namespace {
struct ErrnoMapping
{
    DWORD win32_code;
    int errno_code;

    friend constexpr std::strong_ordering operator<=>(ErrnoMapping a, ErrnoMapping b) noexcept
    { return a.win32_code <=> b.win32_code; }
    friend constexpr bool operator==(ErrnoMapping, ErrnoMapping) noexcept = default;
};

static constexpr ErrnoMapping mapping[] = {
    { ERROR_SUCCESS, 0 },
    { ERROR_FILE_NOT_FOUND, ENOENT },
    { ERROR_PATH_NOT_FOUND, ENOENT },
    { ERROR_TOO_MANY_OPEN_FILES, EMFILE },
    { ERROR_ACCESS_DENIED, EACCES },
    { ERROR_INVALID_HANDLE, EBADF },
    { ERROR_NOT_ENOUGH_MEMORY, ENOMEM },
    { ERROR_INVALID_ACCESS, EINVAL },
    { ERROR_INVALID_DATA, EINVAL },
    { ERROR_OUTOFMEMORY, ENOMEM },
    { ERROR_WRITE_PROTECT, EROFS },
    //{ ERROR_OUT_OF_PAPER, EONFIRE },  // lp0: printer on fire
    { ERROR_NOT_SUPPORTED, ENOTSUP },
    { ERROR_BAD_NETPATH, ENOENT },
    { ERROR_FILE_EXISTS, EEXIST },
    { ERROR_INVALID_PARAMETER, EINVAL },
    { ERROR_BROKEN_PIPE, EPIPE },
    { ERROR_BUFFER_OVERFLOW, EOVERFLOW },
    { ERROR_DISK_FULL, ENOSPC },
    { ERROR_CALL_NOT_IMPLEMENTED, ENOSYS },
    { ERROR_INSUFFICIENT_BUFFER, EFAULT }, // ENOMEM?
    { ERROR_PROC_NOT_FOUND, ESRCH },
    { ERROR_WAIT_NO_CHILDREN, ECHILD },
    { ERROR_DIR_NOT_EMPTY, ENOTEMPTY },
    { ERROR_BAD_PATHNAME, ENOENT },
    { ERROR_BAD_EXE_FORMAT, ENOEXEC },
};

static_assert(std::ranges::is_sorted(mapping), "mapping array is not sorted");
}

extern "C" void set_errno_from_last_error(DWORD error) noexcept
{
    auto it = std::ranges::lower_bound(mapping, ErrnoMapping{error, 0});
    if (it != std::end(mapping) && it->win32_code == error)
        errno = it->errno_code;
    else
        errno = ENOMSG;       // sentinel for when we don't find it
}
