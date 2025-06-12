/*
 * Copyright 2025 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>

#include <windows.h>

void win32_perror(const char *msg)
{
    DWORD dwMessageId = GetLastError();
    if (msg)
        fprintf(stderr, "%s: ", msg);
    fprintf(stderr, "%s\n", win32_strerror(dwMessageId).c_str());

    SetLastError(dwMessageId);      /* restore */
}

std::string win32_strerror(last_error_t last_err)
{
    DWORD dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS |
            FORMAT_MESSAGE_ARGUMENT_ARRAY | FORMAT_MESSAGE_ALLOCATE_BUFFER;
    LPCVOID lpSource = nullptr;
    DWORD dwLanguageId = 0;
    LPSTR lpBuffer = nullptr;
    DWORD nSize = 0;
    FormatMessage(dwFlags, lpSource, last_err, dwLanguageId, (LPTSTR)&lpBuffer, nSize, NULL);
    std::string strerror(lpBuffer);
    LocalFree(lpBuffer);

    return strerror;
}
