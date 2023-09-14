/*
 * Copyright 2023 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>

#include <windows.h>

void win32_perror(const char *msg)
{
    DWORD dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS |
            FORMAT_MESSAGE_ARGUMENT_ARRAY | FORMAT_MESSAGE_ALLOCATE_BUFFER;
    LPCVOID lpSource = NULL;
    DWORD dwMessageId = GetLastError();
    DWORD dwLanguageId = 0;
    LPSTR lpBuffer = NULL;
    DWORD nSize = 0;
    FormatMessage(dwFlags, lpSource, dwMessageId, dwLanguageId, (LPTSTR)&lpBuffer, nSize, NULL);
    if (msg)
        fprintf(stderr, "%s: ", msg);
    fprintf(stderr, "%s\n", lpBuffer);
    LocalFree(lpBuffer);

    SetLastError(dwMessageId);      /* restore */
}
