/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"
#include "sandstone_p.h"

#include <windows.h>

#ifndef RtlGenRandom
#  define RtlGenRandom SystemFunction036
#endif
extern "C"
DECLSPEC_IMPORT BOOLEAN WINAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);

#define WIN_TEMP_MAX_RETIRES            16

static HANDLE hSlot = INVALID_HANDLE_VALUE;

static bool open_mailslot()
{
    static const wchar_t prefix[] = L"\\\\.\\mailslot\\" SANDSTONE_EXECUTABLE_NAME ".";
    wchar_t name[std::size(prefix) + sizeof(SANDSTONE_STRINGIFY(UINT_MAX))];
    memcpy(name, prefix, sizeof(prefix));

    for (int i = 0; hSlot == INVALID_HANDLE_VALUE && i < WIN_TEMP_MAX_RETIRES; ++i) {
        // create a random value in base 36
        unsigned random;
        if (!RtlGenRandom(&random, sizeof(random)))
            continue;
        _ultow(random, name + std::size(prefix) - 1, 36);
        hSlot = CreateMailslotW(name, 0, MAILSLOT_WAIT_FOREVER, nullptr);
    }

    if (hSlot == INVALID_HANDLE_VALUE) {
        win32_perror("CreateMailslot");
    } else {
        // mailslots can't be waited on using WaitForMultipleObjects, so create
        // an event that the child can use to signal us when it's written
        // something
        SECURITY_ATTRIBUTES sa = {};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = true;
        sa.lpSecurityDescriptor = nullptr;
        HANDLE hEvent = CreateEventW(&sa, true, false, nullptr);
        if (!hEvent) {
            win32_perror("CreateEventW for mailslot");
            goto close_hslot;
        }

        // and open a file handle that the child can use to communicate write to
        HANDLE hFile = CreateFileW(name, GENERIC_WRITE, FILE_SHARE_READ, &sa, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            sApp->shmem->debug_event = intptr_t(hEvent);
            sApp->shmem->child_debug_socket = intptr_t(hFile);
            return true;
        }
        win32_perror("CreateFileW on mailslot");
        CloseHandle(hEvent);
    }

close_hslot:
    CloseHandle(hSlot);
    hSlot = INVALID_HANDLE_VALUE;
    return false;
}


void debug_init_child()
{
}

void debug_init_global(const char *on_hang_arg, const char *on_crash_arg)
{
    (void) on_hang_arg;
    if (SandstoneConfig::ChildDebugCrashes) {
        std::string_view arg = on_crash_arg ? on_crash_arg : "context";
        if (arg == "context" || arg == "context+core" || arg == "core+context") {
            open_mailslot();
        } else if (arg != "kill" && arg != "core" && arg != "coredump") {
            fprintf(stderr, "%s: unknown action for --on-crash: %s\n", program_invocation_name, on_crash_arg);
            exit(EX_USAGE);
        }
    }
}

void debug_crashed_child(pid_t child)
{
    (void) child;
}

void debug_hung_child(pid_t child)
{
    (void) child;
}
