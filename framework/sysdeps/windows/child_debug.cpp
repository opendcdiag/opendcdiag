/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone_child_debug_common.h"

#include "sandstone_p.h"
#include "sandstone_context_dump.h"
#include "win32_errorstrings.h"

#include <windows.h>

enum HangAction {
    kill_on_hang,
    context_on_hang,
    attach_gdb_on_hang
};
static uint8_t on_hang_action = kill_on_hang;

#if defined(__x86_64__) && !defined(CONTEXT_XSTATE)
#  define CONTEXT_XSTATE        (CONTEXT_AMD64 | 0x00000040L)
#endif

#ifndef RtlGenRandom
#  define RtlGenRandom SystemFunction036
#endif
extern "C"
DECLSPEC_IMPORT BOOLEAN WINAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);

#define WIN_TEMP_MAX_RETIRES            16

struct CrashContext
{
    struct Header {
        DWORD_PTR baseAddress;
        int thread_num;
    };

    static constexpr DWORD DesiredContextFlags =
#ifdef __x86_64__
            CONTEXT_SEGMENTS | CONTEXT_XSTATE |
#endif
            CONTEXT_FULL;

    Header header;
    EXCEPTION_RECORD exceptionRecord;
    alignas(64) CONTEXT fixedContext;
    char xsave_area[];      // C99 Flexible Array Member
};
static CrashContext *preallocatedContext = nullptr;
static ptrdiff_t preallocatedContextSize = 0;
static uintptr_t executableImageStart, executableImageEnd;
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

static LONG WINAPI handler(EXCEPTION_POINTERS *info)
{
    // Ignore non-error or user-defined exceptions. See
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/87fba13e-bf06-450e-83b1-9241dc81e781
    //  Bits    Meaning     Required value
    //  30:31   severity    3 (STATUS_SEVERITY_ERROR)
    //  29      customer    0 (Microsoft-defined)
    //  28      reserved    0
    //  16:27   facility    0 (NT kernel)
    DWORD code = info->ExceptionRecord->ExceptionCode;
    if ((code >> 16) != 0xC000)
        return EXCEPTION_CONTINUE_SEARCH;

    static std::atomic_flag in_crash_handler = {};
    if (in_crash_handler.test_and_set()) {
        // wait forever
        Sleep(INFINITE);
    }

    // copy the context's fixed portions
    CrashContext *ctx = preallocatedContext;
    ctx->header.thread_num = thread_num;
    ctx->exceptionRecord = *info->ExceptionRecord;
    ptrdiff_t context_size = sizeof(*ctx);
    if (CopyContext(&ctx->fixedContext, CrashContext::DesiredContextFlags, info->ContextRecord))
        context_size = preallocatedContextSize;
    else
        ctx->fixedContext = *info->ContextRecord;

    // did the crash happen inside the executable?
    if (uintptr_t(info->ExceptionRecord->ExceptionAddress) >= executableImageStart
            && uintptr_t(info->ExceptionRecord->ExceptionAddress) < executableImageEnd)
        ctx->header.baseAddress = executableImageStart;

    if (!WriteFile(HANDLE(sApp->shmem->child_debug_socket), ctx, context_size, nullptr, nullptr))
        win32_perror("WriteFile for mailslot");
    if (!SetEvent(HANDLE(sApp->shmem->debug_event)))
        win32_perror("SetEvent for mailslot");

    TerminateProcess(GetCurrentProcess(), info->ExceptionRecord->ExceptionCode);
    __builtin_unreachable();
    return EXCEPTION_CONTINUE_SEARCH;
}

#ifdef __x86_64__
static void print_non_gprs(FILE *log, PCONTEXT ctx)
{
    // Windows doesn't store the XSAVE state in a contiguous block, so
    // we have to put it back together.
    int xsave_size = get_xsave_size();
    if (xsave_size < FXSAVE_SIZE + 64)
        xsave_size = FXSAVE_SIZE;               // legacy only (FXSAVE)

    alignas(64) char xsave_area[xsave_size];    // -Wvla
    memset(xsave_area, 0, xsave_size);
    memcpy(xsave_area, &ctx->FloatSave, sizeof(XMM_SAVE_AREA32));

    if (xsave_size > FXSAVE_SIZE) {
        // copy the rest of the features to where they ought to be
        PDWORD64 xsave_bv_ptr = reinterpret_cast<PDWORD64>(xsave_area + FXSAVE_SIZE);
        if (GetXStateFeaturesMask(ctx, xsave_bv_ptr) && *xsave_bv_ptr) {
            // these are already in the fixed context record:
            DWORD64 xsave_bv = *xsave_bv_ptr & ~XSTATE_MASK_LEGACY;

            for (int bit = XSTATE_AVX; xsave_bv; ++bit) {
                uint32_t eax, ebx, ecx, edx;
                DWORD length;
                DWORD64 mask = DWORD64(1) << bit;
                if ((xsave_bv & mask) == 0)
                    continue;
                xsave_bv &= ~mask;
                void *src = LocateXStateFeature(ctx, bit, &length);

                __cpuid_count(0xd, bit, eax, ebx, ecx, edx);
                if (eax == length)
                    memcpy(xsave_area + ebx, src, eax);
                else
                    *xsave_bv_ptr &= ~mask;
            }
        }
    }

    dump_xsave(log, xsave_area, xsave_size, -1);
}
#endif

static void print_exception_info(const CrashContext *ctx)
{
    std::string message =
            stdprintf("Received exception 0x%x (%s), RIP = 0x%tx",
                      unsigned(ctx->exceptionRecord.ExceptionCode),
                      status_code_to_string(ctx->exceptionRecord.ExceptionCode),
                      uintptr_t(ctx->exceptionRecord.ExceptionAddress));
    if (ctx->header.baseAddress) {
        ptrdiff_t basedAddress = reinterpret_cast<char *>(ctx->exceptionRecord.ExceptionAddress) -
                reinterpret_cast<char *>(ctx->header.baseAddress);
        message += stdprintf(" (base+0x%tx)", basedAddress);
    }

    if (ctx->exceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION
            || ctx->exceptionRecord.ExceptionCode == EXCEPTION_IN_PAGE_ERROR) {
        message += stdprintf(", CR2 = 0x%llx access=%c",
                             ctx->exceptionRecord.ExceptionInformation[1],
                             ctx->exceptionRecord.ExceptionInformation[0] ? 'W' : 'R');
    } else if (ctx->exceptionRecord.NumberParameters) {
        // no documentation for these, but they may be useful
        message += ", parameters [";
        for (int i = 0; i < int(ctx->exceptionRecord.NumberParameters); ++i)
            message += stdprintf("%tx", uintptr_t(ctx->exceptionRecord.ExceptionInformation[i]));
        message += ']';
    }

    log_message(ctx->header.thread_num, SANDSTONE_LOG_ERROR "%s", message.c_str());
}

void debug_init_child()
{
    if (!SandstoneConfig::ChildDebugCrashes || sApp->shmem->debug_event == 0)
        return;
    assert(sApp->shmem->child_debug_socket != intptr_t(INVALID_HANDLE_VALUE));

    MEMORY_BASIC_INFORMATION info;
    DWORD infosize = VirtualQuery(LPCVOID(&handler), &info, sizeof(info));
    if (infosize) {
        executableImageStart = uintptr_t(info.AllocationBase);
        executableImageEnd = executableImageStart + info.RegionSize;
    }

    PCONTEXT pContext;
    DWORD contextLength;
    InitializeContext(nullptr, CrashContext::DesiredContextFlags, nullptr, &contextLength);
    preallocatedContextSize = sizeof(CrashContext) + contextLength - sizeof(CONTEXT);
    void *ptr = aligned_alloc(alignof(CrashContext), preallocatedContextSize);
    preallocatedContext = new (ptr) CrashContext;
    if (!InitializeContext(&preallocatedContext->fixedContext,
                           CrashContext::DesiredContextFlags, &pContext, &contextLength)
            || pContext != &preallocatedContext->fixedContext) {
        free(ptr);
        preallocatedContext = nullptr;
        return;
    }

    // install the vectored exception handler
    PVOID h = AddVectoredExceptionHandler(true, handler);
    (void) h;
}

void debug_init_global(const char *on_hang_arg, const char *on_crash_arg)
{
    if (SandstoneConfig::ChildDebugHangs && on_hang_arg) {
        std::string_view arg = on_hang_arg;
        if (SandstoneConfig::ChildBacktrace && (arg == "gdb" || arg == "attach-gdb")) {
            on_hang_action = attach_gdb_on_hang;
        }
    }
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

static void attach_gdb(HANDLE child)
{
    DWORD pid = GetProcessId(HANDLE(child));
    if (pid == 0)
        return;

    char pidstr[std::numeric_limits<DWORD>::digits10 + 2];
    sprintf(pidstr, "%lu", pid);
    const char *argv[] = {
        "gdb.exe",
        program_invocation_name,
        pidstr,
        nullptr
    };

    // restore our regular stdout, so the user can interact with gdb
    int saved_stdout = _dup(STDOUT_FILENO);
    _dup2(logging_stdout_fd(), STDOUT_FILENO);

    _spawnvp(_P_WAIT, argv[0], const_cast<char **>(argv));

    _dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdout);
}

void debug_crashed_child(std::span<const pid_t> children)
{
    if (!SandstoneConfig::ChildDebugCrashes)
        return;
    if (hSlot == INVALID_HANDLE_VALUE)
        return;
    (void) children;

    ResetEvent(HANDLE(sApp->shmem->debug_event));

    std::string buf;
    DWORD dwNextMessage = 0;
    AutoClosingFile log;
    while (GetMailslotInfo(hSlot, nullptr, &dwNextMessage, nullptr, nullptr)) {
        if (dwNextMessage == MAILSLOT_NO_MESSAGE)
            return;

        if (buf.size() < dwNextMessage)
            buf.resize(dwNextMessage);
        if (!ReadFile(hSlot, buf.data(), dwNextMessage, &dwNextMessage, nullptr))
            break;

        auto ctx = reinterpret_cast<CrashContext *>(buf.data());
        int cpu = ctx->header.thread_num;
        if (cpu < -1 || cpu > sApp->thread_count)
            cpu = ctx->header.thread_num = -1;
        print_exception_info(ctx);

        // no open_memstream() or fcookieopen() in MSVCRT or UCRT, so we use
        // a real file
        if (!log)
            log.f = tmpfile();
        if (!log)
            continue;

        fseek(log, 0, SEEK_SET);
        fprintf(log, "Registers:\n");
#ifdef __x86_64__
        dump_gprs(log, &ctx->fixedContext);
        print_non_gprs(log, &ctx->fixedContext);
#endif

        long size = ftell(log);
        if (size < 0)
            continue;
        if (buf.size() < size_t(size))
            buf.resize(size);

        fseek(log, 0, SEEK_SET);
        size = fread(buf.data(), 1, size, log);

        logging_user_messages_stream(cpu, LOG_LEVEL_VERBOSE(2))
                .write(std::string_view(buf.data(), size));
    }

    // got here on failure
    CloseHandle(hSlot);
    CloseHandle(HANDLE(sApp->shmem->debug_event));
    sApp->shmem->debug_event = 0;
}

void debug_hung_child(pid_t child, std::span<const pid_t> children)
{
    if (!SandstoneConfig::ChildDebugHangs || on_hang_action == kill_on_hang)
        return;
    (void) children;

    // pid_t is actually a HANDLE in disguise (using _spawnv)
    if (on_hang_action == attach_gdb_on_hang)
        attach_gdb(HANDLE(child));
}
