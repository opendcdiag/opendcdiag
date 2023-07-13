/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifdef __APPLE__
// ucontext.h:43:2: error: #error The deprecated ucontext routines require _XOPEN_SOURCE to be defined
#  define _XOPEN_SOURCE 1
#endif

#include "sandstone_p.h"
#include "sandstone_context_dump.h"
#include "sandstone_iovec.h"

#include "futex.h"

#include <initializer_list>
#include <limits>
#include <span>
#include <type_traits>

#include <sys/types.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#ifdef __x86_64__
#  include <cpuid.h>
#endif

#ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL  0
#endif

#ifdef __linux__
#  include <sys/prctl.h>
#  include <sys/syscall.h>

typedef pid_t tid_t;
static inline tid_t sys_gettid()
{
    return syscall(SYS_gettid);
}

// can't #include <asm/ucontext.h> because until glibc 2.26 it conflicted with
// <sys/ucontext.h>, so:
#  ifndef UC_FP_XSTATE
#  define UC_FP_XSTATE  0x1
#  endif

// "recent" constants
#  ifndef FPE_FLTUNK
#  define FPE_FLTUNK	14
#  endif
#  ifndef FPE_CONDTRAP
#  define FPE_CONDTRAP  15
#  endif
#  ifndef ILL_BADIADDR
#  define ILL_BADIADDR  9
#  endif
#  ifndef SEGV_BNDERR
#  define SEGV_BNDERR   3
#  endif
#  ifndef SEGV_PKUERR
#  define SEGV_PKUERR   4
#  endif
#  ifndef BUS_MCEERR_AR
#  define BUS_MCEERR_AR 4
#  endif
#  ifndef BUS_MCEERR_AO
#  define BUS_MCEERR_AO 5
#  endif
#endif

extern char **environ;

namespace {
bool must_ignore_sigpipe()
{
    return O_NOSIGPIPE == 0;
}

struct CrashContext
{
    struct Fixed {
        pid_t pid = getpid();
#ifdef __linux__
        tid_t handle = sys_gettid();
#else
        uintptr_t handle = reinterpret_cast<uintptr_t>(pthread_self());
#endif
        void *crash_address;
        const void *rip;
        int thread_num;
        int signum;
        int signal_code;
        int trap_nr = -1;
        long error_code = 0;
    } fixed;
    static_assert(std::is_trivially_copyable_v<Fixed>, "Must be trivial to transfer over sockets");
    static_assert(std::is_trivially_destructible_v<Fixed>, "Must be trivial to transfer over sockets");

    std::span<uint8_t> xsave_buffer;
    std::remove_pointer_t<mcontext_t> mc;
    enum Contents {
        NoContents = 0x00,
        FixedContext = 0x01,
        MachineContext = 0x02,
        XsaveArea = 0x04
    } contents = NoContents;

    static void send(int sockfd, siginfo_t *si, void *ucontext);
    static CrashContext receive(int sockfd, std::span<uint8_t> xsave_buffer)
    {
        CrashContext result(xsave_buffer);
        result.receive_internal(sockfd);
        return result;
    }

private:
    CrashContext(std::span<uint8_t> xsave_buffer)
        : xsave_buffer(xsave_buffer), mc{}
    { }
    void receive_internal(int sockfd);
    static constexpr int MaxVectorCount = 3;
};
}

enum CrashAction : uint8_t {
    kill_on_crash           = 0x00,
    coredump_on_crash       = 0x01,
    context_on_crash        = 0x02,
    attach_gdb_on_crash     = 0x10,
    backtrace_on_crash      = context_on_crash | attach_gdb_on_crash,
};

enum HangAction {
    kill_on_hang,
    print_ps_on_hang,
    backtrace_on_hang,
    attach_gdb_on_hang
};

enum CrashPipe {
    CrashPipeParent,
    CrashPipeChild
};

static uint8_t on_crash_action = context_on_crash;
static uint8_t on_hang_action = print_ps_on_hang;
static int xsave_size = 0;
static int crashpipe[2] = { -1, -1 };

static const char gdb_preamble_commands[] = R"(set prompt
set pagination off
set confirm off
python handle = %#tx; print('ok')
)";
static const char gdb_bt_commands[] = R"(printf "Backtrace:"
thread apply all bt full
quit
)";
static const char gdb_python_commands[] = "python\n"
        R"gdb(
thr = None
for t in gdb.selected_inferior().threads():
    if t.ptid[1] == handle:
        thr = t
        break
if thr is not None:
    thr.switch()
    f = gdb.newest_frame()
    while f is not None and f.type() != gdb.SIGTRAMP_FRAME:
        f = f.older()
    if f is not None:
        f = f.older()
        f.select()
    gdb.execute("frame")
    try:
        gdb.execute("x/i $pc")
    except gdb.MemoryError as e:
        print(e)
print("..Done..")
end
)gdb";

static void child_crash_handler(int, siginfo_t *si, void *ucontext)
{
    // mark thread as failed
    logging_mark_thread_failed(thread_num);

    auto &thread_state = sApp->main_thread_data()->thread_state;
    thread_state.store(thread_failed, std::memory_order_release);

    if (crashpipe[CrashPipeChild] == -1)
        return;

    static std::atomic_flag in_crash_handler = {};
    if (!in_crash_handler.test_and_set()) {
        // let parent process know
        CrashContext::send(crashpipe[CrashPipeChild], si, ucontext);

        if (on_crash_action & attach_gdb_on_crash) {
            // now wait for the parent process to be done with us
            while (thread_state.load(std::memory_order_relaxed) == thread_failed)
                futex_wait(&thread_state, int(thread_failed));
        }

        // restore the signal handler so we can be killed
        signal(si->si_signo, SIG_DFL);
        if (si->si_signo != SIGABRT) {
            // if we return, we'll execute the same instruction and crash again
            // but the core dump should point to the exact locus now
            return;
        }
        raise(si->si_signo);
    }

    // wait forever
    struct pollfd dummy;
    while (true)
        poll(&dummy, 0, -1);
}

void CrashContext::send(int sockfd, siginfo_t *si, void *ucontext)
{
    CrashContext::Fixed fixed = {
        .crash_address = si->si_addr,
        .rip = si->si_addr,
        .thread_num = ::thread_num,
        .signum = si->si_signo,
        .signal_code = si->si_code,
    };
    size_t count = 1;
    struct iovec vec[MaxVectorCount] = {
        { &fixed, sizeof(fixed) }
    };

#ifdef __x86_64__
    auto ctx = static_cast<ucontext_t *>(ucontext);
#  ifdef __linux__
    // On Linux, the XSAVE area is pointed by the mcontext::fpregs pointer
    size_t n = xsave_size;
    mcontext_t *mc = &ctx->uc_mcontext;
    if (!mc->fpregs || (ctx->uc_flags & UC_FP_XSTATE) == 0)
        n = 0;
    vec[1] = { &mc->gregs, sizeof(mc->gregs) };
    vec[2] = { mc->fpregs, n };
    fixed.rip = reinterpret_cast<void *>(mc->gregs[REG_RIP]);
    fixed.error_code = mc->gregs[REG_ERR];
    fixed.trap_nr = mc->gregs[REG_TRAPNO];
    count = 3;
#  elif defined(__FreeBSD__)
    // On FreeBSD, the XSAVE area is split into two chunks, so we transfer
    // everything, including pointers. We put it together in the parent process.
    mcontext_t *mc = &ctx->uc_mcontext;
    vec[1] = { mc, size_t(mc->mc_len) };
    vec[2] = { reinterpret_cast<void *>(mc->mc_xfpustate), size_t(mc->mc_xfpustate_len) };
    fixed.rip = reinterpret_cast<void *>(mc->mc_rip);
    fixed.error_code = mc->mc_err;
    fixed.trap_nr = mc->mc_trapno;
    count = 3;
#  elif defined(__APPLE__)
    // We're not transferring the XSAVE state...
    vec[1] = { ctx->uc_mcontext, ctx->uc_mcsize };
    mcontext_t mc = ctx->uc_mcontext;
    fixed.error_code = mc->__es.__err;
    fixed.rip = reinterpret_cast<void *>(mc->__ss.__rip);
    fixed.trap_nr = mc->__es.__trapno;
    count = 2;
#  endif
#endif // x86-64

    if ((on_crash_action & context_on_crash) == 0)
        count = 1;

    struct msghdr hdr = {};
    hdr.msg_iov = vec;
    hdr.msg_iovlen = count;
    IGNORE_RETVAL(sendmsg(sockfd, &hdr, MSG_NOSIGNAL));
}

void CrashContext::receive_internal(int sockfd)
{
    size_t gpr_size = 0;
    size_t count = 1;
    struct iovec vec[MaxVectorCount] = {
        { &fixed, sizeof(fixed) }
    };

    // transfer our state to the parent process
    if (on_crash_action & context_on_crash) {
#ifdef __x86_64__
#  ifdef __linux__
        gpr_size = sizeof(mc.gregs);
        vec[1] = { &mc.gregs, gpr_size };
        vec[2] = { xsave_buffer.data(), xsave_buffer.size() };
        count = 3;
#  elif defined(__FreeBSD__)
        // not tested
        gpr_size = sizeof(mc);
        vec[1] = { &mc, gpr_size };
        vec[2] = { xsave_buffer.data() + FXSAVE_SIZE, xsave_buffer.size() - FXSAVE_SIZE };
        count = 3;
#  endif
#endif
    }

    struct msghdr hdr = {};
    hdr.msg_iov = vec;
    hdr.msg_iovlen = count;
    ssize_t ret = recvmsg(sockfd, &hdr, 0);
    contents = NoContents;
    ret -= sizeof(fixed);
    if (ret < 0)
        return;

    contents = FixedContext;

    if (gpr_size) {
        ret -= gpr_size;
        if (ret < 0)
            return;

        contents = Contents(contents | MachineContext);

#ifdef __FreeBSD__
        // need to move some stuff around
        if (ret == mc.mc_xfpustate_len) {
            memcpy(xsave_buffer.data(), mc.mc_fpstate, sizeof(mc.mc_fpstate));
            ret = sizeof(mc.mc_fpstate) + mc.mc_xfpustate_len;
        } else {
            ret = 0;
        }
#endif
        xsave_buffer = std::span(xsave_buffer.data(), ret);
        if (ret)
            contents = Contents(contents | MachineContext);
    } else {
        xsave_buffer = {};
    }
}

static bool check_gdb_available()
{
    if (!SandstoneConfig::ChildBacktrace)
        return false;

    std::string path;
    if (const char *env = getenv("PATH"); env && *env)
        path = env;
    else
        path = _PATH_DEFPATH;

    std::string candidate;
    for (const char *dir = strtok(path.data(), ":"); dir; dir = strtok(nullptr, ":")) {
        candidate = dir;
        candidate += "/gdb";
        if (access(candidate.data(), X_OK) == 0)
            return true;
    }

    return false;
}

static bool create_crash_pipe(int xsave_size)
{
    int socktype = SOCK_DGRAM;
#ifdef SOCK_CLOEXEC
    socktype |= SOCK_CLOEXEC;
#endif
    if (socketpair(AF_UNIX, socktype, 0, crashpipe) == -1)
        return false;

    // set the buffer sizes
    xsave_size += sizeof(CrashContext::Fixed) + sizeof(CrashContext::mc);
    xsave_size += 256;      // add some headroom; the Linux kernel subtracts 32
    xsave_size = ROUND_UP_TO(xsave_size, 1024U);

    int rcvbuf;
    socklen_t size = sizeof(rcvbuf);
    if (getsockopt(crashpipe[CrashPipeParent], SOL_SOCKET, SO_RCVBUF, &rcvbuf, &size) == 0) {
        if (rcvbuf >= xsave_size)
            xsave_size = 0;
    }
    if (xsave_size) {
        bool ok = setsockopt(crashpipe[CrashPipeChild], SOL_SOCKET, SO_SNDBUF, &xsave_size, sizeof(xsave_size)) == 0;
        ok = ok && setsockopt(crashpipe[CrashPipeParent], SOL_SOCKET, SO_RCVBUF, &xsave_size, sizeof(xsave_size)) == 0;
        if (!ok) {
            close(crashpipe[CrashPipeParent]);
            close(crashpipe[CrashPipeChild]);
            crashpipe[CrashPipeParent] = crashpipe[CrashPipeChild] = -1;
            return false;
        }
    }

    // set the parent end to non-blocking and leave the child end blocking
    int ret = fcntl(crashpipe[CrashPipeParent], F_GETFL);
    if (ret >= 0)
        fcntl(crashpipe[CrashPipeParent], F_SETFL, ret | O_NONBLOCK);

    return true;
}

static void set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int run_process(int stdout_fd, const char *args[])
{
    pid_t child = vfork();
    if (child == -1)
        return -1;
    if (child > 0) {
        /* parent process, wait for child */
        int ret;
        EINTR_LOOP(ret, waitpid(child, NULL, 0));
        return ret;
    }

    /* child process */
    dup2(stdout_fd, STDOUT_FILENO);     /* No O_CLOEXEC */
    execvp(args[0], const_cast<char **>(args));

    IGNORE_RETVAL(writeln(STDERR_FILENO, "# Could not start '", args[0], "': ", strerror(errno)));
    _exit(1);
    return -1;
}

static void communicate_gdb_backtrace(int log, int in, int out, uintptr_t handle, int cpu)
{
    using namespace std::chrono;
    using namespace std::chrono_literals;
    constexpr auto GdbCommunicationTimeout = SandstoneConfig::Debug ? 1h : 30s;

    ssize_t ret;
    char buf[4096];
    auto deadline = coarse_steady_clock::now() + GdbCommunicationTimeout;
    struct pollfd pfd[1] = {
        { .fd = in, .events = POLLIN }
    };
    auto wait_for_more = [&pfd, deadline]() {
        int remaining = duration_cast<milliseconds>(deadline - coarse_steady_clock::now()).count();
        while (remaining >= 0) {
            int ret = poll(pfd, std::size(pfd), remaining);
            if (ret == -1 && errno == EINTR) {
                // recalculate and restart
                remaining = duration_cast<milliseconds>(deadline - coarse_steady_clock::now()).count();
                continue;
            }
            return ret;
        }
        return 0;           // timed out
    };

    // drain gdb's start
    set_nonblock(in);
    for (;;) {
        static const char needle[] = "(gdb) ";
        ret = wait_for_more();
        if (ret <= 0)
            return;

        ret = read(in, buf, sizeof(buf) - 1);
        if (ret <= 0)
            return;
        buf[ret] = '\0';

        // ### the needle may be split between buffers!
        // but experience says gdb writes only a handful of bytes
        if (size_t(ret) >= strlen(needle)) {
            if (strcmp(buf + (ret - strlen(needle)), needle) == 0)
                break;
        }
    }

    // send a python command setting the search handle
    ret = dprintf(out, gdb_preamble_commands, handle);
    if (ret <= 0)
        return;
    ret = wait_for_more();
    if (ret <= 0)
        return;

    ret = read(in, buf, sizeof(buf) - 1);
    if (ret <= 0)
        return;
    buf[ret] = '\0';

    bool send_python = handle && (strcmp(buf, "ok\n") == 0);
    if (send_python) {
        ret = write(out, gdb_python_commands, strlen(gdb_python_commands));
        if (ret != ssize_t(strlen(gdb_python_commands)))
            return;

        // skip the >>>>> caused by the multi-line python command
        for (;;) {
            ret = wait_for_more();
            if (ret <= 0)
                return;

            ret = read(in, buf, sizeof(buf) - 1);
            if (ret <= 0)
                return;
            buf[ret] = '\0';

            char *msg = buf;
            while (*msg == '>' || *msg == '\n')
                ++msg;
            if (*msg != '\0') {
                ret -= msg - buf;
                memmove(buf, msg, ret);
                break;
            }
        }

        // wait until the Python reply is complete
        for (;;) {
            static const char needle[] = "..Done..\n";
            if (ret >= strlen(needle) && strcmp(buf + ret - strlen(needle), needle) == 0) {
                buf[ret - strlen(needle)] = '\0';
                break;
            }

            ssize_t ret2 = wait_for_more();
            if (ret2 <= 0)
                return;

            ret2 = read(in, buf + ret, sizeof(buf) - ret);
            if (ret2 <= 0)
                return;
            buf[ret + ret2] = '\0';
            ret += ret2;
        }

        if (cpu != -1) {
            // log to the specific CPU
            log_message(cpu, SANDSTONE_LOG_WARNING "%s", buf);
        } else {
            IGNORE_RETVAL(write(log, buf, strlen(buf)));
        }
    }

    // now get the actual backtrace (includes "quit")
    ret = write(out, gdb_bt_commands, strlen(gdb_bt_commands));
    if (ret != ssize_t(strlen(gdb_bt_commands)))
        return;

    // splice backtrace from gdb to our log file
    for (;;) {
        ret = wait_for_more();
        if (ret <= 0)
            return;

#if defined(SPLICE_F_NONBLOCK)
        ret = splice(in, nullptr, log, nullptr, std::numeric_limits<int>::max(),
                     SPLICE_F_NONBLOCK);
#else
        ret = read(in, buf, sizeof(buf));
        if (ret > 0)
            IGNORE_RETVAL(write(log, buf, ret));
#endif
        if (ret == -1 && (errno == EINTR || errno == EWOULDBLOCK))
            continue;
        if (ret <= 0)
            return;
    }
}

static void generate_backtrace(const char *pidstr, uintptr_t handle = 0, int cpu = -1)
{
    if (!SandstoneConfig::ChildBacktrace) {
        assert(false && "Should not have reached here");
        __builtin_unreachable();
    }

    Pipe gdb_in, gdb_out;
    if (!gdb_in || !gdb_out)
        return;

    pid_t gdb_pid = fork();
    if (gdb_pid < 0)
        return;
    if (gdb_pid == 0) {
        // child process, set up standard streams and run gdb
        dup2(gdb_out.out(), STDERR_FILENO);
        dup2(gdb_out.out(), STDOUT_FILENO);
        dup2(gdb_in.in(), STDIN_FILENO);

        // unset DEBUGINFO_URLS, if it is set
        for (char **ptr = environ; *ptr; ++ptr) {
            static char debuginfo_urls[] = "DEBUGINFO_URLS=";
            if (strncmp(*ptr, debuginfo_urls, strlen(debuginfo_urls)) == 0)
                (*ptr)[strlen(debuginfo_urls)] = '\0';
        }

        execlp("gdb", "gdb", "-nw", "-n", "-q", "-p", pidstr, nullptr);
        _exit(EX_UNAVAILABLE);
    }

    // parent process
    gdb_in.close_input();
    gdb_out.close_output();

    struct sigaction old_sigpipe, ign_sigpipe;
    if (must_ignore_sigpipe()) {
        // temporarily suspend SIGPIPE handling (in case gdb exits early on us)
        sigemptyset(&ign_sigpipe.sa_mask);
        ign_sigpipe.sa_flags = 0;
        ign_sigpipe.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &ign_sigpipe, &old_sigpipe);
    }

    {
        LoggingStream stream = logging_user_messages_stream(-1, LOG_LEVEL_VERBOSE(2));
        communicate_gdb_backtrace(stream, gdb_out.in(), gdb_in.out(), handle, cpu);
    }

    // close the pipes and wait for gdb to exit
    gdb_in.close_output();
    gdb_out.close_input();

    int ret;
    EINTR_LOOP(ret, waitpid(gdb_pid, nullptr, 0));

    // restore SIGPIPE
    if (must_ignore_sigpipe())
        sigaction(SIGPIPE, &old_sigpipe, nullptr);
}

static void attach_gdb(const char *pidstr)
{
    if (!SandstoneConfig::ChildBacktrace) {
        assert(false && "Should not have reached here");
        __builtin_unreachable();
    }
    const char *gdb_args[] = { "gdb", "-p", pidstr, nullptr };
    run_process(logging_stdout_fd(), gdb_args);
}

/// returns true we should print register information for this signal
static bool print_signal_info(const CrashContext::Fixed &ctx)
{
    static auto generic_code_string = +[](int code) {
        switch (code) {
        // POSIX.1 constants - https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/signal.h.html
        case SI_USER: return "SI_USER";
        case SI_QUEUE: return "SI_QUEUE";
        case SI_TIMER: return "SI_TIMER";
        case SI_ASYNCIO: return "SI_ASYNCIO";
        case SI_MESGQ: return "SI_MESGQ";
#ifdef SI_KERNEL
        case SI_KERNEL: return "SI_KERNEL";
#endif
#ifdef SI_SIGIO
        case SI_SIGIO: return "SI_SIGIO";
#endif
#ifdef SI_DETHREAD
        case SI_DETHREAD: return "SI_DETHREAD";
#endif
        }
        return "??";
    };

    auto sigfpe_code_string = [](int code) {
        switch (code) {
        case FPE_INTDIV: return "FPE_INTDIV";        // Integer divide by zero.
        case FPE_INTOVF: return "FPE_INTOVF";        // Integer overflow.
        case FPE_FLTDIV: return "FPE_FLTDIV";        // Floating point divide by zero.
        case FPE_FLTOVF: return "FPE_FLTOVF";        // Floating point overflow.
        case FPE_FLTUND: return "FPE_FLTUND";        // Floating point underflow.
        case FPE_FLTRES: return "FPE_FLTRES";        // Floating point inexact result.
        case FPE_FLTINV: return "FPE_FLTINV";        // Floating point invalid operation.
        case FPE_FLTSUB: return "FPE_FLTSUB";        // Subscript out of range.
#ifdef FPE_FLTUNK
        case FPE_FLTUNK: return "FPE_FLTUNK";        // Undiagnosed floating-point exception.
#endif
#ifdef FPE_CONDTRAP
        case FPE_CONDTRAP: return "FPE_CONDTRAP";    // Trap on condition.
#endif
        }
        return generic_code_string(code);
    };

    auto sigill_code_string = [](int code) {
        switch (code) {
        case ILL_ILLOPC: return "ILL_ILLOPC";        // Illegal opcode.
        case ILL_ILLOPN: return "ILL_ILLOPN";        // Illegal operand.
        case ILL_ILLADR: return "ILL_ILLADR";        // Illegal addressing mode.
        case ILL_ILLTRP: return "ILL_ILLTRP";        // Illegal trap.
        case ILL_PRVOPC: return "ILL_PRVOPC";        // Privileged opcode.
        case ILL_PRVREG: return "ILL_PRVREG";        // Privileged register.
        case ILL_COPROC: return "ILL_COPROC";        // Coprocessor error.
        case ILL_BADSTK: return "ILL_BADSTK";        // Internal stack error.
#ifdef ILL_BADIADDR
        case ILL_BADIADDR: return "ILL_BADIADDR";    // Unimplemented instruction address.
#endif
        }
        return generic_code_string(code);
    };

    auto sigsegv_code_string = [](int code) {
        switch (code) {
        // Linux seems to generate only MAPERR, BNDERR and PKUERR
        case SEGV_MAPERR: return "SEGV_MAPERR";        // Address not mapped to object.
        case SEGV_ACCERR: return "SEGV_ACCERR";        // Invalid permissions for mapped object.
#ifdef SEGV_BNDERR
        case SEGV_BNDERR: return "SEGV_BNDERR";        // Bounds checking failure.
#endif
#ifdef SEGV_PKUERR
        case SEGV_PKUERR: return "SEGV_PKUERR";        // Protection key checking failure.
#endif
#if 0               // seem to be Sparc-specific
        case SEGV_ACCADI: return "SEGV_ACCADI";        // ADI not enabled for mapped object.
        case SEGV_ADIDERR: return "SEGV_ADIDERR";      // Disrupting MCD error.
        case SEGV_ADIPERR: return "SEGV_ADIPERR";      // Precise MCD exception.
#endif
#if 0               // ARM exceptions can't occur on x86
        case SEGV_MTEAERR: return "SEGV_MTEAERR";      // Asynchronous ARM MTE error.
        case SEGV_MTESERR: return "SEGV_MTESERR";      // Synchronous ARM MTE exception.
#endif
        }
        return generic_code_string(code);
    };

    auto sigbus_code_string = [](int code) {
        switch (code) {
        case BUS_ADRALN: return "BUS_ADRALN";        // Invalid address alignment.
        case BUS_ADRERR: return "BUS_ADRERR";        // Non-existant physical address.
        case BUS_OBJERR: return "BUS_OBJERR";        // Object specific hardware error.
#ifdef BUS_MCEERR_AR
        case BUS_MCEERR_AR: return "BUS_MCEERR_AR";  // Hardware memory error: action required.
#endif
#ifdef BUS_MCEERR_AO
        case BUS_MCEERR_AO: return "BUS_MCEERR_AO";  // Hardware memory error: action optional.
#endif
        }
        return generic_code_string(code);
    };

    auto sigtrap_code_string = [](int code) {
        switch (code) {
        case TRAP_BRKPT: return "TRAP_BRKPT";
        case TRAP_TRACE: return "TRAP_TRACE";
#ifdef TRAP_BRANCH      // added on 2.6.28
        case TRAP_BRANCH: return "TRAP_BRANCH";
#endif
#ifdef TRAP_HWBKPT
        case TRAP_HWBKPT: return "TRAP_HWBKPT";
#endif
#ifdef TRAP_UNK
        case TRAP_UNK: return "TRAP_UNK";
#endif
        }
        return generic_code_string(code);
    };

    const char *(*code_string_fn)(int) = nullptr;
    (void)code_string_fn;

    int cpu = ctx.thread_num;
    switch (ctx.signum) {
    case SIGABRT:
        log_message(cpu, SANDSTONE_LOG_WARNING
                    "Received signal %d (Abort) - could be a software error", SIGABRT);
        return false;

    case SIGFPE:
        code_string_fn = sigfpe_code_string;
        break;

    case SIGILL:
        code_string_fn = sigill_code_string;
        break;

    case SIGSEGV:
        code_string_fn = sigsegv_code_string;
        break;

    case SIGBUS:
        code_string_fn = sigbus_code_string;
        break;

    case SIGTRAP:
        code_string_fn = sigtrap_code_string;
        break;

    default:
        // don't know this signal and won't print it
        return false;
    }

    std::string message =
            stdprintf("Received signal %d (%s) code=%d (%s), RIP = %p", ctx.signum,
                      strsignal(ctx.signum), ctx.signal_code,
                      code_string_fn(ctx.signal_code), ctx.rip);

    if (Dl_info info; dladdr(ctx.rip, &info) && uintptr_t(ctx.rip) > uintptr_t(info.dli_fbase)) {
        // include the shared object's name and subtract its base address
        if (const char *slash = strrchr(info.dli_fname, '/'))
            info.dli_fname = slash + 1;
        message += stdprintf(" (%s+%#tx)", info.dli_fname,
                               uintptr_t(ctx.rip) - uintptr_t(info.dli_fbase));
    }
    if (ctx.rip != ctx.crash_address)
        message += stdprintf(", CR2 = %p", ctx.crash_address);
    if (ctx.trap_nr >= 0) {
        static const char trap_names[][4] = {
            "DE", "DB", "NMI", "BP",
            "OF", "BR", "UD", "NM",
            "DF", "MF", "TS", "NP",
            "SS", "GP", "PF", "spu",
            "MF", "AC", "MC", "XF",
        };
        const char *trap_name = "??";
        if (ctx.trap_nr == 32)
            trap_name = "IRET";
        else if (size_t(ctx.trap_nr) < std::size(trap_names))
            trap_name = trap_names[ctx.trap_nr];

        message += stdprintf(", trap=%d (%s), error_code = 0x%lx",
                             ctx.trap_nr, trap_name, ctx.error_code);
    }

    log_message(cpu, SANDSTONE_LOG_ERROR "%s", message.c_str());
    return true;
}

static void print_crash_info(const char *pidstr, CrashContext &ctx)
{
    int cpu = -1;
    uintptr_t handle = 0;
    if (ctx.contents & CrashContext::FixedContext) {
        cpu = ctx.fixed.thread_num;
        handle = ctx.fixed.handle;
        if (cpu < -1 || cpu > sApp->thread_count)
            ctx.fixed.thread_num = cpu = -1;

        bool print_registers = print_signal_info(ctx.fixed);
        if (!print_registers)
            handle = 0;
    }

    if (SandstoneConfig::ChildBacktrace
            && (on_crash_action & backtrace_on_crash) == backtrace_on_crash) {
        // generate the backtrace as a second step
        generate_backtrace(pidstr, handle, cpu);
    }

    // now include the register state
    if (handle && ctx.contents & CrashContext::MachineContext) {
        char *buffer = nullptr;
        size_t buflen = 0;
        FILE *log = open_memstream(&buffer, &buflen);
        fprintf(log, "Registers:\n");

#ifdef __x86_64__
        dump_gprs(log, &ctx.mc);
        dump_xsave(log, ctx.xsave_buffer.data(), ctx.xsave_buffer.size(), -1);
#endif

        fclose(log);
        logging_user_messages_stream(cpu, LOG_LEVEL_VERBOSE(2))
                .write(std::string_view(buffer, buflen));
        free(buffer);
    }
}

void debug_init_global(const char *on_hang_arg, const char *on_crash_arg)
{
    int gdb_available = -1;
    if (!FutexAvailable)
        gdb_available = 0;      // we can't synchronize without futexes
    if (SandstoneConfig::RestrictedCommandLine)
        on_hang_arg = on_crash_arg = nullptr;       // enforce the defaults

    if (SandstoneConfig::ChildDebugHangs && on_hang_arg) {
        std::string_view arg = on_hang_arg;
        if (SandstoneConfig::ChildBacktrace && (arg == "gdb" || arg == "attach-gdb")) {
            on_hang_action = attach_gdb_on_hang;
        } else if (SandstoneConfig::ChildBacktrace && arg == "backtrace") {
            on_hang_action = backtrace_on_hang;
        } else if (arg == "ps") {
            on_hang_action = print_ps_on_hang;
        } else if (arg == "kill") {
            on_hang_action = kill_on_hang;
        } else {
            fprintf(stderr, "%s: unknown action for --on-hang: %s\n", program_invocation_name, on_hang_arg);
            exit(EX_USAGE);
        }

        if (SandstoneConfig::ChildBacktrace && on_hang_action >= backtrace_on_hang) {
            if (gdb_available == -1)
                gdb_available = check_gdb_available();
            if (!gdb_available) {
                fprintf(stderr, "%s: --on-hang=%s requires gdb but we couldn't find it.\n", program_invocation_name, on_hang_arg);
                exit(EX_USAGE);
            }
        }
    }

    if (SandstoneConfig::ChildDebugCrashes && on_crash_arg) {
        std::string_view arg = on_crash_arg;
        if (SandstoneConfig::ChildBacktrace && (arg == "gdb" || arg == "attach-gdb")) {
            on_crash_action = attach_gdb_on_crash;
        } else if (arg == "context") {
            on_crash_action = context_on_crash;
        } else if (arg == "context+core" || arg == "core+context") {
            on_crash_action = coredump_on_crash | context_on_crash;
        } else if (SandstoneConfig::ChildBacktrace && arg == "backtrace") {
            on_crash_action = backtrace_on_crash;
        } else if (arg == "core" || arg == "coredump") {
            on_crash_action = coredump_on_crash;
        } else if (SandstoneConfig::ChildBacktrace && (arg == "backtrace+core" || arg == "core+backtrace")) {
            on_crash_action = coredump_on_crash | backtrace_on_crash;
        } else if (arg == "kill") {
            on_crash_action = kill_on_crash;
        } else {
            fprintf(stderr, "%s: unknown action for --on-crash: %s\n", program_invocation_name, on_crash_arg);
            exit(EX_USAGE);
        }

        if (SandstoneConfig::ChildBacktrace && on_crash_action & backtrace_on_hang) {
            if (gdb_available == -1)
                gdb_available = check_gdb_available();
            if (!gdb_available) {
                fprintf(stderr, "%s: --on-crash=%s requires gdb but we couldn't find it.\n",
                        program_invocation_name, on_crash_arg);
                exit(EX_USAGE);
            }
        }
    } else {
#  ifdef __linux__
        // do we have gdb?
        if (gdb_available == -1)
            gdb_available = check_gdb_available();
        if (gdb_available)
            on_crash_action = backtrace_on_crash;
#  else
        on_crash_action = context_on_crash;
#  endif
    }

    if (on_crash_action & (context_on_crash | attach_gdb_on_crash)) {
#  ifdef __x86_64__
        // get the size of the context to transfer
        uint32_t eax, ebx, ecx, edx;
        if (__get_cpuid_count(0xd, 0, &eax, &ebx, &ecx, &edx))
            xsave_size = ebx;
        else
            xsave_size = FXSAVE_SIZE;
#  endif

        if (!create_crash_pipe(xsave_size)) {
            // could not create the communications pipe, pare the action back
            on_crash_action &= ~(context_on_crash | attach_gdb_on_crash);
        }
    }

    /* set us up for producing core dumps if wanted */
    struct rlimit core_limit;
    getrlimit(RLIMIT_CORE, &core_limit);
    if (on_crash_action & coredump_on_crash) {
        if (core_limit.rlim_cur < core_limit.rlim_max) {
            // raise RLIMIT_CORE to the max
            core_limit.rlim_cur = core_limit.rlim_max;
        } else if (core_limit.rlim_max == 0) {
            fprintf(stderr, "%s: cannot honor --on-crash=%s: system hard core file size limit is 0.\n",
                    program_invocation_name, on_crash_arg);
        }
    } else if (on_crash_action == kill_on_crash) {
        core_limit.rlim_cur = 0;
    }
    setrlimit(RLIMIT_CORE, &core_limit);

#if defined(__linux__)
    // this makes attaching gdb impossible, so do it only in non-debug builds
    if (!SandstoneConfig::Debug && on_crash_action == kill_on_crash && on_hang_action == kill_on_hang)
        prctl(PR_SET_DUMPABLE, false);
#endif
}

void debug_init_child()
{
    if (!SandstoneConfig::ChildDebug)
        return;

    if (SandstoneConfig::ChildBacktrace && on_crash_action & (context_on_crash | attach_gdb_on_crash)) {
        struct sigaction action = {};
        sigemptyset(&action.sa_mask);
        action.sa_sigaction = child_crash_handler;
        action.sa_flags = SA_NODEFER;       // allow recursive signalling, so the child can raise()
        action.sa_flags |= SA_SIGINFO;
        for (int signum : { SIGILL, SIGABRT, SIGFPE, SIGBUS, SIGSEGV }) {
            sigaction(signum, &action, nullptr);
        }
    }
}

intptr_t debug_child_watch()
{
    return crashpipe[CrashPipeParent];
}

void debug_crashed_child()
{
    if (!SandstoneConfig::ChildDebugCrashes || crashpipe[CrashPipeParent] == -1)
        return;

    // receive the context
    alignas(16) uint8_t xsave_area[xsave_size];     // Variable Length Array, a.k.a. alloca
    CrashContext ctx = CrashContext::receive(crashpipe[CrashPipeParent],
                                             { xsave_area, size_t(xsave_size) });

    if (ctx.contents != CrashContext::NoContents) {
        char buf[std::numeric_limits<pid_t>::digits10 + 2];
        sprintf(buf, "%d", ctx.fixed.pid);

        if (on_crash_action == attach_gdb_on_crash)
            attach_gdb(buf);
        else
            print_crash_info(buf, ctx);
    }

    // release the child
    auto &thread_state = sApp->main_thread_data()->thread_state;
    thread_state.load(std::memory_order_acquire);
    if (on_crash_action != context_on_crash) {
        thread_state.store(thread_debugged, std::memory_order_relaxed);
        futex_wake_all(&thread_state);
    }
}

void debug_hung_child(pid_t child)
{
    if (!SandstoneConfig::ChildDebugHangs)
        return;

    char buf[std::numeric_limits<pid_t>::digits10 + 2];
    sprintf(buf, "%d", child);

    if (on_hang_action == print_ps_on_hang) {
        const char *ps_args[] =
            { "ps", "Hww", "-opid,tid,psr,vsz,rss,wchan,%cpu,stat,time,comm,args", buf, nullptr };
        LoggingStream stream = logging_user_messages_stream(-1, LOG_LEVEL_VERBOSE(2));
        run_process(stream, ps_args);
    } else if (SandstoneConfig::ChildBacktrace) {
        if (on_hang_action == attach_gdb_on_hang) {
            attach_gdb(buf);
        } else if (on_hang_action == backtrace_on_hang) {
            generate_backtrace(buf);
        }
    }
}
