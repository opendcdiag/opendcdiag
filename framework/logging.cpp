/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE 1
#ifdef _WIN32
#  define _POSIX_C_SOURCE 200112L
#endif
#include "sandstone.h"
#include "sandstone_p.h"
#include "sandstone_iovec.h"
#include "sandstone_utils.h"
#include "sandstone_virt.h"

#if SANDSTONE_SSL_BUILD
#  include "sandstone_ssl.h"
#endif
#include "topology.h"
#include "logging.h"
#include "device/logging_device.h"

#include <limits>
#include <string>
#include <string_view>
#include <unordered_set>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#ifndef _WIN32
#  include <sys/utsname.h>
#endif

#if O_CLOEXEC
#  define FOPEN_CLOEXEC     "e"
#elif defined(_O_NOINHERIT) && defined(_UCRT)
#  define FOPEN_CLOEXEC     "N"
#  define O_CLOEXEC         _O_NOINHERIT
#else
#  define FOPEN_CLOEXEC     ""
#endif
#if defined(_O_SHORT_LIVED) && defined(_UCRT)
#  define FOPEN_SHORTLIVED  "D"
#else
#  define FOPEN_SHORTLIVED  ""
#endif

#if defined(__GLIBC__)
// this disables pthread cancellation
#  define FOPEN_EXTRA       "c"
#else
#  define FOPEN_EXTRA       ""
#endif

#ifndef O_CLOEXEC
#  define O_CLOEXEC 0
#endif

#ifdef _WIN32
#  include <ntstatus.h>
#  include <windows.h>
#  include "win32_errorstrings.h"
#  define dup _dup
#  define dup2 _dup2
#  define _PATH_DEVNULL "NUL"

// ddk/ntddk.h
extern "C" {
NTSYSAPI
NTSTATUS
NTAPI
RtlGetVersion(
  IN OUT PRTL_OSVERSIONINFOW lpVersionInformation);
}
#else
#  include <paths.h>
#  include <syslog.h>
#endif

#if __has_include(<gnu/libc-version.h>)
#  include <gnu/libc-version.h>
#endif

using LogMessage = AbstractLogger::LogMessage;              // for convenience
using LogMessagesFile = AbstractLogger::LogMessagesFile;    // for convenience

static constexpr const char *levels[] = { "error", "warning", "info", "debug" };

static int tty = -1;
static int stderr_fd = -1;
static bool delete_log_on_success;
static uint8_t progress_bar_needs_flush = false;

static constexpr auto UsedKnobValueLoggingLevel = LOG_LEVEL_VERBOSE(1);

int AbstractLogger::real_stdout_fd = STDOUT_FILENO;
int AbstractLogger::file_log_fd = -1;

enum class AbstractLogger::LogTypes : uint8_t
{
    UserMessages = 0,
    Preformatted = 1,
    UsedKnobValue = 2,
    SkipMessages = 3,
    RawYaml = 4,
};
using LogTypes = AbstractLogger::LogTypes;

static SandstoneApplication::OutputFormat current_output_format()
{
    if (SandstoneConfig::NoLogging)
        return SandstoneApplication::OutputFormat::no_output;
    return sApp->shmem->cfg.output_format;
}

std::string_view AbstractLogger::indent_spaces()
{
    if (current_output_format() == SandstoneApplication::OutputFormat::no_output)
        return {};

    static const std::string spaces(sApp->shmem->cfg.output_yaml_indent, ' ');
    return spaces;
}

static const char *strnchr(const char *buffer, char c, size_t len)
{
    // we do NOT handle an embedded NUL, but the code in this file doesn't do
    // that (crossing fingers, promise)
    return static_cast<const char *>(memchr(buffer, c, len));
}

static Iso8601Format operator|(Iso8601Format f1, Iso8601Format f2)
{ return Iso8601Format(unsigned(f1) | unsigned(f2)); }
static unsigned operator&(Iso8601Format f1, Iso8601Format f2)
{ return unsigned(f1) & unsigned(f2); }

const char *AbstractLogger::iso8601_time_now(Iso8601Format format)
{
    static char buffer[sizeof "2147483647-12-31T23:59:60.999999Z"];
    struct tm tm;
    struct timespec now;
#if _POSIX_MONOTONIC_CLOCK >= 0
    clock_t clock = CLOCK_REALTIME;
#  ifdef CLOCK_REALTIME_COARSE
    clock = CLOCK_REALTIME_COARSE;
#  endif
    clock_gettime(clock, &now);
#else
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    now.tv_sec = tv.tv_sec;
    now.tv_nsec = tv.tv_usec * 1000;
#endif
    gmtime_r(&now.tv_sec, &tm);

    size_t off = strftime(buffer, sizeof(buffer) - sizeof(".999999Z") + 1,
                          format & Iso8601Format::FilenameCompatible ?
                              "%Y%m%dT%H%M%S" :  "%Y-%m-%dT%H:%M:%S",
                          &tm);

    if (format & Iso8601Format::WithMs) {
        // append microseconds
        snprintf(buffer + off, sizeof(buffer) - off, ".%06dZ", int(now.tv_nsec) / 1000);
    } else {
        // append only the Zulu timezone marker
        buffer[off++] = 'Z';
        buffer[off] = '\0';
    }

    return buffer;
}

static struct timespec elapsed_runtime(void)
{
    static struct timespec start_time = { -1, 0 };
    struct timespec now;
    get_monotonic_time_now(&now);
    if (start_time.tv_sec < 0)
        start_time = now;

    long secs = now.tv_sec - start_time.tv_sec;
    long nsecs = now.tv_nsec - start_time.tv_nsec;
    if (nsecs < 0) {
        --secs;
        nsecs += 1000 * 1000 * 1000;
    }

    return (struct timespec){ secs, nsecs };
}

std::string AbstractLogger::log_timestamp()
{
    struct timespec elapsed = elapsed_runtime();
    return stdprintf("[%5ld.%06d] ", (long)elapsed.tv_sec, (int)elapsed.tv_nsec / 1000);
}

static bool is_dumb_terminal()
{
    static const bool result = []() {
        const char *term = getenv("TERM");
        return term && strcmp(term, "dumb") == 0;
    }();
    return result;
}

static void progress_bar_update()
{
    using namespace std::chrono;
    static constexpr seconds PrintingInterval{10};
    if (tty == -1)
        return;

    static struct timespec last_dot_time = { -1, 0 };
    struct timespec now;
    get_monotonic_time_now(&now);

    nanoseconds interval = PrintingInterval;
    if (last_dot_time.tv_sec >= 0)
        interval = seconds(now.tv_sec - last_dot_time.tv_sec) +
                nanoseconds(now.tv_nsec - last_dot_time.tv_nsec);

    char buf[2] = { '\x08', '.' };      // BACKSPACE
    char *ptr = progress_bar_needs_flush & 2 ? buf : buf + 1;
    size_t n = progress_bar_needs_flush & 2 ? 2 : 1;
    if (interval >= PrintingInterval) {
        last_dot_time = now;
        progress_bar_needs_flush &= ~2;
    } else if (is_dumb_terminal()) {
        return;
    } else {
        static const char distractions[4] = { '-', '\\', '|', '/' };
        int idx = duration_cast<seconds>(interval).count() % sizeof(distractions);
        buf[1] = distractions[idx];
        progress_bar_needs_flush |= 2;
    }
    progress_bar_needs_flush |= write(tty, ptr, n) >= 0;
}

static void progress_bar_flush()
{
    if (!progress_bar_needs_flush)
        return;

    std::string_view flush_str =
            is_dumb_terminal() ? "\n" :
                                 // don't get a newline, simply clear this one to EOL
                                 "\r\e[K";
    progress_bar_needs_flush = false;
    IGNORE_RETVAL(write(tty, flush_str.data(), flush_str.size()));
}

/* which level of "quiet" should this log print at */
static LogLevelVerbosity status_level(char letter)
{
    // note: the YAML logger requires that the message levels have a 1:1 mapping
    switch (letter) {
    case 'E':
        return LOG_LEVEL_QUIET;         /* always */
    case 'W':
        return LOG_LEVEL_VERBOSE(1);    /* no warnings if -q */
    case 'I':
        return LOG_LEVEL_VERBOSE(2);    /* info only with -vv */
    case 'd':
        return LOG_LEVEL_VERBOSE(3);    /* debug only with -vvv or the log file */
    }

    log_warning("got improper status log message '%c'", letter);
    return LOG_LEVEL_VERBOSE(2);
}

const char *AbstractLogger::char_to_skip_category(int val)
{
    switch (val) {
    case CpuNotSupportedSkipCategory:
        return "CpuNotSupported";
    case DeviceNotFoundSkipCategory:
        return "DeviceNotFound";
    case DeviceNotConfiguredSkipCategory:
        return "DeviceNotConfigured";
    case UnknownSkipCategory:
        return "Unknown";
    case RuntimeSkipCategory:
        return "Runtime";
    case SelftestSkipCategory:
        return "Selftest";
    case OsNotSupportedSkipCategory:
        return "OsNotSupported";
    case TestResourceIssueSkipCategory:
        return "TestResourceIssue";
    case CpuTopologyIssueSkipCategory:
        return "CpuTopologyIssue";
    case OSResourceIssueSkipCategory:
        return "OSResourceIssue";
    case IgnoredMceCategory:
        return "IgnoredMceCategory";
    case TestObsoleteSkipCategory:
        return "TestObsolete";
    }

    return "NO CATEGORY PRESENT";
}

template <typename... Args> static ssize_t
log_message_for_thread(PerThreadData::Common *thread, LogTypes logType,
                       LogLevelVerbosity level, Args &&... args)
{
    iovec vec[1 + sizeof...(args)] = { {}, IoVecMaker{}(args)... };
    size_t size_bytes = 0;
    for (const iovec &v : vec)
        size_bytes += v.iov_len;

    LogMessage msg = { .msglen = uint32_t(size_bytes), .type = logType, .verbosity = level, };
    assert(msg.msglen == size_bytes && "too many bytes logged in a single message!");
    thread->messages_logged.fetch_add(1, std::memory_order_relaxed);

    vec[0].iov_base = &msg;
    vec[0].iov_len = sizeof(msg);
    return writev(thread->log_fd, vec, std::size(vec));
}

int logging_stdout_fd(void)
{
    return AbstractLogger::real_stdout_fd;
}

static inline int open_new_log()
{
    if (sApp->current_fork_mode() == SandstoneApplication::ForkMode::exec_each_test)
        return open_memfd(MemfdInheritOnExec);
    else
        return open_memfd(MemfdCloseOnExec);
}

static inline void truncate_log(int fd)
{
    // truncate files back to empty, preparing for the next iteration
    lseek(fd, 0, SEEK_SET);
    IGNORE_RETVAL(ftruncate(fd, 0));
}

AbstractLogger::LogMessagesFile AbstractLogger::maybe_mmap_log(const PerThreadData::Common *data)
{
    if (data->messages_logged.load(std::memory_order_relaxed) == 0)
        return {};
    return LogMessagesFile(data->log_fd);
}

void AbstractLogger::munmap_and_truncate_log(PerThreadData::Common *data, LogMessagesFile &r)
{
    if (r.empty())
        return;
    r.unmap();
    truncate_log(data->log_fd);
    data->messages_logged.store(0, std::memory_order_relaxed);
}

void logging_init_global_child()
{
    assert(sApp->current_fork_mode() == SandstoneApplication::ForkMode::child_exec_each_test);

    AbstractLogger::file_log_fd = AbstractLogger::real_stdout_fd = STDOUT_FILENO;
#ifndef NDEBUG
    logging_printf(LOG_LEVEL_QUIET, "# stdout is expected to be connected to " _PATH_DEVNULL
                   " so you should never see this message\n");
#endif
}

static bool should_log_to_file()
{
    return sApp->file_log_path != "-" &&
            sApp->file_log_path != "/dev/stdout" &&
            sApp->file_log_path != "stdout";
}

static const char *time_based_log_path()
{
    extern char *program_invocation_name;
    const char *extension =
            current_output_format() == SandstoneApplication::OutputFormat::yaml ? ".yaml" : ".log";

    constexpr bool IsWindows =
#ifdef _WIN32
            true;
#else
            false;
#endif

    assert(!sApp->file_log_path.empty());
    std::string_view toolname = program_invocation_name;
    std::size_t pos = toolname.rfind('/');
    if (IsWindows && pos == std::string_view::npos)
        pos = toolname.rfind('\\');
    if (pos == std::string_view::npos) {
        // We're in $PATH?
        sApp->file_log_path += '/';
        sApp->file_log_path += toolname;
    } else {
        sApp->file_log_path += toolname.substr(pos);
    }
    if (IsWindows) {
        // strip the .exe suffix if it's there
        static const char exeSuffix[] = ".exe";
        if (toolname.size() > strlen(exeSuffix)
                && toolname.substr(toolname.size() - strlen(exeSuffix)) == ".exe")
        sApp->file_log_path.resize(sApp->file_log_path.size() - 4);
    }

    // append suffixes
    sApp->file_log_path += '-';
    sApp->file_log_path += AbstractLogger::iso8601_time_now(Iso8601Format::WithMs | Iso8601Format::FilenameCompatible);
    sApp->file_log_path += extension;
    return sApp->file_log_path.c_str();
}

void logging_init_global(void)
{
#ifdef _WIN32
    // Enable virtual terminal sequences in our console, so sequences used in
    // progress bar are handled correctly. We do it early so that we can get
    // our console from STD_OUTPUT_HANDLE.
    DWORD conmode;
    HANDLE hstdout = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleMode(hstdout, &conmode);
    SetConsoleMode(hstdout, conmode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#endif

    /* move stdout to a different file descriptor for us */
#ifdef F_DUPFD_CLOEXEC
    AbstractLogger::real_stdout_fd = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 0);
#else
    AbstractLogger::real_stdout_fd = dup(STDOUT_FILENO);
#endif
    if (AbstractLogger::real_stdout_fd == -1) {
        // this will never happen
        perror("fdopen");
        exit(EXIT_MEMORY);
    }

    if (current_output_format() == SandstoneApplication::OutputFormat::no_output ||
            !SandstoneConfig::AllowStdoutFromTests) {
        // replace stdout with /dev/null
        close(STDOUT_FILENO);
        int devnull = open(_PATH_DEVNULL, O_RDWR);
        assert(devnull >= 0);
        if (devnull != STDOUT_FILENO) {
            dup2(devnull, STDOUT_FILENO);
            close(devnull);
        }
    }

    if (current_output_format() == SandstoneApplication::OutputFormat::no_output) {
        AbstractLogger::file_log_fd = STDOUT_FILENO;
    } else if (should_log_to_file()) {
        errno = EISDIR;
        if (sApp->file_log_path.empty())
            sApp->file_log_path = '.';

        AbstractLogger::file_log_fd = open(sApp->file_log_path.c_str(), O_RDWR | O_CLOEXEC | O_CREAT | O_TRUNC, 0666);
        bool isdir = false;
        if (AbstractLogger::file_log_fd == -1) {
#ifdef _WIN32
            // open(".") for writing on Windows results in other errors instead of EISDIR
            DWORD attr = GetFileAttributesA(sApp->file_log_path.c_str());
            isdir = attr & FILE_ATTRIBUTE_DIRECTORY;
#else
            // on Unix, we can rely on EISDIR
            isdir = errno == EISDIR;
#endif
        }
        if (isdir) {
            AbstractLogger::file_log_fd = open(time_based_log_path(), O_RDWR | O_CLOEXEC | O_CREAT | O_TRUNC | O_EXCL, 0666);
            delete_log_on_success = true;
        }
        if (AbstractLogger::file_log_fd == -1) {
            fprintf(stderr, "%s: failed to open log file: %s: %s\n",
                    program_invocation_name, sApp->file_log_path.c_str(), strerror(errno));
            exit(EX_CANTCREAT);
        }
    }

    if (AbstractLogger::file_log_fd == -1) {
        AbstractLogger::file_log_fd = AbstractLogger::real_stdout_fd;
    } else {
#ifdef _WIN32
        // no tty on win32, open app's console instead
        tty = open("CON:", _O_WRONLY);
#elif defined _PATH_TTY
        if (isatty(AbstractLogger::real_stdout_fd)) {
            // stdout is a tty, so try to open /dev/tty
            tty = open(_PATH_TTY, O_WRONLY | O_NOCTTY | O_CLOEXEC);
        }
#endif
    }

    /* open some place to store stderr in the child processes */
#if !defined(__SANITIZE_ADDRESS__)
    stderr_fd = open_memfd(MemfdCloseOnExec);
#endif

    // open log files for each main thread
    auto logopener = [](PerThreadData::Common *data, int) {
        data->log_fd = open_new_log();
    };
    for_each_main_thread(logopener);
    for_each_test_thread(logopener);

#ifdef __GLIBC__
    setenv("LIBC_FATAL_STDERR_", "1", true);
#endif
}

int logging_close_global(int exitcode)
{
    progress_bar_flush();
    if (!SandstoneConfig::NoLogging) {
        if (exitcode != EXIT_SUCCESS)
            logging_print_log_file_name();

        const char *exitline = [&] {
            switch (exitcode) {
            case EXIT_SUCCESS:
                if (sApp->shmem->cfg.verbosity >= 0)
                    return "pass";
                return (const char *)nullptr;
            case EXIT_FAILURE:
                return "fail";
            default:
                if (exitcode & EXIT_INTERRUPTED)
                    return "interrupted";
                [[fallthrough]];
            case EXIT_INVALID:
                return "invalid";
            }
        }();
        if (exitline)
            logging_printf(LOG_LEVEL_QUIET, "exit: %s\n", exitline);
    }
    if (exitcode == EXIT_SUCCESS && delete_log_on_success) {
        close(AbstractLogger::file_log_fd);
        remove(sApp->file_log_path.c_str());
    }

#ifndef NDEBUG
    // close all log files (in release mode, the OS closes for us)
    auto logcloser = [](PerThreadData::Common *data, int) {
        close(data->log_fd);
    };
    for_each_main_thread(logcloser);
    for_each_test_thread(logcloser);
#endif

    /* leak all file descriptors without closing, the application
     * is about to exit anyway */
    return exitcode;
}

void logging_print_log_file_name()
{
    if (AbstractLogger::real_stdout_fd == AbstractLogger::file_log_fd || AbstractLogger::file_log_fd == STDOUT_FILENO)
        return;
    switch (current_output_format()) {
    case SandstoneApplication::OutputFormat::key_value:
    case SandstoneApplication::OutputFormat::tap:
        dprintf(AbstractLogger::real_stdout_fd, "# More information logged to '%s'\n", sApp->file_log_path.c_str());
        break;

    case SandstoneApplication::OutputFormat::yaml:
        dprintf(AbstractLogger::real_stdout_fd, "%slog_file: '%s'\n", AbstractLogger::indent_spaces().data(), sApp->file_log_path.c_str());
        // timestamp in the iteration start
        break;

    case SandstoneApplication::OutputFormat::no_output:
        break;
    }
}

static std::string create_filtered_message_string(const char *fmt, va_list va)
{
    std::string s = vstdprintf(fmt, va);
    for (char &c : s) {
        // filter any non-US-ASCII character from the message
        // (this includes any non-terminating NUL)
        if (c < 0x20 || c > 0x7e) {
            if (c != '\n' && c != '\t')
                c = '?';
        }
    }
    return s;
}

// function must be async-signal-safe
void logging_mark_thread_failed(int thread_num) noexcept
{
    PerThreadData::Common *thr = sApp->thread_data(thread_num);
    if (thr->has_failed())
        return;

    // note: must use std::chrono::steady_clock here instead of
    // get_monotonic_time_now() because we'll compare to
    // sApp->current_test_starttime.
    thr->fail_time = std::chrono::steady_clock::now();
    if (thread_num >= 0) {
        auto tthr = static_cast<PerThreadData::Test *>(thr);
        tthr->inner_loop_count_at_fail = tthr->inner_loop_count;
    }
}

void logging_mark_thread_skipped(int thread_num) noexcept
{
    PerThreadData::Common *thr = sApp->thread_data(thread_num);
    if (thr->has_failed())
        return;

    // we set to a negative monotonic time to indicate a skip
    thr->fail_time = MonotonicTimePoint(Duration(-1));
}

void logging_run_callback()
{
    if (current_output_format() == SandstoneApplication::OutputFormat::no_output)
        return;
    if (thread_num < 0)
        return;     // callbacks don't apply to the main thread

    PerThreadData::Common *thr = sApp->thread_data(thread_num);
    if (thr->thread_flags & PerThreadData::Common::Flag::CallbackCalled)
        return;     // already done

    // make sure so we don't recurse in case the callback calls log_error()
    thr->thread_flags |= uint32_t(PerThreadData::Common::Flag::CallbackCalled);
    if (!SandstoneConfig::NoLogging && sApp->current_test_failure_callback.cb)
        sApp->current_test_failure_callback.cb(sApp->current_test_failure_callback.token);
}

static void log_message_preformatted(int thread_num, std::string_view msg)
{
    LogLevelVerbosity level = status_level(msg[0]);
    bool is_error = msg[0] == 'E';
    if (is_error)
        logging_mark_thread_failed(thread_num);

    log_message_preformatted(thread_num, level, msg);
    if (is_error)
        logging_run_callback();
}

void log_message_preformatted(int thread_num, LogLevelVerbosity level, std::string_view msg)
{
    if (current_output_format() == SandstoneApplication::OutputFormat::no_output)
        return;

    PerThreadData::Common *thread = sApp->thread_data(thread_num);
    std::atomic<int> &messages_logged = thread->messages_logged;
    if (level != LOG_LEVEL_QUIET &&
            messages_logged.load(std::memory_order_relaxed) >= sApp->shmem->cfg.max_messages_per_thread)
        return;

    if (msg[msg.size() - 1] == '\n')
        msg.remove_suffix(1);           // remove trailing newline

    log_message_for_thread(thread, LogTypes::UserMessages, level, msg);
}

static __attribute__((cold)) void log_message_to_syslog(const char *msg)
{
    // since logging to the system log is so infrequent, we initialize and tear
    // down every time.
    if (!sApp->syslog_ident)
        return;
#ifdef _WIN32
    // Advapi32's event log functionality is too complex for us to make use of
#else
    openlog(sApp->syslog_ident, LOG_CONS, LOG_DAEMON);
    syslog(LOG_ERR, "%s", msg);
    closelog();
#endif
}

#if SANDSTONE_NO_LOGGING
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security"
void logging_restricted(LogLevelVerbosity level, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    std::string msg = vstdprintf(fmt, va);
    va_end(va);

    if (msg.empty())
        return;

    progress_bar_flush();

    int fd = AbstractLogger::real_stdout_fd;
    if (level < 0)
        fd = STDERR_FILENO;

    writeln(fd, msg.c_str());

    if (level < 0)
        log_message_to_syslog(msg.c_str());
}
#pragma GCC diagnostic pop

#else

void logging_printf(LogLevelVerbosity level, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    std::string msg = create_filtered_message_string(fmt, va);
    va_end(va);

    if (msg.empty())
        return;     // can happen if fmt was "%s" and the string ended up empty

    if (level <= sApp->shmem->cfg.verbosity && AbstractLogger::file_log_fd != AbstractLogger::real_stdout_fd) {
        progress_bar_flush();
        int fd = AbstractLogger::real_stdout_fd;
        if (level < 0)
            fd = STDERR_FILENO;
        writevec(fd, AbstractLogger::indent_spaces(), msg);
    }

    int fd = AbstractLogger::file_log_fd;
    if (level < 0 && AbstractLogger::file_log_fd == AbstractLogger::real_stdout_fd)
        fd = STDERR_FILENO;         // no stderr logging above, so do it here

    // include the timestamp in each line, unless we're using YAML format
    // (timestamps are elsewhere there)
    if (current_output_format() != SandstoneApplication::OutputFormat::yaml) {
        writevec(fd, AbstractLogger::log_timestamp(), msg);
    } else {
        writevec(fd, AbstractLogger::indent_spaces(), msg);
    }

    if (level < 0)
        log_message_to_syslog(msg.c_str());
}
#endif /* SANDSTONE_NO_LOGGING */

static std::string kernel_info()
{
#ifdef _WIN32
    OSVERSIONINFOEXW osver = { .dwOSVersionInfoSize = sizeof(osver) };
    std::string s = "Windows";

    // try RtlGetVersion
    if (RtlGetVersion(reinterpret_cast<OSVERSIONINFOW *>(&osver)) == STATUS_SUCCESS) {
        if (osver.wProductType != VER_NT_WORKSTATION)
            s += " Server";
        if (wcslen(osver.szCSDVersion))
            s += stdprintf(" v%ld.%ld.%ld (%ls)", osver.dwMajorVersion, osver.dwMinorVersion,
                           osver.dwBuildNumber, osver.szCSDVersion);
        else
            s += stdprintf(" v%ld.%ld.%ld", osver.dwMajorVersion, osver.dwMinorVersion,
                           osver.dwBuildNumber);
    }
    return s;
#else
    struct utsname u;
    if (uname(&u) == 0)
        return stdprintf("%s %s", u.sysname, u.release);
#endif
    return {};
}

static std::string libc_info()
{
    std::string result;
#if __has_include(<gnu/libc-version.h>)
    result = std::string("glibc ") + gnu_get_libc_version();
#elif defined(_UCRT)
    // UCRT comes with Windows 10, so its version should match the OS
    result = "UCRT";
#elif defined(_WIN32)
    // I don't think MSVCRT has changed in since 1995
    result = "MSVCRT";
#else
    // on all other OSes, the libc comes with the OS, so its version should suffice
#endif

    if constexpr (SandstoneConfig::StaticLink)
        result += " (statically linked)";
    return result;
}

#if !SANDSTONE_SSL_BUILD
static std::string openssl_info()
{
    return {};
}
#endif

static std::string os_info()
{
    std::string os_info;
    std::string kernel = kernel_info();
    std::string libc = libc_info();
    std::string libssl = openssl_info();
    if (kernel.empty())
        return "<unknown>";
    os_info = std::move(kernel);
    if (!libc.empty())
        os_info += ", " + libc;
    if (!libssl.empty())
        os_info += ", " + libssl;

    return os_info;
}

static void print_reproduction_details()
{
    switch (current_output_format()) {
    case SandstoneApplication::OutputFormat::key_value:
        logging_printf(LOG_LEVEL_QUIET, "version = %s\n", AbstractLogger::program_version);
        logging_printf(LOG_LEVEL_QUIET, "current_time = %s\n", AbstractLogger::iso8601_time_now(Iso8601Format::WithMs));
        logging_printf(LOG_LEVEL_VERBOSE(1), "os = %s\n", os_info().c_str());
        return;

    case SandstoneApplication::OutputFormat::tap:
        logging_printf(LOG_LEVEL_QUIET, "# Built from git commit: %s\n", AbstractLogger::program_version);
        logging_printf(LOG_LEVEL_QUIET, "# Current time: %s\n", AbstractLogger::iso8601_time_now(Iso8601Format::WithMs));
        break;

    case SandstoneApplication::OutputFormat::yaml:
        logging_printf(LOG_LEVEL_QUIET, "version: %s\n", AbstractLogger::program_version);
        // timestamp in the iteration start
        break;

    case SandstoneApplication::OutputFormat::no_output:
        assert(false && "Shouldn't have reached here");
        __builtin_unreachable();
        break;
    }
}

void logging_print_version()
{
    printf("%s\n", AbstractLogger::program_version);
}

void logging_print_header(int argc, char **argv, ShortDuration test_duration, ShortDuration test_timeout)
{
    if (current_output_format() == SandstoneApplication::OutputFormat::no_output)
        return;                 // short-circuit

    std::string cmdline;
    if (argc > 0) {
        cmdline = argv[0];
#ifdef _WIN32
        size_t pos = cmdline.find_last_of('\\');
#else
        size_t pos = cmdline.find_last_of('/');
#endif
        if (pos != std::string::npos)
            cmdline = cmdline.substr(pos+1);
        for (int i = 1; i < argc; i++)
            cmdline += " " + std::string(argv[i]);
    }

    switch (current_output_format()) {
    case SandstoneApplication::OutputFormat::key_value:
        logging_printf(LOG_LEVEL_QUIET, "command_line = %s\n", cmdline.data());
        print_reproduction_details();
        break;

    case SandstoneApplication::OutputFormat::tap:
        logging_printf(LOG_LEVEL_QUIET, "# %s\n", cmdline.data());
        logging_printf(LOG_LEVEL_VERBOSE(1), "# %s; Operating system: %s\n",
                       AbstractLogger::program_version, os_info().c_str());
        logging_printf(LOG_LEVEL_VERBOSE(2), "# Target test duration is %s per test, timeout %s\n",
                       format_duration(test_duration, FormatDurationOptions::WithUnit).c_str(),
                       format_duration(test_timeout, FormatDurationOptions::WithUnit).c_str());
        break;

    case SandstoneApplication::OutputFormat::yaml:
        YamlLogger::print_header(cmdline, test_duration, test_timeout);
        break;

    case SandstoneApplication::OutputFormat::no_output:
        break;
    }
}

void logging_print_iteration_start()
{
    if (current_output_format() == SandstoneApplication::OutputFormat::no_output)
        return;                 // short-circuit

    std::string random_seed = random_format_seed();
    switch (sApp->shmem->cfg.output_format) {
    case SandstoneApplication::OutputFormat::key_value:
        return logging_printf(LOG_LEVEL_QUIET, "random_generator_state = %s\n", random_seed.c_str());
    case SandstoneApplication::OutputFormat::tap:
    case SandstoneApplication::OutputFormat::yaml:
        return;
    case SandstoneApplication::OutputFormat::no_output:
        return;
    }
}

void logging_print_footer()
{
    switch (current_output_format()) {
    case SandstoneApplication::OutputFormat::key_value:
    case SandstoneApplication::OutputFormat::tap:
        return print_reproduction_details();

    case SandstoneApplication::OutputFormat::yaml:
        // produces malformed YAML if we print the same information again
    case SandstoneApplication::OutputFormat::no_output:
        return;
    }
}

void logging_flush(void)
{
    if (current_output_format() == SandstoneApplication::OutputFormat::no_output)
        return;                 // short-circuit

    auto do_flush = [](int fd) {
        if (fd < 0)
            return;
#if defined(_POSIX_SYNCHRONIZED_IO) && _POSIX_SYNCHRONIZED_IO > 0
        IGNORE_RETVAL(fdatasync(fd));
#elif defined(_WIN32)
        FlushFileBuffers(HANDLE(_get_osfhandle(fd)));
#endif
    };

    // we don't need to fflush() because all our log files are opened without
    // buffering
    do_flush(AbstractLogger::file_log_fd);
    do_flush(sApp->main_thread_data()->log_fd);
}

void logging_init(const struct test *test)
{
    sApp->current_test_failure_callback = {};
    if (sApp->shmem->cfg.verbosity <= 0)
        progress_bar_update();

    switch (current_output_format()) {
    case SandstoneApplication::OutputFormat::key_value:
    case SandstoneApplication::OutputFormat::tap:
        logging_printf(LOG_LEVEL_VERBOSE(2), "# Executing test %s '%s'\n", test->id, test->description);
        logging_printf(LOG_LEVEL_VERBOSE(2), "# Seed: %s \n", random_format_seed().c_str());
        break;
    case SandstoneApplication::OutputFormat::yaml:
        YamlLogger::print_tests_header(YamlLogger::AtStart);
        logging_printf(LOG_LEVEL_VERBOSE(1), "- test: %s\n", test->id);
        logging_printf(LOG_LEVEL_VERBOSE(3), "  details: { quality: %s, description: \"%s\" }\n",
                       YamlLogger::quality_string(test), test->description);
        logging_printf(LOG_LEVEL_VERBOSE(3), "  state: { seed: '%s', iteration: %d, retry: %s }\n",
                       random_format_seed().c_str(), abs(sApp->current_iteration_count),
                       sApp->current_iteration_count < 0 ? "true" : "false");
        logging_printf(LOG_LEVEL_VERBOSE(2), "  time-at-start: %s\n", YamlLogger::get_current_time().c_str());
        break;
    case SandstoneApplication::OutputFormat::no_output:
        return;                 // short-circuit
    }

    logging_flush();
}

void logging_init_child_preexec()
{
    if (stderr_fd != -1)
        dup2(stderr_fd, STDERR_FILENO);
}

void logging_finish()
{
}

static inline void assert_log_message(const char *fmt)
{
    assert(fmt);
    assert(fmt[0] == 'd' || fmt[0] == 'I' || fmt[0] == 'W' || fmt[0] == 'E');
    assert(fmt[1] == '>');
    assert(fmt[2] == ' ');
    (void)fmt;  // for release builds
}

#undef log_platform_message
void log_platform_message(const char *fmt, ...)
{
    if (current_output_format() == SandstoneApplication::OutputFormat::no_output)
        return;

    assert_log_message(fmt);
    if (!SandstoneConfig::Debug && *fmt == 'd')
        return;         /* no Debug in non-debug build */
    va_list va;
    va_start(va, fmt);
    std::string msg = create_filtered_message_string(fmt, va);
    va_end(va);

    // Insert prefix and log to main thread
    msg.insert(3, "Platform issue: ");
    log_message_preformatted(-1, msg);
}

#undef log_message_skip
void log_message_skip(int thread_num, SkipCategory category, const char *fmt, ...)
{
    logging_mark_thread_skipped(thread_num);
    if (current_output_format() == SandstoneApplication::OutputFormat::no_output)
        return;

    va_list va;
    va_start(va, fmt);
    std::string msg = create_filtered_message_string(fmt, va);
    va_end(va);

    msg.insert(msg.begin(), category);

    if (msg[msg.size() - 1] == '\n')
        msg.pop_back(); // remove trailing newline

    PerThreadData::Common *thread = sApp->thread_data(thread_num);
    log_message_for_thread(thread, LogTypes::SkipMessages, LOG_LEVEL_VERBOSE(1), msg);
}

#undef log_message
void log_message(int thread_num, const char *fmt, ...)
{
    if (current_output_format() == SandstoneApplication::OutputFormat::no_output)
        return;

    assert_log_message(fmt);
    if (!SandstoneConfig::Debug && *fmt == 'd')
        return;         /* no Debug in non-debug build */
    va_list va;
    va_start(va, fmt);
    std::string msg = create_filtered_message_string(fmt, va);
    va_end(va);
    log_message_preformatted(thread_num, msg);
}

#if SANDSTONE_NO_LOGGING == 0
void install_failure_callback(void (*cb)(void *), void *token)
{
    assert(thread_num < 0 && "callbacks can only be installed from the main thread");
    sApp->current_test_failure_callback.token = token;
    sApp->current_test_failure_callback.cb = cb;
}
#endif

/// Escapes \c{message} suitable for a single-quote YAML line and returns it.
/// The \c{storage} parameter is used in case we need to do escaping.
/// (This could've been a std::variant<std::string, std::string_view>)
static std::string_view escape_for_single_line(std::string_view message, std::string &storage)
{
    const char quote = '\'';
    size_t pos = message.find(quote);
    if (pos == std::string_view::npos)
        return message;

    // Message contains apostrophes, so we need to double the single
    // quotes. Do that by looping over the string copying it in chunks
    // delimited by apostrophes, with the apostrophes being copied twice
    // (that means we're inefficient for back-to-back apostrophes, but
    // that's not common English text)
    storage.resize(0);          // just in case
    storage.reserve(message.size() + message.size() / 16);  // 1/16th is guesstimate

    while (pos != std::string_view::npos) {
        storage += message.substr(0, pos + 1);
        message.remove_prefix(pos);
        pos = message.find(quote, 1);
    }

    storage += message;     // copy the last chunk (if any)
    return storage;
}

static std::string_view escape_for_single_line(std::string_view msg, std::string &&storage = {})
{
    return escape_for_single_line(msg, storage);
}

static void log_data_common(const char *message, const uint8_t *ptr, size_t size, bool from_memcmp)
{
    std::string spaces;
    std::string buffer;

    switch (current_output_format()) {
    case SandstoneApplication::OutputFormat::yaml:
        spaces.resize(sApp->shmem->cfg.output_yaml_indent + 4 + (from_memcmp ? 3 : 0), ' ');
        if (from_memcmp) {
            // no escaping, the message is proper YAML
            buffer = message;
        } else {
            // need to escape message from user
            std::string storage;
            std::string_view escaped = escape_for_single_line(message, storage);
            buffer = stdprintf("%s- level: info\n"
                               "%s  text: '%.*s'\n"
                               "%s  data:",     // no newline
                               spaces.c_str(),
                               spaces.c_str(), int(escaped.length()), escaped.data(),
                               spaces.c_str());
            spaces += "  ";     // two more spaces
        }
        break;

    case SandstoneApplication::OutputFormat::tap:
        if (!from_memcmp)
            buffer = "  - >-\n";
        [[fallthrough]];

    case SandstoneApplication::OutputFormat::key_value:
        spaces.resize(4 + (from_memcmp ? 1 : 0), ' ');
        buffer += spaces;
        buffer += "data(";
        buffer += message;
        buffer += ')';
        break;

    case SandstoneApplication::OutputFormat::no_output:
        assert(false && "Shouldn't have reached here");
        __builtin_unreachable();
        break;
    }

    spaces = '\n' + std::move(spaces);
    for (size_t i = 0; i < size; ++i) {
        if (current_output_format() != SandstoneApplication::OutputFormat::key_value) {
            if ((i % 32) == 0)
                buffer += spaces;
            else if ((i % 16) == 0)
                buffer += "  ";
            else if ((i % 4) == 0)
                buffer += ' ';
        }
        buffer += stdprintf(" %02x", (unsigned)ptr[i]);
    }
    buffer += '\n';

    // data logging is informational (verbose level 2)
    PerThreadData::Common *thread = sApp->thread_data(thread_num);
    log_message_for_thread(thread, LogTypes::Preformatted, LOG_LEVEL_VERBOSE(2), buffer);
}

#undef log_data
void log_data(const char *message, const void *data, size_t size)
{
    if (current_output_format() == SandstoneApplication::OutputFormat::no_output)
        return;                 // short-circuit

    PerThreadData::Common *thread = sApp->thread_data(thread_num);
    std::atomic<int> &messages_logged = thread->messages_logged;
    std::atomic<unsigned> &data_bytes_logged = thread->data_bytes_logged;
    if (messages_logged.load(std::memory_order_relaxed) >= sApp->shmem->cfg.max_messages_per_thread)
        return;
    if (data_bytes_logged.fetch_add(size, std::memory_order_relaxed) > sApp->shmem->cfg.max_logdata_per_thread)
        return;

    log_data_common(message, static_cast<const uint8_t *>(data), size, false);
}

static void logging_format_data(DataType type, std::string_view description, const uint8_t *data1,
                                const uint8_t *data2, ptrdiff_t offset)
{
    // see format_and_print_raw_yaml() for the line protocol
    std::string buffer = "data-miscompare:\n\n";
    auto formatAddresses = [&](const uint8_t *ptr) {
        std::string result = stdprintf("address:     '%p'\n", ptr);
        if (uint64_t physaddr = retrieve_physical_address(ptr)) {
            // 2^48-1 requires 12 hex digits
            result += stdprintf("physical:    '%#012" PRIx64 "'\n", physaddr);
        }
        return result;
    };

    buffer += "description: '";
    buffer += description;
    buffer += "'\ntype:        ";

    const char *typeName = SandstoneDataDetails::type_name(type);
    if (!typeName) {
        // also a validity check
        type = UInt8Data;
        typeName = SandstoneDataDetails::type_name(type);
    }
    buffer += typeName;
    buffer += '\n';

    if (offset >= 0) {
        // typical case
        int typeSize = SandstoneDataDetails::type_real_size(type);
        unsigned typeAlignment = SandstoneDataDetails::type_alignment(type);

        // The offset may not be the first byte of the data, so realign it
        ptrdiff_t alignedOffset = offset & ~(typeAlignment - 1);

        // create an XOR mask
        uint8_t xormask[SandstoneDataDetails::MaxDataTypeSize];
        for (int i = 0; i < typeSize; ++i)
            xormask[i] = data1[alignedOffset + i] ^ data2[alignedOffset + i];

        buffer += stdprintf("offset:      [ %td, %td ]\n",
                            alignedOffset, offset - alignedOffset);
        buffer += formatAddresses(data1 + offset);
        buffer += stdprintf("actual:      '0x%s'\n"
                            "expected:    '0x%s'\n"
                            "mask:        '0x%s'",
                            format_single_type(type, typeSize, data1 + alignedOffset, true).c_str(),
                            format_single_type(type, typeSize, data2 + alignedOffset, true).c_str(),
                            format_single_type(type, typeSize, xormask, false).c_str());
    } else {
        // no difference was found: memcmp_offset() disagrees with memcmp_or_fail()
        buffer += "offset:      null\n";
        buffer += formatAddresses(data1);
        buffer += "actual:      null\n"
                  "expected:    null\n"
                  "mask:        null\n"
                  "remark:      'memcmp_offset() could not locate difference'";
    }

    PerThreadData::Common *thread = sApp->thread_data(thread_num);
    log_message_for_thread(thread, LogTypes::RawYaml, LOG_LEVEL_QUIET, buffer);
}

void logging_report_mismatched_data(DataType type, const uint8_t *actual, const uint8_t *expected,
                                    size_t size, ptrdiff_t offset, const char *fmt, va_list va)
{
    logging_mark_thread_failed(thread_num);
    if (current_output_format() == SandstoneApplication::OutputFormat::no_output)
        return;

    {
        // create the description of what failed
        std::string description, escaped_description;
        if (fmt && *fmt)
            description = vstdprintf(fmt, va);

        logging_format_data(type, escape_for_single_line(description, escaped_description),
                            actual, expected, offset);
    }
    if (offset < 0) {
        // we couldn't find a difference
        logging_run_callback();
        return;
    }

    // Log the data that failed. We have two buffers of size bytes to log, but
    // we'll obey the max_logdata_per_thread limit (shared with log_data()).
    // Note: this didn't need to be atomic...
    //   size_t avail = sApp->shmem->cfg.max_logdata_per_thread - bytes_logged;
    //   size_t len = std::min(size, avail / 2);
    auto &bytes_logged = sApp->thread_data(thread_num)->data_bytes_logged;
    size_t len = size;
    if (size_t old_total = bytes_logged.fetch_add(2 * size, std::memory_order_relaxed);
            sApp->shmem->cfg.max_logdata_per_thread - old_total < 2 * size) {
        // trim how much data we'll print so we stick to the limit
        len = (sApp->shmem->cfg.max_logdata_per_thread - old_total) / 2;
    }

    ptrdiff_t start;
    if (offset < len) {
        start = 0;
        if (len > size)
            len = size;
    } else if (offset >= size - len) {
        start = size - len;
    } else {
        start = offset - len / 2;
    }

    auto do_log_data = [=](const char *name, const uint8_t *which) {
        std::string message;
        if (current_output_format() == SandstoneApplication::OutputFormat::yaml) {
            // we're skipping the start byte offset, hopefully we won't miss it
            message = stdprintf("%s       %s data:",
                                AbstractLogger::indent_spaces().data(), name);
        } else {
            message = stdprintf("Bytes %td..%td of %s", start, start + len - 1, name);
        }
        log_data_common(message.c_str(), which + start, len, true);
    };
    do_log_data("actual", actual);
    do_log_data("expected", expected);
    logging_run_callback();
}

#undef log_yaml
void log_yaml(char levelchar, const char *yaml)
{
    LogLevelVerbosity level = status_level(levelchar);
    if (levelchar == 'E')
        logging_mark_thread_failed(thread_num);
    if (!SandstoneConfig::Debug && levelchar == 'd')
        return;             // no Debug in non-debug build
    if (current_output_format() == SandstoneApplication::OutputFormat::no_output)
        return;             // short-circuit

    PerThreadData::Common *thread = sApp->thread_data(thread_num);
    std::atomic<int> &messages_logged = thread->messages_logged;
    if (messages_logged.load(std::memory_order_relaxed) >= sApp->shmem->cfg.max_messages_per_thread)
        return;

    log_message_for_thread(thread, LogTypes::RawYaml, level, '\n', yaml);
    if (levelchar == 'E')
        logging_run_callback();
}

void logging_mark_knob_used(std::string_view key, TestKnobValue value, KnobOrigin origin)
{
    if (current_output_format() == SandstoneApplication::OutputFormat::no_output)
        return;             // short-circuit

#ifndef NDEBUG
    if (thread_num != -1) {
        fprintf(stderr, "### Internal error: get_test_knob_value_xxx() called from outside the main thread!\n"
                        "### Fix this test! Test option values are only allowed in the init() function.\n");
        abort();
    }

    // ensure the key requires no escaping
    if (key.find_first_not_of(".-_0123456789"
                              "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                              "abcdefghijklmnopqrstuvwxyz") != std::string_view::npos) {
        fprintf(stderr, "### Internal error: key used in get_test_knob_value_xxx() is not a simple string!\n"
                        "### Fix this test! Test option keys must letters, digits, hyphen, underscore and dot.\n");
        abort();
    }
#endif

    if (!sApp->shmem->cfg.log_test_knobs)
        return;

    struct Visitor {
        std::string operator()(uint64_t v)
        {
            if (v < 4096)
                return stdprintf("%u", unsigned(v));
            else
                return stdprintf("0x%" PRIx64, v);
        }
        std::string operator()(int64_t v)
        {
            if (v >= 0)
                return operator()(uint64_t(v));
            else if (v >= -4096)
                return stdprintf("%d", int(v));
            else
                return stdprintf("-0x%" PRIx64, -v);
        }
        std::string operator()(double v)
        {
            return stdprintf("%.17g", double(v));
        }
        std::string operator()(std::string_view v)
        {
            if (v.data() == nullptr) {
                return "null";
            } else {
                return stdprintf("'%s'", escape_for_single_line(v).data());
            }
        }
    };
    std::string formatted = std::visit(Visitor{}, value);
    PerThreadData::Common *thread = sApp->thread_data(thread_num);
    log_message_for_thread(thread, LogTypes::UsedKnobValue, UsedKnobValueLoggingLevel,
                           key, ": ", formatted);
}

static void print_content_indented(int fd, std::string_view indent, std::string_view content)
{
    const char *line = content.data();
    const char *end = line + content.size();
    while (line <= end) {
        const char *newline = strnchr(line, '\n', end - line);
        if (!newline)
            newline = end;

        writevec(fd, AbstractLogger::indent_spaces(), indent, std::string_view(line, newline - line), '\n');
        line = newline + 1;
    }
}

/// Prints the content suitable for a single-quote YAML line
/// (quotes must be supplied in \c{before} and \c{after}
static void print_content_single_line(int fd, std::string_view before,
                                      std::string_view message,
                                      std::string_view after)
{
    writeln(fd, before, escape_for_single_line(message), after);
}

std::string AbstractLogger::get_skip_message(int thread_num)
{
    std::string skip_message;
    LogMessagesFile msgs(sApp->thread_data(thread_num)->log_fd);
    for (const LogMessage &msg : msgs) {
        if (msg.type == LogTypes::SkipMessages) {
            skip_message.assign(msg);
            break;
        }
    }
    return skip_message;
}

static std::string_view format_skip_message(std::string_view message)
{
    // skip messages contain a byte with the category identifier that we must
    // not print
    return message.substr(1);
}

static void format_and_print_raw_yaml(int fd, LogLevelVerbosity message_level, std::string_view message)
{
    assert(size_t(message_level) < std::size(levels));
    while (message.ends_with('\n'))
        message.remove_suffix(1);       // remove trailing newline

    int indent = sApp->shmem->cfg.output_yaml_indent + 2;
    if (current_output_format() == SandstoneApplication::OutputFormat::yaml)
        indent += 2;    // under "messages:"

    std::string buffer(indent, ' ');
    buffer += "- level: ";
    buffer += levels[size_t(message_level)];
    buffer += '\n';
    indent += 2;

    // the first line is the heading; for log_yaml(), it's always "details:"
    std::string_view heading = "details:\n";
    ptrdiff_t nl = message.find('\n');
    assert(nl >= 0);
    if (nl)
        heading = message.substr(0, nl + 1);    // include the newline
    message.remove_prefix(nl + 1);

    // the second line is the optional description for "text:"
    nl = message.find('\n');
    assert(nl >= 0);
    if (nl) {
        buffer.append(indent, ' ');
        buffer += "text: '";
        buffer += escape_for_single_line(message.substr(0, nl));
        buffer += "'\n";
    }
    message.remove_prefix(nl + 1);

    buffer.append(indent, ' ');
    buffer += heading;

    indent += 1; // nest inside "details:"
    nl = message.find('\n');
    while (nl >= 0) {
        buffer.append(indent, ' ');

        // write the newline too
        ++nl;
        buffer += message.substr(0, nl);
        message.remove_prefix(nl);
        nl = message.find('\n');
    }
    buffer.append(indent, ' ');
    buffer += message;
    buffer += '\n';
    writevec(fd, buffer);
}

void AbstractLogger::format_and_print_message(int fd, std::string_view message, bool from_thread_message)
{
    if (message.find('\n') != std::string_view::npos) {
        /* multi line */
        if (from_thread_message) // are you writing individual thread's message?
            writeln(fd, "  - |");
        else                     // are you writing init thread's message?
            writeln(fd, "\n", indent_spaces(), " - |");
        print_content_indented(fd, "    ", message);
    } else {
        /* single line */
        if (from_thread_message) { // are you writing individual thread's message?
            char c = '\'';
            print_content_single_line(fd, "   - '", message, std::string_view(&c, 1));
        } else { // are you writing init thread's message?
            print_content_single_line(fd, "'", message, "'");
        }
    }
}

/// Returns the lowest priority found
/// (this function is shared between the TAP and key-value pair loggers)
LogLevelVerbosity
AbstractLogger::print_one_thread_messages_tdata(int fd, PerThreadData::Common *data,
                                                const LogMessagesFile &msgs, LogLevelVerbosity level)
{
    LogLevelVerbosity lowest_level = LogLevelVerbosity::Max;
    for (const LogMessage &msg : msgs) {
        LogLevelVerbosity message_level = msg.verbosity;
        if (message_level > level)
            continue;

        std::string_view message = msg;
        switch (msg.type) {
        case LogTypes::UserMessages:
            format_and_print_message(fd, message, true);
            break;

        case LogTypes::RawYaml:
            format_and_print_raw_yaml(fd, message_level, message);
            break;

        case LogTypes::Preformatted:
            IGNORE_RETVAL(writevec(fd, message));
            break;

        case LogTypes::SkipMessages:
            if (!skipInMainThread) {
                // Only print if the result line didn't already include this
                format_and_print_message(fd, format_skip_message(message), true);
            }
            break;

        case LogTypes::UsedKnobValue: {
            static bool warning_printed = false;
            if (!warning_printed) {
                static const char msg[] = "# One or more tests used test options. Logging only in YAML.\n";
                warning_printed = true;
                IGNORE_RETVAL(write(fd, msg, strlen(msg)));
                if (fd != real_stdout_fd)
                    IGNORE_RETVAL(write(real_stdout_fd, msg, strlen(msg)));
            }
            continue;   // not break
        }
        }

        if (message_level < lowest_level)
            lowest_level = message_level;
    }

    return lowest_level;
}

void AbstractLogger::print_child_stderr_common(std::function<void(int)> header)
{
    struct mmap_region r = mmap_file(stderr_fd);
    if (r.size == 0)
        return;

    char indent[] = "    ";
    std::string_view contents(static_cast<const char *>(r.base), r.size);

    header(AbstractLogger::file_log_fd);
    print_content_indented(AbstractLogger::file_log_fd, indent, contents);
    if (AbstractLogger::file_log_fd != AbstractLogger::real_stdout_fd && sApp->shmem->cfg.verbosity > 0) {
        header(AbstractLogger::real_stdout_fd);
        print_content_indented(AbstractLogger::real_stdout_fd, indent, contents);
    }
    munmap_file(r);

    /* reset it for the next iteration */
    truncate_log(stderr_fd);
}

static ChildExitStatus find_most_serious_result(std::span<const ChildExitStatus> results)
{
    auto comparator = [](const ChildExitStatus &s1, const ChildExitStatus &s2) {
        return s1.result < s2.result;
    };
    return *std::max_element(results.begin(), results.end(), comparator);
}

inline AbstractLogger::AbstractLogger(const struct test *test, std::span<const ChildExitStatus> state_)
    : test(test),
      slices(state_),
      childExitStatus(find_most_serious_result(state_)),
      testResult(childExitStatus.result)
{
    // check that most serious result
    switch (testResult) {
    case TestResult::Skipped:
        skipInMainThread = true;
        break;

    case TestResult::Passed:
        // normal condition
        break;

    case TestResult::Failed:
        // test's test_init() failed. That's usually not supposed to happen...
        return;

    case TestResult::TimedOut:
        // find stuck threads and insert error message
        for_each_test_thread([](PerThreadData::Test *data, int i) {
            ThreadState thr_state = data->thread_state.load(std::memory_order_relaxed);
            if (thr_state == thread_running)
                log_message(i, SANDSTONE_LOG_ERROR "Thread is stuck");
        });
        return;

    case TestResult::CoreDumped:
    case TestResult::Killed:
    case TestResult::OperatingSystemError:
    case TestResult::OutOfMemory:
    case TestResult::Interrupted:
        // child process had serious problems
        return;
    }

    // scan the threads for their state
    int sc = 0;
    auto message_checker = [&](PerThreadData::Common *data, int i) {
        ThreadState thr_state = data->thread_state.load(std::memory_order_relaxed);
        if (data->has_failed()) {
            earliest_fail = std::min(earliest_fail, data->fail_time);
            testResult = TestResult::Failed;
        } else if (i >= 0) {
            // thread passed test. Don't count main thread results.
            ++pc;
            if (thr_state == thread_skipped) ++sc;
        }
    };
    for_each_main_thread(message_checker, slices.size());
    for_each_test_thread(message_checker);

    if (testResult == TestResult::Passed && pc == sc)
        testResult = TestResult::Skipped;       // all threads skipped
}

LogLevelVerbosity AbstractLogger::loglevel() const
{
    switch (testResult) {
    case TestResult::Skipped:
        return sApp->fatal_skips ? LOG_LEVEL_QUIET : LOG_LEVEL_VERBOSE(1);
    case TestResult::Passed:
        return LOG_LEVEL_VERBOSE(1);
    case TestResult::Failed:
    case TestResult::CoreDumped:
    case TestResult::Killed:
    case TestResult::OperatingSystemError:
    case TestResult::TimedOut:
    case TestResult::OutOfMemory:
    case TestResult::Interrupted:
        return LOG_LEVEL_QUIET;
    }
    __builtin_unreachable();
}

bool AbstractLogger::should_print_fail_info() const
{
    switch (testResult) {
    case TestResult::Skipped:
    case TestResult::Passed:
        return false;
    case TestResult::Failed:
    case TestResult::CoreDumped:
    case TestResult::Killed:
    case TestResult::OperatingSystemError:
    case TestResult::TimedOut:
    case TestResult::OutOfMemory:
        return true;
    case TestResult::Interrupted:
        return false;
    }
    __builtin_unreachable();
}

[[gnu::pure]] const char *AbstractLogger::crash_reason(const ChildExitStatus &status)
{
    assert(status.result != TestResult::Passed);
    assert(status.result != TestResult::Skipped);
    assert(status.result != TestResult::Failed);
    assert(status.result != TestResult::TimedOut);
    assert(status.result != TestResult::Interrupted);
#ifdef _WIN32
    return status_code_to_string(status.extra);
#else
    return strsignal(status.extra);
#endif
}

[[gnu::pure]] const char *AbstractLogger::sysexit_reason(const ChildExitStatus &status)
{
    assert(status.result == TestResult::OperatingSystemError);
    switch (status.extra) {
    case EXIT_NOTINSTALLED: return "the program is not installed.";
    case EX_USAGE:      return "command line usage error";
    case EX_DATAERR:    return "data format error";
    case EX_NOINPUT:    return "cannot open input";
    case EX_NOUSER:     return "addressee unknown";
    case EX_NOHOST:     return "host name unknown";
    case EX_UNAVAILABLE:return "service unavailable";
    case EX_SOFTWARE:   return "internal software error";
    case EX_OSERR:      return "system error"; // "(e.g., can't fork)";
    case EX_OSFILE:     return "critical OS file missing";
    case EX_CANTCREAT:  return "can't create (user) output file";
    case EX_IOERR:      return "input/output error";
    case EX_TEMPFAIL:   return "temporary failure";
    case EX_PROTOCOL:   return "remote error in protocol";
    case EX_NOPERM:     return "permission denied";
    case EX_CONFIG:     return "configuration error";
    case EXIT_MEMORY:   return "failed to perform an action due to memory shortage.";
    }
    return "unknown error";
}

/// builds the fail info message (including newline)
/// returns an empty string if there was no failure
std::string YamlLogger::fail_info_details()
{
    std::string result;
    if (!should_print_fail_info())
        return result;

    auto add_value = [&result](const std::string &s, char separator) {
        if (s.empty()) {
            result += "null";
        } else if (!separator) {
            result += s;
        } else {
            result += separator;
            result += s;
            result += separator;
        }
    };

    std::string seed = random_format_seed();
    std::string time = format_duration(earliest_fail, FormatDurationOptions::WithoutUnit);
    std::string fail_mask = build_failure_mask_for_topology(test);

    result.reserve(strlen("  fail: { cpu-mask: '', time-to-fail: , seed: '' }\n") +
                   seed.size() + time.size() + fail_mask.size());
#if SANDSTONE_DEVICE_CPU
    result += "  fail: { cpu-mask: ";
#else
    result += "  fail: { dev-mask: "; // keep it 3 letters
#endif
    add_value(fail_mask, '\'');
    result += ", time-to-fail: ";
    add_value(time, '\0');
    result += ", seed: ";
    add_value(seed, '\'');
    result += "}\n";
    return result;
}

void YamlLogger::maybe_print_messages_header(int fd)
{
    bool *hdr = (fd == file_log_fd ? &file_printed_messages_header : &stdout_printed_messages_header);
    if (!*hdr) {
        writeln(fd, indent_spaces(), "  threads:");
        *hdr = true;
    }
}

void YamlLogger::print_thread_header(int fd, int device, LogLevelVerbosity verbosity)
{
    maybe_print_messages_header(fd);
    if (device < 0) {
        device = ~device;
        if (device == 0)
            writeln(fd, indent_spaces(), "  - thread: main");
        else
            writeln(fd, indent_spaces(), "  - thread: main ", std::to_string(device));
        maybe_print_slice_resource_usage(fd, device);
    } else {
        dprintf(fd, "%s  - thread: %d\n", indent_spaces().data(), device);
        dprintf(fd, "%s    id: %s\n", indent_spaces().data(), thread_id_header_for_device(device, verbosity).c_str());

        if (verbosity > 1) {
            PerThreadData::Test *thr = sApp->test_thread_data(device);
            auto opts = FormatDurationOptions::WithoutUnit;
            if (std::string time = format_duration(thr->fail_time, opts); time.size()) {
                writeln(fd, indent_spaces(), "    state: failed");
                writeln(fd, indent_spaces(), "    time-to-fail: ", time);
                writeln(fd, indent_spaces(), "    loop-count: ",
                        std::to_string(thr->inner_loop_count_at_fail));
            } else if (verbosity > 2) {
                writeln(fd, indent_spaces(), "    loop-count: ",
                        std::to_string(thr->inner_loop_count));
            }
            print_thread_header_for_device(fd, thr);
        }
    }
    writeln(fd, indent_spaces(), "    messages:");
}

bool YamlLogger::want_slice_resource_usage(int slice)
{
    switch (slices[slice].result) {
    case TestResult::Skipped:
    case TestResult::Passed:
    case TestResult::Failed:
    case TestResult::OperatingSystemError:
        return sApp->shmem->cfg.verbosity >= 3;

    case TestResult::Killed:
    case TestResult::CoreDumped:
    case TestResult::OutOfMemory:
    case TestResult::TimedOut:
    case TestResult::Interrupted:
        break;
    }
    return true;
}

void YamlLogger::maybe_print_slice_resource_usage(int fd, int slice)
{
    using ::format_duration;
    if (!want_slice_resource_usage(slice))
        return;

    auto runtime = slices[slice].endtime - sApp->current_test_starttime;
    writeln(fd, indent_spaces(), "    runtime: ", format_duration(runtime, FormatDurationOptions::WithoutUnit));

    using namespace std::chrono;
    const struct rusage &usage = slices[slice].usage;
    auto utime = seconds(usage.ru_utime.tv_sec) + microseconds(usage.ru_utime.tv_usec);
    auto stime = seconds(usage.ru_stime.tv_sec) + microseconds(usage.ru_stime.tv_usec);
    dprintf(fd, "%s    resource-usage: { utime: %s, stime: %s, cpuavg: %.1f, maxrss: %lld, majflt: %lld"
#ifndef _WIN32
                ", minflt: %lld, voluntary-cs: %lld, involutary-cs: %lld"
#endif
                " }\n",
            indent_spaces().data(),
            format_duration(utime, FormatDurationOptions::WithoutUnit).c_str(),
            format_duration(stime, FormatDurationOptions::WithoutUnit).c_str(),
            (utime + stime) * 100.0 / runtime,
            (long long)usage.ru_maxrss, (long long)usage.ru_majflt
#ifndef _WIN32
            , (long long)usage.ru_minflt, (long long)usage.ru_nvcsw, (long long)usage.ru_nivcsw
#endif
            );
}

int YamlLogger::print_test_knobs(int fd, const LogMessagesFile &msgs)
{
    std::unordered_set<std::string_view> seen_keys;
    int print_count = 0;
    for (const LogMessage &msg : msgs) {
        if (msg.type != LogTypes::UsedKnobValue)
            continue;

        if (print_count++ == 0)
            writeln(fd, indent_spaces(), "  test-options:");

        std::string_view message = msg;
        size_t colon = message.find(':');
        assert(colon != std::string_view::npos);

        // check if we've already printed this key or not
        std::string_view key = message.substr(0, colon);
        if (auto [it, inserted] = seen_keys.insert(key); inserted)
            writeln(fd, indent_spaces(), "    ", message);
    }

    return print_count;
}

void YamlLogger::format_and_print_message(int fd, std::string_view level, std::string_view message)
{
    if (message.find('\n') != std::string_view::npos) {
        /* multi line */
        // trim a trailing newline, if any (just one)
        if (message[message.size() - 1] == '\n')
            message.remove_suffix(1);

        writeln(fd, indent_spaces(), "    - level: ", level);
        writeln(fd, indent_spaces(), "      text: |1");
        print_content_indented(fd, "       ", message);
    } else {
        /* single line */
        writevec(fd, indent_spaces(), "    - { level: ", level);
        print_content_single_line(fd, ", text: '", message, "' }");
    }
}

void YamlLogger::format_and_print_skip_reason(int fd, std::string_view message)
{
    if (message.find('\n') != std::string_view::npos) {
        /* multi line */
        writeln(fd, indent_spaces(), "  skip-reason: |1");
        print_content_indented(fd, "   ", message);
    } else {
        writevec(fd, indent_spaces());
        print_content_single_line(fd, "  skip-reason: '", message, "'");
    }
}

inline LogLevelVerbosity
YamlLogger::print_one_thread_messages(int fd, const LogMessagesFile &msgs, LogLevelVerbosity level)
{
    LogLevelVerbosity lowest_level = LogLevelVerbosity::Max;
    for (const LogMessage &msg : msgs) {
        LogLevelVerbosity message_level = msg.verbosity;
        if (message_level > level)
            continue;

        std::string_view message = msg;
        if (message.empty())
            continue;       // shouldn't happen...

        switch (msg.type) {
        case LogTypes::UserMessages:
            assert(size_t(message_level) < std::size(levels));
            format_and_print_message(fd, levels[size_t(message_level)], message);
            break;

        case LogTypes::RawYaml:
            assert(size_t(message_level) < std::size(levels));
            format_and_print_raw_yaml(fd, message_level, message);
            break;

        case LogTypes::Preformatted:
            IGNORE_RETVAL(write(fd, message.data(), message.size()));
            break;

        case LogTypes::SkipMessages:
            if (!skipInMainThread) {
                // Only print if the result line didn't already include this
                format_and_print_message(fd, "skip", format_skip_message(message));
            }
            break;

        case LogTypes::UsedKnobValue:
            assert(sApp->shmem->cfg.log_test_knobs);
            continue;       // not break
        }

        if (message_level < lowest_level)
            lowest_level = message_level;
    }

    return lowest_level;
}

void YamlLogger::print_result_line(int &init_skip_message_bytes)
{
    LogLevelVerbosity loglevel = this->loglevel();
    if (loglevel == LOG_LEVEL_QUIET && file_log_fd != real_stdout_fd && sApp->shmem->cfg.verbosity < 1) {
        // logging_init won't have printed "- test:" to stdout, so do it now
        progress_bar_flush();
        print_tests_header(OnFirstFail);
        writeln(real_stdout_fd, indent_spaces(), "- test: ", test->id);
    }

    bool crashed = false;
    bool coredumped = false;
    std::string reason;

    switch (testResult) {
    case TestResult::Skipped:
        logging_printf(loglevel, "  result: skip\n");
        if (!skipInMainThread) {
            logging_printf(loglevel, "  skip-category: %s\n", "Runtime");
            logging_printf(loglevel, "  skip-reason: %s\n",
                           "All CPUs skipped while executing 'test_run()' function, check log "
                           "for details");
        } else {
            // FIXME: multiple main threads
            std::string init_skip_message = get_skip_message(-1);
            if (init_skip_message.size() > 0) {
                logging_printf(loglevel, "  skip-category: %s\n",
                               char_to_skip_category(init_skip_message[0]));
                std::string_view message(&init_skip_message[1], init_skip_message.size()-1);
                if (loglevel <= sApp->shmem->cfg.verbosity && file_log_fd != real_stdout_fd)
                    format_and_print_skip_reason(real_stdout_fd, message);
                format_and_print_skip_reason(file_log_fd, message);
                init_skip_message_bytes = init_skip_message.size() + 2;
            } else {
                logging_printf(loglevel, "  skip-category: %s\n", "Unknown");
                logging_printf(loglevel, "  skip-reason: %s\n",
                               "Unknown, check main thread message for details or use -vv "
                               "option for more info");
            }
        }
        return;
    case TestResult::Passed:
        return logging_printf(loglevel, "  result: pass\n");
    case TestResult::Failed:
        return logging_printf(loglevel, "  result: fail\n");
    case TestResult::TimedOut:
        return logging_printf(loglevel, "  result: timed out\n");
    case TestResult::Interrupted:
        return logging_printf(loglevel, "  result: interrupted\n");
    case TestResult::OperatingSystemError:
        logging_printf(loglevel, "  result: operating system error\n");
        reason = "Operating system error: ";
        reason += sysexit_reason(childExitStatus);
        break;
    case TestResult::CoreDumped:
        coredumped = true;
        [[fallthrough]];
    case TestResult::OutOfMemory:
    case TestResult::Killed:
        logging_printf(loglevel, "  result: crash\n");
        reason = crash_reason(childExitStatus);
        crashed = true;
        break;
    }
    assert(should_print_fail_info());

    // format the code for us first
    char code[std::numeric_limits<unsigned>::digits10 + 2]; // sufficient for 0x + hex too
    snprintf(code, sizeof(code), childExitStatus.extra > 4096 ? "%#08x" : "%u", childExitStatus.extra);

    // print result details now
    auto booleanstr = [](bool cond) { return cond ? "true" : "false"; };
    logging_printf(loglevel, "  result-details: { crashed: %s, core-dump: %s, code: %s, reason: '%s' }\n",
                   booleanstr(crashed), booleanstr(coredumped), code, reason.c_str());
}

std::string YamlLogger::get_current_time()
{
    // write only to the log file
    // we're not using signal_safe_log_timestamp() because we don't want the brackets
    struct timespec elapsed = elapsed_runtime();

    using namespace std::chrono;
    auto ns = seconds(elapsed.tv_sec) + nanoseconds(elapsed.tv_nsec);
    auto us = duration_cast<microseconds>(ns);
    milliseconds ms = duration_cast<milliseconds>(us);
    us -= ms;

    // aligns for up to 999.999 s
    return stdprintf("{ elapsed: %6ld.%03d, now: !!timestamp '%s' }",
             long(ms.count()), int(us.count()),
             AbstractLogger::iso8601_time_now(Iso8601Format::WithoutMs));
}

const char *YamlLogger::quality_string(const struct test *test)
{
    if (test->quality_level < 0)
        return "alpha";
    if (test->quality_level == TEST_QUALITY_BETA)
        return "beta";
    return "production";
}

void YamlLogger::print_fixed()
{
    using ::format_duration;
    Duration test_duration = MonotonicTimePoint::clock::now() - sApp->current_test_starttime;

    print_result_line(init_skip_message_bytes);
    if (should_print_fail_info())
        logging_printf(LOG_LEVEL_QUIET, "%s", fail_info_details().c_str());
    logging_printf(LOG_LEVEL_VERBOSE(1), "  time-at-end:   %s\n", get_current_time().c_str());
    logging_printf(LOG_LEVEL_VERBOSE(1), "  test-runtime: %s\n",
                   format_duration(test_duration, FormatDurationOptions::WithoutUnit).c_str());

    print_fixed_for_device();

    if (sApp->shmem->cfg.log_test_knobs) {
        LogMessagesFile main_mmap = maybe_mmap_log(sApp->main_thread_data());
        if (!main_mmap.empty()) {
            int count = print_test_knobs(file_log_fd, main_mmap);
            if (count && real_stdout_fd != file_log_fd
                    && sApp->shmem->cfg.verbosity >= UsedKnobValueLoggingLevel)
                print_test_knobs(real_stdout_fd, main_mmap);
        }
    }
}

void YamlLogger::print_thread_messages()
{
    // print the thread messages
    auto doprint = [this](PerThreadData::Common *data, int s_tid) {
        LogMessagesFile r = maybe_mmap_log(data);
        bool want_print = data->has_failed() || sApp->shmem->cfg.verbosity >= 3;
        ssize_t min_size = 0;

        /* for main threads (negative ids) adjust the message size to account
         * for skip message. this is to avoid empty messages printed to the log.
         */
        if (s_tid < 0 && !want_print) {
            min_size = init_skip_message_bytes;
            want_print = want_slice_resource_usage(~s_tid);
        }
        if (r.size_bytes() <= min_size && !want_print) {
            munmap_and_truncate_log(data, r);
            return;             /* nothing to be printed, on any level */
        }

        print_thread_header(file_log_fd, s_tid, LogLevelVerbosity::Max);
        LogLevelVerbosity lowest_level =
                print_one_thread_messages(file_log_fd, r, LogLevelVerbosity::Max);

        if (lowest_level <= sApp->shmem->cfg.verbosity && file_log_fd != real_stdout_fd) {
            print_thread_header(real_stdout_fd, s_tid, sApp->shmem->cfg.verbosity);
            print_one_thread_messages(real_stdout_fd, r, sApp->shmem->cfg.verbosity);
        }

        munmap_and_truncate_log(data, r);
    };
    for_each_main_thread(doprint, slices.size());
    for_each_test_thread(doprint);
}

void YamlLogger::print()
{
    print_fixed();
    print_thread_messages();
    print_child_stderr_common([](int fd) {
        writeln(fd, indent_spaces(), "  stderr messages: |");
    });
    logging_flush();
}

void YamlLogger::maybe_print_virt_state() {
    auto detected_vm = detect_running_vm();
    auto detected_container = detect_running_container();

    if ((!detected_vm.empty()) || (!detected_container.empty())) {
        logging_printf(LOG_LEVEL_VERBOSE(1), "virtualization-state: { %s%s%s%s }\n",
                detected_vm.empty() ? "" : "vm: ",
                detected_vm.empty() ? "" : detected_vm.c_str(),
                detected_container.empty() ? "" : detected_vm.empty()
                    ? "container: " : ", container: ",
                detected_container.empty() ? "" : detected_container.c_str()
            );
    }
}

void YamlLogger::print_header(std::string_view cmdline, Duration test_duration, Duration test_timeout)
{
    using ::format_duration;
    logging_printf(LOG_LEVEL_QUIET, "command-line: '%s'\n", cmdline.data());
    logging_printf(LOG_LEVEL_QUIET, "version: %s\n", program_version);
    logging_printf(LOG_LEVEL_VERBOSE(1), "os: %s\n", kernel_info().c_str());
    logging_printf(LOG_LEVEL_VERBOSE(1), "runtime: %s\n", libc_info().c_str());
    if (std::string openssl = openssl_info(); openssl.size())
        logging_printf(LOG_LEVEL_VERBOSE(1), "openssl: { version: %s }\n", openssl.c_str());
    else
        logging_printf(LOG_LEVEL_VERBOSE(1), "openssl: null\n");
    logging_printf(LOG_LEVEL_VERBOSE(1), "timing: { duration: %s, timeout: %s }\n",
                   format_duration(test_duration, FormatDurationOptions::WithoutUnit).c_str(),
                   format_duration(test_timeout, FormatDurationOptions::WithoutUnit).c_str());

    // print the device information
    maybe_print_virt_state();
#if SANDSTONE_DEVICE_CPU
    logging_printf(LOG_LEVEL_VERBOSE(1), "cpu-info:\n");
#else
    logging_printf(LOG_LEVEL_VERBOSE(1), "device-info:\n");
#endif
    for (int i = 0; i < thread_count(); ++i) {
        logging_printf(LOG_LEVEL_VERBOSE(1), "- %s   # %d\n",
                       thread_id_header_for_device(i, LOG_LEVEL_VERBOSE(2)).c_str(), i);
    }

#if SANDSTONE_DEVICE_CPU
    auto make_plan_string = [](const std::vector<DeviceRange> &plan) {
        std::string result;
        for (DeviceRange r : plan) {
            if (result.size())
                result += ", ";
            result += "{ starting_cpu: ";
            result += std::to_string(r.starting_device);
            result += ", count: ";
            result += std::to_string(r.device_count);
            result += " }";
        }
        return result;
    };
    const std::vector<DeviceRange> &fullsocket = sApp->slice_plans.plans[SandstoneApplication::SlicePlans::IsolateSockets];
    const std::vector<DeviceRange> &isolatenuma = sApp->slice_plans.plans[SandstoneApplication::SlicePlans::IsolateNuma];
    const std::vector<DeviceRange> &heuristic = sApp->slice_plans.plans[SandstoneApplication::SlicePlans::Heuristic];
    logging_printf(LOG_LEVEL_VERBOSE(1), "test-plans:\n");
    logging_printf(LOG_LEVEL_VERBOSE(1), "  fullsocket: [ %s ]\n",
                   make_plan_string(fullsocket).c_str());
    logging_printf(LOG_LEVEL_VERBOSE(1), "  isolate_numa: [ %s ]\n",
                   make_plan_string(isolatenuma).c_str());
    logging_printf(LOG_LEVEL_VERBOSE(1), "  heuristic: [ %s ]\n",
                   make_plan_string(heuristic).c_str());
#endif
}

void YamlLogger::print_tests_header(TestHeaderTime mode)
{
    enum { NoHeader, LogFileOnly, Both };
    static auto state = NoHeader;
    if (state == Both)
        return;

    if (state == NoHeader) {
        writeln(file_log_fd, indent_spaces(), "tests:");
        state = LogFileOnly;
    }

    // if we're in quiet mode, we print the header only on first fail
    if (mode == AtStart && sApp->shmem->cfg.verbosity == 0 && file_log_fd != real_stdout_fd)
        return;

    if (file_log_fd != real_stdout_fd)
        writeln(real_stdout_fd, indent_spaces(), "tests:");
    state = Both;
}

/// prints the results from running the test \c{test} (test number \c{tc})
/// and returns the effective test result
TestResult logging_print_results(std::span<const ChildExitStatus> status, const struct test *test)
{
    switch (current_output_format()) {
#if SANDSTONE_LOGGING_YAML_ONLY
    // only YAML logging supported (or none at all)
    case SandstoneApplication::OutputFormat::key_value:
    case SandstoneApplication::OutputFormat::tap:
        __builtin_unreachable();
#else
    case SandstoneApplication::OutputFormat::key_value: {
        KeyValuePairLogger l(test, status);
        l.print(sApp->current_test_count);
        return l.testResult;
    }

    case SandstoneApplication::OutputFormat::tap: {
        TapFormatLogger l(test, status);
        l.print(sApp->current_test_count);
        return l.testResult;
    }
#endif // !SANDSTONE_LOGGING_YAML_ONLY

    case SandstoneApplication::OutputFormat::yaml: {
#if SANDSTONE_NO_LOGGING
        __builtin_unreachable();
#endif
        YamlLogger l(test, status);
        l.print();
        return l.testResult;
    }

    case SandstoneApplication::OutputFormat::no_output:
        break;
    }

    return AbstractLogger(test, status).testResult;
}
