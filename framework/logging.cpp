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
#if SANDSTONE_SSL_BUILD
#  include "sandstone_ssl.h"
#endif
#include "test_knobs.h"
#include "topology.h"

#include <array>
#include <charconv>
#include <functional>
#include <limits>
#include <string>
#include <string_view>
#include <unordered_set>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef _WIN32
#  include <sys/utsname.h>
#endif

#include "gitid.h"

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


#define PROGRAM_VERSION         SANDSTONE_EXECUTABLE_NAME "-" GIT_ID

static int real_stdout_fd = STDOUT_FILENO;
static int tty = -1;
static int file_log_fd = -1;
static int stderr_fd = -1;
static bool delete_log_on_success;
static uint8_t progress_bar_needs_flush = false;

static constexpr auto UsedKnobValueLoggingLevel = LOG_LEVEL_VERBOSE(1);

namespace {
enum LogTypes {
    UserMessages = 0,
    Preformatted = 1,
    UsedKnobValue = 2,
    SkipMessages = 3,
};

class AbstractLogger
{
public:
    AbstractLogger(const struct test *test, ChildExitStatus state);

    const struct test *test;
    MonotonicTimePoint earliest_fail = MonotonicTimePoint::max();
    ChildExitStatus childExitStatus;
    TestResult testResult = TestResult::Passed;
    int pc = 0;
    bool skipInMainThread = false;

protected:
    int loglevel() const;
    bool should_print_fail_info() const;

    // shared between the TAP and key-value loggers; YAML overrides
    int print_one_thread_messages(int fd, PerThreadData::Common *data, struct mmap_region r, int level);
};

class TapFormatLogger : public AbstractLogger
{
public:
    TapFormatLogger(const struct test *test, ChildExitStatus state)
        : AbstractLogger(test, state)
    {}

    void print(int tc);

protected:
    // shared with the pure YAML logger
    std::string fail_info_details();

private:
    const char *file_terminator = nullptr;
    const char *stdout_terminator = nullptr;

    void maybe_print_yaml_marker(int fd);
    void print_thread_messages();
    void print_thread_header(int fd, int cpu, int verbosity);
    void print_child_stderr();
    std::string format_status_code();
};

class YamlLogger : public TapFormatLogger
{
public:
    YamlLogger(const struct test *test, ChildExitStatus state)
        : TapFormatLogger(test, state)
    { }

    static std::string get_current_time();

    // non-virtual override
    void print();
    static void print_header(std::string_view cmdline, Duration test_duration, Duration test_timeout);

private:
    bool file_printed_messages_header = false;
    bool stdout_printed_messages_header = false;

    static std::string thread_id_header(int cpu, int verbosity);
    void maybe_print_messages_header(int fd);
    void print_thread_header(int fd, int cpu, int verbosity);
    static int print_test_knobs(int fd, mmap_region r);
    int print_one_thread_messages(int fd, mmap_region r, int level);
    void print_result_line();

    enum TestHeaderTime { AtStart, OnFirstFail };
    static void print_tests_header(TestHeaderTime mode);
};

class KeyValuePairLogger : public AbstractLogger
{
public:
    KeyValuePairLogger(const struct test *test, ChildExitStatus state)
        : AbstractLogger(test, state)
    {
        prepare_line_prefix();
    }

    void print(int tc);

private:
    std::string timestamp_prefix;

    void prepare_line_prefix();
    void print_thread_header(int fd, int cpu, const char *prefix);
    void print_thread_messages();
    void print_child_stderr();
};

} // unnamed namespace

static SandstoneApplication::OutputFormat current_output_format()
{
    if (SandstoneConfig::NoLogging)
        return SandstoneApplication::OutputFormat::no_output;
    return sApp->shmem->output_format;
}

static std::string_view indent_spaces()
{
    if (current_output_format() == SandstoneApplication::OutputFormat::no_output)
        return {};

    static const std::string spaces(sApp->shmem->output_yaml_indent, ' ');
    return spaces;
}

static const char *strnchr(const char *buffer, char c, size_t len)
{
    // we do NOT handle an embedded NUL, but the code in this file doesn't do
    // that (crossing fingers, promise)
    return static_cast<const char *>(memchr(buffer, c, len));
}

static uint8_t message_code(enum LogTypes logType, int level)
{
    assert((int)logType < 4);
    unsigned code = ((unsigned)logType + 1) << 4;
    code |= (level & 0xf);
    return (uint8_t)code;
}

static enum LogTypes log_type_from_code(uint8_t code)
{
    return (enum LogTypes)((code >> 4) - 1);
}

static int level_from_code(uint8_t code)
{
    return code & 0xf;
}

static auto thread_core_spacing()
{
    // calculate the spacing so things align
    // Note: this assumes the topology won't change after the first time this
    // function is called.
    static const auto spacing = []() {
        struct { int logical, core; } result = { 1, 1 };
        int max_core_id = 0;
        int max_logical_id = 0;
        for (int i = 0; i < num_cpus(); ++i) {
            if (cpu_info[i].cpu_number > max_logical_id)
                max_logical_id = cpu_info[i].cpu_number;
            if (cpu_info[i].core_id > max_core_id)
                max_core_id = cpu_info[i].core_id;
        }
        if (max_logical_id > 9)
            ++result.logical;
        if (max_logical_id > 99)
            ++result.logical;
        if (max_core_id > 9)
            ++result.core;
        if (max_core_id > 99)
            ++result.core;
        return result;
    }();
    return spacing;
}

enum class Iso8601Format : unsigned {
    WithoutMs           = 0,
    WithMs              = 1,
    FilenameCompatible  = 2,
};
static Iso8601Format operator|(Iso8601Format f1, Iso8601Format f2)
{ return Iso8601Format(unsigned(f1) | unsigned(f2)); }
static unsigned operator&(Iso8601Format f1, Iso8601Format f2)
{ return unsigned(f1) & unsigned(f2); }

static const char *iso8601_time_now(Iso8601Format format)
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

static std::string log_timestamp()
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

static const char *quality_string(const struct test *test)
{
    switch (current_output_format()) {
    case SandstoneApplication::OutputFormat::key_value:
    case SandstoneApplication::OutputFormat::yaml:
        if (test->quality_level < 0)
            return "alpha";
        if (test->quality_level < TEST_QUALITY_PROD)
            return "beta";
        return "production";
    case SandstoneApplication::OutputFormat::tap:
        if (test->quality_level < 0)
            return "(alpha test) ";
        if (test->quality_level < TEST_QUALITY_PROD)
            return "(beta test) ";
        return nullptr;
    case SandstoneApplication::OutputFormat::no_output:
        return nullptr;
    }
    __builtin_unreachable();
    return NULL;
}

/* which level of "quiet" should this log print at */
static uint8_t status_level(char letter)
{
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
    return 2;
}

static const char *char_to_skip_category(int val)
{
    switch (val) {
    case SkipCategory(1):
        return "ResourceIssueSkipCategory";
    case SkipCategory(2):
        return "CpuNotSupportedSkipCategory";
    case SkipCategory(3):
        return "DeviceNotFoundSkipCategory";
    case SkipCategory(4):
        return "DeviceNotConfiguredSkipCategory";
    case SkipCategory(5):
        return "UnknownSkipCategory";
    case SkipCategory(6):
        return "RuntimeSkipCategory";
    case SkipCategory(7):
        return "SelftestSkipCategory";
    case SkipCategory(8):
        return "OsNotSupportedSkipCategory";
    case SkipCategory(9):
        return "ThreadIssueSkipCategory";
    }

    return "NO CATEGORY PRESENT";
}

template <typename... Args> static ssize_t
log_message_for_thread(int thread_num, LogTypes logType, int level, Args &&... args)
{
    int fd = sApp->thread_data(thread_num)->log_fd;
    uint8_t code = message_code(logType, level);
    sApp->thread_data(thread_num)->messages_logged.fetch_add(1, std::memory_order_relaxed);
    return writevec(fd, code, std::forward<Args>(args)..., '\0');
}

int logging_stdout_fd(void)
{
    return real_stdout_fd;
}

static inline int open_new_log()
{
    if (sApp->current_fork_mode() == SandstoneApplication::exec_each_test)
        return open_memfd(MemfdInheritOnExec);
    else
        return open_memfd(MemfdCloseOnExec);
}

static inline void truncate_log(int fd)
{
    // truncate files back to empty, preparing for the next iteration
    lseek(fd, 0, SEEK_SET);
    ftruncate(fd, 0);
}

void logging_init_global_child()
{
    assert(sApp->current_fork_mode() == SandstoneApplication::child_exec_each_test);

    file_log_fd = real_stdout_fd = STDOUT_FILENO;
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
    sApp->file_log_path += iso8601_time_now(Iso8601Format::WithMs | Iso8601Format::FilenameCompatible);
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
    real_stdout_fd = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 0);
#else
    real_stdout_fd = dup(STDOUT_FILENO);
#endif
    if (real_stdout_fd == -1) {
        // this will never happen
        perror("fdopen");
        exit(EXIT_MEMORY);
    }

    // replace stdout with /dev/null
    int devnull = open(_PATH_DEVNULL, O_RDWR | O_CLOEXEC);
    dup2(devnull, STDOUT_FILENO);

    if (current_output_format() == SandstoneApplication::OutputFormat::no_output) {
        file_log_fd = STDOUT_FILENO;
    } else if (should_log_to_file()) {
        errno = EISDIR;
        if (sApp->file_log_path.empty())
            sApp->file_log_path = '.';

        file_log_fd = open(sApp->file_log_path.c_str(), O_RDWR | O_CLOEXEC | O_CREAT | O_TRUNC, 0666);
        bool isdir = false;
        if (file_log_fd == -1) {
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
            file_log_fd = open(time_based_log_path(), O_RDWR | O_CLOEXEC | O_CREAT | O_TRUNC, 0666);
            delete_log_on_success = true;
        }
        if (file_log_fd == -1) {
            fprintf(stderr, "%s: failed to open log file: %s: %s\n",
                    program_invocation_name, sApp->file_log_path.c_str(), strerror(errno));
            exit(EX_CANTCREAT);
        }
    }

    if (file_log_fd == -1) {
        file_log_fd = real_stdout_fd;
    } else {
#ifdef _WIN32
        // no tty on win32, open app's console instead
        tty = open("CON:", _O_WRONLY);
#elif defined _PATH_TTY
        if (isatty(real_stdout_fd)) {
            // stdout is a tty, so try to open /dev/tty
            tty = open(_PATH_TTY, O_WRONLY | O_NOCTTY | O_CLOEXEC);
        }
#endif
    }

    close(devnull);

    /* open some place to store stderr in the child processes */
#if !defined(__SANITIZE_ADDRESS__)
    stderr_fd = open_memfd(MemfdCloseOnExec);
#endif

    // open log files for each thread
    for (int i = -1; i < num_cpus(); ++i)
        sApp->thread_data(i)->log_fd = open_new_log();

#ifdef __GLIBC__
    setenv("LIBC_FATAL_STDERR_", "1", true);
#endif
}

int logging_close_global(int exitcode)
{
    progress_bar_flush();
    if (!SandstoneConfig::NoLogging) {
        if (exitcode != EXIT_SUCCESS) {
            logging_print_log_file_name();
            logging_printf(LOG_LEVEL_QUIET,
                           exitcode == EXIT_FAILURE ? "exit: fail\n" : "exit: invalid\n");
        } else if (sApp->shmem->verbosity >= 0) {
            logging_printf(LOG_LEVEL_QUIET, "exit: pass\n");
        }
    }

    if (exitcode == EXIT_SUCCESS && delete_log_on_success) {
        close(file_log_fd);
        remove(sApp->file_log_path.c_str());
    }

#ifndef NDEBUG
    // close all log files (in release mode, the OS closes for us)
    for (int i = -1; i < num_cpus(); ++i)
        close(sApp->thread_data(i)->log_fd);
#endif

    /* leak all file descriptors without closing, the application
     * is about to exit anyway */
    return exitcode;
}

void logging_print_log_file_name()
{
    if (real_stdout_fd == file_log_fd || file_log_fd == STDOUT_FILENO)
        return;
    switch (current_output_format()) {
    case SandstoneApplication::OutputFormat::key_value:
    case SandstoneApplication::OutputFormat::tap:
        dprintf(real_stdout_fd, "# More information logged to '%s'\n", sApp->file_log_path.c_str());
        break;

    case SandstoneApplication::OutputFormat::yaml:
        dprintf(real_stdout_fd, "%slog_file: '%s'\n", indent_spaces().data(), sApp->file_log_path.c_str());
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
void logging_mark_thread_failed(int thread_num)
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

static void log_message_preformatted(int thread_num, std::string_view msg)
{
    int level = status_level(msg[0]);
    if (msg[0] == 'E')
        logging_mark_thread_failed(thread_num);

    std::atomic<int> &messages_logged = sApp->thread_data(thread_num)->messages_logged;
    if (messages_logged.load(std::memory_order_relaxed) >= sApp->shmem->max_messages_per_thread)
        return;

    if (msg[msg.size() - 1] == '\n')
        msg.remove_suffix(1);           // remove trailing newline

    log_message_for_thread(thread_num, UserMessages, level, msg);
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
void logging_restricted(int level, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    std::string msg = vstdprintf(fmt, va);
    va_end(va);

    if (msg.empty())
        return;

    progress_bar_flush();

    int fd = real_stdout_fd;
    if (level < 0)
        fd = STDERR_FILENO;

    writeln(fd, msg.c_str());

    if (level < 0)
        log_message_to_syslog(msg.c_str());
}
#pragma GCC diagnostic pop

#else

void logging_printf(int level, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    std::string msg = create_filtered_message_string(fmt, va);
    va_end(va);

    if (msg.empty())
        return;     // can happen if fmt was "%s" and the string ended up empty

    if (level <= sApp->shmem->verbosity && file_log_fd != real_stdout_fd) {
        progress_bar_flush();
        int fd = real_stdout_fd;
        if (level < 0)
            fd = STDERR_FILENO;
        writevec(fd, indent_spaces(), msg);
    }

    int fd = file_log_fd;
    if (level < 0 && file_log_fd == real_stdout_fd)
        fd = STDERR_FILENO;         // no stderr logging above, so do it here

    // include the timestamp in each line, unless we're using YAML format
    // (timestamps are elsewhere there)
    if (current_output_format() != SandstoneApplication::OutputFormat::yaml) {
        writevec(fd, log_timestamp(), msg);
    } else {
        writevec(fd, indent_spaces(), msg);
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

#if SANDSTONE_SSL_BUILD
static std::string openssl_info()
{
    std::string result = "";
    if (s_OpenSSL_version)
        result = s_OpenSSL_version(0);
    return result;
}
#endif

static std::string os_info()
{
    std::string os_info;
    std::string kernel = kernel_info();
    std::string libc = libc_info();
#if SANDSTONE_SSL_BUILD
    std::string libssl = openssl_info();
#endif
    if (kernel.empty())
        return "<unknown>";
    os_info = kernel;
    if (!libc.empty())
        os_info += ", " + libc;
#if SANDSTONE_SSL_BUILD
    if (!libssl.empty())
        os_info += ", " + libssl;
#endif

    return os_info;
}

static void print_reproduction_details()
{
    switch (current_output_format()) {
    case SandstoneApplication::OutputFormat::key_value:
        logging_printf(LOG_LEVEL_QUIET, "version = " PROGRAM_VERSION "\n");
        logging_printf(LOG_LEVEL_QUIET, "current_time = %s\n", iso8601_time_now(Iso8601Format::WithMs));
        logging_printf(LOG_LEVEL_VERBOSE(1), "os = %s\n", os_info().c_str());
        return;

    case SandstoneApplication::OutputFormat::tap:
        logging_printf(LOG_LEVEL_QUIET, "# Built from git commit: " PROGRAM_VERSION "\n");
        logging_printf(LOG_LEVEL_QUIET, "# Current time: %s\n", iso8601_time_now(Iso8601Format::WithMs));
        break;

    case SandstoneApplication::OutputFormat::yaml:
        logging_printf(LOG_LEVEL_QUIET, "version: " PROGRAM_VERSION "\n");
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
    printf(PROGRAM_VERSION "\n");
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
        logging_printf(LOG_LEVEL_VERBOSE(1), "# Operating system: %s\n", os_info().c_str());
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
    switch (sApp->shmem->output_format) {
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

void logging_print_triage_results(const std::vector<int> &sockets)
{
    if (current_output_format() == SandstoneApplication::OutputFormat::no_output)
        return;                 // short-circuit
    if (sockets.empty())
        return;

    // join the socket list
    std::string_view comma;
    std::string list;
    for (int no : sockets) {
        list += comma;
        list += std::to_string(no);
        comma = ", ";
    }

    switch (current_output_format()) {
    case SandstoneApplication::OutputFormat::key_value:
        return logging_printf(LOG_LEVEL_QUIET, "triage_results = %s\n", list.c_str());
    case SandstoneApplication::OutputFormat::tap:
        return logging_printf(LOG_LEVEL_QUIET, "# The failure was isolated to sockets: %s\n", list.c_str());
    case SandstoneApplication::OutputFormat::yaml:
        return logging_printf(LOG_LEVEL_QUIET, "triage-results: [ %s ]\n", list.c_str());
    case SandstoneApplication::OutputFormat::no_output:
        break;
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
    do_flush(file_log_fd);
    do_flush(sApp->main_thread_data()->log_fd);
}

void logging_init(const struct test *test)
{
    if (sApp->shmem->verbosity <= 0)
        progress_bar_update();

    switch (current_output_format()) {
    case SandstoneApplication::OutputFormat::key_value:
    case SandstoneApplication::OutputFormat::tap:
        logging_printf(LOG_LEVEL_VERBOSE(2), "# Executing test %s '%s'\n", test->id, test->description);
        logging_printf(LOG_LEVEL_VERBOSE(2), "# Seed: %s \n", random_format_seed().c_str());
        break;
    case SandstoneApplication::OutputFormat::yaml:
        // note: see comments in YamlLogger::print() on this first line
        logging_printf(LOG_LEVEL_VERBOSE(1), "- test: %s\n", test->id);
        logging_printf(LOG_LEVEL_VERBOSE(3), "  details: { quality: %s, description: \"%s\" }\n",
                       quality_string(test), test->description);
        logging_printf(LOG_LEVEL_VERBOSE(3), "  state: { seed: '%s', iteration: %d, retry: %s }\n",
                       random_format_seed().c_str(), abs(sApp->current_iteration_count),
                       sApp->current_iteration_count < 0 ? "true" : "false");
        logging_printf(LOG_LEVEL_VERBOSE(2), "  time-at-start: %s\n", YamlLogger::get_current_time().c_str());
        break;
    case SandstoneApplication::OutputFormat::no_output:
        return;                 // short-circuit
    }
}

void logging_init_child_preexec()
{
    if (stderr_fd != -1)
        dup2(stderr_fd, STDERR_FILENO);
}

void logging_finish()
{
}

LoggingStream logging_user_messages_stream(int thread_num, int level)
{
    LoggingStream stream(sApp->thread_data(thread_num)->log_fd);
    sApp->thread_data(thread_num)->messages_logged.fetch_add(1, std::memory_order_relaxed);
    uint8_t code = message_code(UserMessages, level);
    stream.write(code);
    return stream;
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
    if (current_output_format() == SandstoneApplication::OutputFormat::no_output)
        return;

    va_list va;
    va_start(va, fmt);
    std::string msg = create_filtered_message_string(fmt, va);
    va_end(va);
    
    msg.insert(msg.begin(), category);

    if (msg[msg.size() - 1] == '\n')
        msg.pop_back(); // remove trailing newline
             
    log_message_for_thread(thread_num, SkipMessages, LOG_LEVEL_VERBOSE(1), msg);
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

static void log_data_common(const char *message, const uint8_t *ptr, size_t size, bool from_memcmp)
{
    std::string spaces;
    std::string buffer;

    switch (current_output_format()) {
    case SandstoneApplication::OutputFormat::yaml:
        spaces.resize(sApp->shmem->output_yaml_indent + 4 + (from_memcmp ? 3 : 0), ' ');
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
        spaces.resize(4 + (from_memcmp ? 3 : 0), ' ');
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
    log_message_for_thread(thread_num, Preformatted, LOG_LEVEL_VERBOSE(2), buffer);
}

#undef log_data
void log_data(const char *message, const void *data, size_t size)
{
    if (current_output_format() == SandstoneApplication::OutputFormat::no_output)
        return;                 // short-circuit

    std::atomic<int> &messages_logged = sApp->thread_data(thread_num)->messages_logged;
    std::atomic<unsigned> &data_bytes_logged = sApp->thread_data(thread_num)->data_bytes_logged;
    if (messages_logged.load(std::memory_order_relaxed) >= sApp->shmem->max_messages_per_thread ||
            (data_bytes_logged.fetch_add(size, std::memory_order_relaxed) > sApp->shmem->max_logdata_per_thread))
        return;


    log_data_common(message, static_cast<const uint8_t *>(data), size, false);
}

static void logging_format_data(DataType type, std::string_view description, const uint8_t *data1,
                                const uint8_t *data2, ptrdiff_t offset)
{
    std::string spaces(sApp->shmem->output_yaml_indent + 7, ' ');
    std::string buffer;
    switch (current_output_format()) {
    case SandstoneApplication::OutputFormat::tap:
    case SandstoneApplication::OutputFormat::key_value:
        buffer += "  - data-miscompare:\n";
        break;

    case SandstoneApplication::OutputFormat::yaml:
        buffer += stdprintf("%s- level: error\n"
                            "%s  data-miscompare:\n",
                            spaces.c_str() + 3,
                            spaces.c_str() + 3);
        break;

    case SandstoneApplication::OutputFormat::no_output:
        assert(false && "Shouldn't have reached here");
        __builtin_unreachable();
        break;
    }

    auto formatAddresses = [&spaces](const uint8_t *ptr) {
        std::string result = stdprintf("%saddress:     '%p'\n", spaces.c_str(), ptr);
        if (uint64_t physaddr = retrieve_physical_address(ptr)) {
            // 2^48-1 requires 12 hex digits
            result += stdprintf("%sphysical:    '%#012" PRIx64 "'\n",
                                 spaces.c_str(), physaddr);
        }
        return result;
    };

    const char *typeName = SandstoneDataDetails::type_name(type);
    if (!typeName) {
        // also a validity check
        type = UInt8Data;
        typeName = SandstoneDataDetails::type_name(type);
    }
    buffer += stdprintf("%sdescription: '%.*s'\n"
                        "%stype:        %s\n",
                        spaces.c_str(), int(description.size()), description.data(),
                        spaces.c_str(), typeName);

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

        buffer += stdprintf("%soffset:      [ %td, %td ]\n",
                            spaces.c_str(), alignedOffset, offset - alignedOffset);
        buffer += formatAddresses(data1 + offset);
        buffer += stdprintf("%sactual:      '0x%s'\n"
                            "%sexpected:    '0x%s'\n"
                            "%smask:        '0x%s'\n",
                            spaces.c_str(), format_single_type(type, typeSize, data1 + alignedOffset, true).c_str(),
                            spaces.c_str(), format_single_type(type, typeSize, data2 + alignedOffset, true).c_str(),
                            spaces.c_str(), format_single_type(type, typeSize, xormask, false).c_str());
    } else {
        // no difference was found: memcmp_offset() disagrees with memcmp_or_fail()
        buffer += stdprintf("%soffset:      null\n", spaces.c_str());
        buffer += formatAddresses(data1);
        buffer += stdprintf("%sactual:      null\n"
                            "%sexpected:    null\n"
                            "%smask:        null\n"
                            "%sremark:      'memcmp_offset() could not locate difference'\n",
                            spaces.c_str(), spaces.c_str(), spaces.c_str(), spaces.c_str());
    }

    log_message_for_thread(thread_num, Preformatted, LOG_LEVEL_QUIET, buffer);
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
    if (offset < 0)
        return;         // we couldn't find a difference

    // log the data that failed
    ptrdiff_t start;
    size_t len = 64;
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
                                indent_spaces().data(), name);
        } else {
            message = stdprintf("Bytes %td..%td of %s", start, start + len - 1, name);
        }
        log_data_common(message.c_str(), which + start, len, true);
    };
    do_log_data("actual", actual);
    do_log_data("expected", expected);
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

    if (!sApp->shmem->log_test_knobs)
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
        std::string operator()(std::string_view v)
        {
            if (v.data() == nullptr) {
                return "null";
            } else {
                std::string storage;
                return stdprintf("'%s'", escape_for_single_line(v, storage).data());
            }
        }
    };
    std::string formatted = std::visit(Visitor{}, value);
    log_message_for_thread(-1, UsedKnobValue, UsedKnobValueLoggingLevel,
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

        writevec(fd, indent_spaces(), indent, std::string_view(line, newline - line), '\n');
        line = newline + 1;
    }
}

/// Prints the content suitable for a single-quote YAML line
/// (quotes must be supplied in \c{before} and \c{after}
static void print_content_single_line(int fd, std::string_view before,
                                      std::string_view message,
                                      std::string_view after)
{
    std::string escaped;
    writeln(fd, before, escape_for_single_line(message, escaped), after);
}

static void format_and_print_message(int fd, int message_level, std::string_view message, bool from_thread_message)
{
    const char *levels[] = { "error", "warning", "info", "debug", "skip" }; //levels for yaml

    if (message.find('\n') != std::string_view::npos) {
        /* multi line */
        if (current_output_format() == SandstoneApplication::OutputFormat::yaml) {
            if (from_thread_message) {
                 if (message_level > int(std::size(levels)))
                    message_level = std::size(levels) - 1;

                // trim a trailing newline, if any (just one)
                if (message[message.size() - 1] == '\n')
                    message.remove_suffix(1);

                writeln(fd, indent_spaces(), "    - level: ", levels[message_level]);
                writeln(fd, indent_spaces(), "      text: |1");
                print_content_indented(fd, "       ", message);
            } else {
                writeln(fd, indent_spaces(), "  skip-reason: |1");
                print_content_indented(fd, "   ", message);
            }   
        } else {
            if (from_thread_message) // are you writing individual thread's message?
                writeln(fd, "  - |");
            else                     // are you writing init thread's message?
                writeln(fd, "\n", indent_spaces(), " - |");
            print_content_indented(fd, "    ", message); 
        }
    } else {
        /* single line */
        if (current_output_format() == SandstoneApplication::OutputFormat::yaml) {
            if (from_thread_message) {
                writevec(fd, indent_spaces(), "    - { level: ", levels[message_level]);
                print_content_single_line(fd, ", text: '", message, "' }");
            } else {
                writevec(fd, indent_spaces());
                print_content_single_line(fd, "  skip-reason: '", message, "'");
            }
        } else {
            if (from_thread_message) { // are you writing individual thread's message?
                char c = '\'';
                print_content_single_line(fd, "   - '", message, std::string_view(&c, 1));
            } else { // are you writing init thread's message?
                print_content_single_line(fd, "'", message, "'"); 
            }
        }
    }
}

static std::string get_skip_message(int thread_num)
{
    std::string skip_message;
    struct mmap_region r = mmap_file(sApp->thread_data(thread_num)->log_fd);
    auto ptr = static_cast<const char *>(r.base);
    const char *end = ptr + r.size;
    const char *delim;

    for ( ; ptr < end && (delim = strnchr(ptr, '\0', end - ptr)) != nullptr; ptr = delim + 1) {
        uint8_t code = (uint8_t)*ptr++;
        if (log_type_from_code(code) == LogTypes::SkipMessages) {
            skip_message.assign(ptr, delim);
            break;
        }
    }
    munmap_file(r);
    return skip_message;
}

static inline void format_skip_message(std::string &skip_message, std::string_view message)
{
    skip_message += message.substr(1, message.size());
}

/// Returns the lowest priority found
/// (this function is shared between the TAP and key-value pair loggers)
int AbstractLogger::print_one_thread_messages(int fd, PerThreadData::Common *data, struct mmap_region r, int level)
{
    int lowest_level = INT_MAX;
    auto ptr = static_cast<const char *>(r.base);
    const char *end = ptr + r.size;
    const char *delim;

    for ( ; ptr < end && (delim = strnchr(ptr, '\0', end - ptr)) != nullptr; ptr = delim + 1) {
        uint8_t code = (uint8_t)*ptr++;
        int message_level = level_from_code(code);

        if (message_level > level)
            continue;

        std::string_view message(ptr, delim - ptr);
        switch (log_type_from_code(code)) {
        case UserMessages:
            format_and_print_message(fd, -1, message, true);
            break;

        case Preformatted:
            IGNORE_RETVAL(write(fd, ptr, delim - ptr));
            break;
        
        case SkipMessages: 
            if (!skipInMainThread) {
                // Only print if the result line didn't already include this
                std::string skip_message;
                format_skip_message(skip_message, message);
                format_and_print_message(fd, -1, std::string_view{&skip_message[0], skip_message.size()}, true);
            }
            break;

        case UsedKnobValue: {
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

static void print_child_stderr_common(std::function<void(int)> header)
{
    struct mmap_region r = mmap_file(stderr_fd);
    if (r.size == 0)
        return;

    char indent[] = "    ";
    std::string_view contents(static_cast<const char *>(r.base), r.size);

    header(file_log_fd);
    print_content_indented(file_log_fd, indent, contents);
    if (file_log_fd != real_stdout_fd && sApp->shmem->verbosity > 0) {
        header(real_stdout_fd);
        print_content_indented(real_stdout_fd, indent, contents);
    }
    munmap_file(r);

    /* reset it for the next iteration */
    truncate_log(stderr_fd);
}

static std::string
format_duration(MonotonicTimePoint tp, FormatDurationOptions opts = FormatDurationOptions::WithoutUnit)
{
    if (tp == MonotonicTimePoint() || tp == MonotonicTimePoint::max())
        return {};

    return format_duration(tp - sApp->current_test_starttime, opts);
}

inline AbstractLogger::AbstractLogger(const struct test *test, ChildExitStatus state_)
    : test(test), childExitStatus(state_), testResult(state_.result)
{
    switch (testResult) {
    case TestResult::Skipped:
        skipInMainThread = true;
        return;         // no threads were started

    case TestResult::Passed:
        // normal condition
        break;

    case TestResult::Failed:
        // test's test_init() failed. That's usually not supposed to happen...
        return;

    case TestResult::TimedOut:
        // find stuck threads and insert error message
        for (int i = 0; i < num_cpus(); ++i) {
            ThreadState thr_state = sApp->thread_data(i)->thread_state.load(std::memory_order_relaxed);
            if (thr_state == thread_running)
                log_message(i, SANDSTONE_LOG_ERROR "Thread is stuck");
        }
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
    for (int i = 0; i < num_cpus(); ++i) {
        PerThreadData::Common *data = sApp->thread_data(i);
        ThreadState thr_state = data->thread_state.load(std::memory_order_relaxed);
        if (data->has_failed()) {
            earliest_fail = std::min(earliest_fail, data->fail_time);
            testResult = TestResult::Failed;
        } else {
            // thread passed test
            ++pc;
            if (thr_state == thread_skipped) ++sc;
        }
    }

    if (testResult == TestResult::Passed && pc == sc)
        testResult = TestResult::Skipped;       // all threads skipped
}

inline int AbstractLogger::loglevel() const
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

inline bool AbstractLogger::should_print_fail_info() const
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

void KeyValuePairLogger::prepare_line_prefix()
{
    timestamp_prefix = log_timestamp();
    timestamp_prefix += test->id;
}

void KeyValuePairLogger::print(int tc)
{
    logging_printf(LOG_LEVEL_QUIET, "%s_result = %s\n", test->id,
                   testResult == TestResult::Skipped ? "skip" :
                   testResult == TestResult::Passed ? "pass" : "fail");
    
    if (testResult == TestResult::Skipped && !skipInMainThread) {
        logging_printf(LOG_LEVEL_QUIET, "%s_skip_category = %s\n", test->id, "RuntimeSkipCategory");
        logging_printf(LOG_LEVEL_QUIET, "%s_skip_reason = %s\n", test->id,
                       "All CPUs skipped while executing 'test_run()' function, check log for details");
    } else if (testResult == TestResult::Skipped) {
        // skipped in the test_init()
        std::string init_skip_message = get_skip_message(-1);
        if (init_skip_message.size() > 0) {
            logging_printf(LOG_LEVEL_QUIET, "%s_skip_category = %s\n", test->id, char_to_skip_category(init_skip_message[0]));
            logging_printf(LOG_LEVEL_QUIET, "%s_skip_reason = ", test->id);
            std::string_view message(&init_skip_message[1], init_skip_message.size()-1);
            format_and_print_message(real_stdout_fd, -1, message, false);
            if (file_log_fd != real_stdout_fd)
                format_and_print_message(file_log_fd, -1, message, false);
        } else {
            logging_printf(LOG_LEVEL_QUIET, "%s_skip_category = %s\n", test->id, "UnknownSkipCategory");
            logging_printf(LOG_LEVEL_QUIET, "%s_skip_reason = %s\n", test->id,
                           "Unknown, check main thread message for details or use -vv option for more info");
        }
    }

    logging_printf(LOG_LEVEL_VERBOSE(1), "%s_seq = %d\n", test->id, tc);
    logging_printf(LOG_LEVEL_VERBOSE(1), "%s_quality = %s\n", test->id, quality_string(test));
    logging_printf(LOG_LEVEL_VERBOSE(1), "%s_description = %s\n", test->id, test->description);
    logging_printf(LOG_LEVEL_VERBOSE(1), "%s_pass_count = %d\n", test->id, pc);
    logging_printf(LOG_LEVEL_VERBOSE(2), "%s_virtualized = %s\n", test->id,
                   cpu_has_feature(cpu_feature_hypervisor) ? "yes" : "no");
    if (should_print_fail_info()) {
        logging_printf(LOG_LEVEL_VERBOSE(1), "%s_fail_percent = %.1f\n", test->id,
                       100. * (num_cpus() - pc) / num_cpus());
        logging_printf(LOG_LEVEL_VERBOSE(1), "%s_random_generator_state = %s\n", test->id,
                       random_format_seed().c_str());
        logging_printf(LOG_LEVEL_VERBOSE(1), "%s_fail_mask = %s\n", test->id,
                       Topology::topology().build_falure_mask(test).c_str());
        if (std::string time = format_duration(earliest_fail); time.size())
            logging_printf(LOG_LEVEL_VERBOSE(1), "%s_earliest_fail_time = %s\n", test->id, time.c_str());
    }

    logging_flush();
    print_thread_messages();
    print_child_stderr();
    logging_flush();
}

void KeyValuePairLogger::print_thread_header(int fd, int cpu, const char *prefix)
{
    if (cpu < 0) {
        writeln(file_log_fd, timestamp_prefix, "_messages_mainthread = \\");
        return;
    }

    struct cpu_info *info = cpu_info + cpu;
    PerThreadData::Test *thr = sApp->test_thread_data(cpu);
    if (std::string time = format_duration(thr->fail_time); time.size()) {
        dprintf(fd, "%s_thread_%d_fail_time = %s\n", prefix, cpu, time.c_str());
        dprintf(fd, "%s_thread_%d_loop_count = %" PRIu64 "\n", prefix, cpu,
                thr->inner_loop_count_at_fail);
    } else {
        dprintf(fd, "%s_thread_%d_loop_count = %" PRIu64 "\n", prefix, cpu,
                thr->inner_loop_count);
    }
    dprintf(fd, "%s_messages_thread_%d_cpu = %d\n", prefix, cpu, info->cpu_number);
    dprintf(fd, "%s_messages_thread_%d_family_model_stepping = %02x-%02x-%02x\n", prefix, cpu,
            info->family, info->model, info->stepping);
    dprintf(fd, "%s_messages_thread_%d_topology = phys %d, core %d, thr %d\n",
            prefix, cpu, info->package_id, info->core_id, info->thread_id);
    dprintf(fd, "%s_messages_thread_%d_microcode =", prefix, cpu);
    if (info->microcode)
        dprintf(fd, " 0x%" PRIx64, info->microcode);
    dprintf(fd, "\n%s_messages_thread_%d_ppin =",
            prefix, cpu);
    if (info->ppin)
        dprintf(fd, " 0x%" PRIx64, info->ppin);
    dprintf(fd, "\n%s_messages_thread_%d = \\\n", prefix, cpu);
}

void KeyValuePairLogger::print_thread_messages()
{
    for (int i = -1; i < num_cpus(); i++) {
        PerThreadData::Common *data = sApp->thread_data(i);
        struct mmap_region r = mmap_file(data->log_fd);

        if (r.size == 0 && !data->has_failed() && sApp->shmem->verbosity < 3)
            continue;           /* nothing to be printed, on any level */

        print_thread_header(file_log_fd, i, timestamp_prefix.c_str());
        int lowest_level = print_one_thread_messages(file_log_fd, data, r, INT_MAX);

        if (lowest_level <= sApp->shmem->verbosity && file_log_fd != real_stdout_fd) {
            print_thread_header(real_stdout_fd, i, test->id);
            print_one_thread_messages(real_stdout_fd, data, r, sApp->shmem->verbosity);
        }

        munmap_file(r);
        truncate_log(data->log_fd);
    }
}

void KeyValuePairLogger::print_child_stderr()
{
    print_child_stderr_common([this](int fd) {
        std::string_view prefix = test->id;
        if (fd == file_log_fd)
            prefix = timestamp_prefix.c_str();
        writeln(fd, prefix, "_strerr = \\");
    });
}

void TapFormatLogger::print(int tc)
{
    // build the ok / not ok line
    std::string extra;
    if (const char *qual = quality_string(test))
        extra = qual;

    const char *okstring = "not ok";
    switch (testResult) {
    case TestResult::Skipped:
        extra += "SKIP";
        if (skipInMainThread) {
            std::string init_skip_message = get_skip_message(-1);
            if (init_skip_message.size() != 0)
                extra += "(" + std::string(char_to_skip_category(init_skip_message[0])) +
                        " : " + init_skip_message.substr(1,init_skip_message.size()) + ")";
            else
                extra += "(UnknownSkipCategory: check main thread message for details or "
                            "use -vv option for more info)";
        } else {
            extra += "(RuntimeSkipCategory: All CPUs skipped while executing 'test_run()' "
                     "function, check log for details)";
        }
        [[fallthrough]];
    case TestResult::Passed:
        okstring = "ok";
        break;
    case TestResult::Failed:
        break;          // no suffix necessary
    case TestResult::TimedOut:
        extra += "timed out";
        break;
    case TestResult::CoreDumped:
        extra += "Core Dumped: ";
        extra += format_status_code();
        break;
    case TestResult::OutOfMemory:
    case TestResult::Killed:
        extra += "Killed: ";
        extra += format_status_code();
        break;
    case TestResult::Interrupted:
        extra += "Interrupted";
        break;
    case TestResult::OperatingSystemError:
        extra += "Operating system error: ";
        extra += format_status_code();
        break;
    }

    std::string tap_line = stdprintf("%s %3i %s", okstring, tc, test->id);
    if (extra.size()) {
        static constexpr std::string_view separator = "# ";
        size_t newsize = std::max(tap_line.size(), size_t(32)) + separator.size() + extra.size();
        tap_line.reserve(newsize);
        if (tap_line.size() < 32)
            tap_line.resize(32, ' ');
        tap_line += separator;
        tap_line += extra;
        extra.clear();
    }

    logging_printf(loglevel(), "%s\n", tap_line.c_str());

    logging_flush();
    print_thread_messages();
    if (sApp->shmem->verbosity >= 1)
        print_child_stderr();

    if (file_terminator)
        writeln(file_log_fd, file_terminator);
    if (stdout_terminator)
        writeln(real_stdout_fd, stdout_terminator);

    logging_flush();
}

/// builds the fail info message (including newline)
/// returns an empty string if there was no failure
std::string TapFormatLogger::fail_info_details()
{
    std::string result;
    if (!should_print_fail_info())
        return result;

    auto add_value = [&result](std::string s, char separator) {
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
    std::string fail_mask = Topology::topology().build_falure_mask(test);

    result.reserve(strlen("  fail: { cpu-mask: '', time-to-fail: , seed: '' }\n") +
                   seed.size() + time.size() + fail_mask.size());
    result += "  fail: { cpu-mask: ";
    add_value(fail_mask, '\'');
    result += ", time-to-fail: ";
    add_value(time, '\0');
    result += ", seed: ";
    add_value(seed, '\'');
    result += "}\n";
    return result;
}

[[gnu::pure]] static const char *crash_reason(ChildExitStatus status)
{
    assert(status.result != TestResult::Passed);
    assert(status.result != TestResult::Skipped);
    assert(status.result != TestResult::Failed);
    assert(status.result != TestResult::TimedOut);
    assert(status.result != TestResult::Interrupted);
#ifdef _WIN32
    switch (status.extra) {
    case static_cast<unsigned>(STATUS_FAIL_FAST_EXCEPTION):
        return "Aborted";
    case STATUS_ACCESS_VIOLATION:
        return "Access violation";
    case STATUS_ILLEGAL_INSTRUCTION:
        return "Illegal instruction";
    case STATUS_INTEGER_DIVIDE_BY_ZERO:
        return "Integer division by zero";
    case STATUS_NO_MEMORY:
        return "Out of memory condition";
    case STATUS_STACK_BUFFER_OVERRUN:
        return "Stack buffer overrun";
    }
    return "Unknown";
#else
    return strsignal(status.extra);
#endif
}

[[gnu::pure]] static const char *sysexit_reason(ChildExitStatus status)
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

std::string TapFormatLogger::format_status_code()
{
    if (childExitStatus.result == TestResult::OperatingSystemError)
        return sysexit_reason(childExitStatus);
    std::string msg = crash_reason(childExitStatus);
    if (msg.empty()) {
        // format the number
#ifdef _WIN32
        msg = stdprintf("Child process caused error %#08x", childExitStatus.extra);
#else
        // probably a real-time signal
        msg = stdprintf("Child process died with signal %d", childExitStatus.extra);
#endif
    }
    return msg;
}

void TapFormatLogger::maybe_print_yaml_marker(int fd)
{
    static const char yamlseparator[] = " ---";
    auto &terminator = (fd == file_log_fd ? file_terminator : stdout_terminator);
    if (terminator)
        return;

    std::string_view nothing;
    terminator = yamlseparator;
    writeln(fd, yamlseparator,
            "\n  info: {version: " PROGRAM_VERSION
            ", timestamp: ", iso8601_time_now(Iso8601Format::WithoutMs),
            cpu_has_feature(cpu_feature_hypervisor) ? ", virtualized: true" : nothing,
            "}");
    if (std::string fail_info = fail_info_details(); !fail_info.empty())
        IGNORE_RETVAL(write(fd, fail_info.c_str(), fail_info.size()));
}

void TapFormatLogger::print_thread_header(int fd, int cpu, int verbosity)
{
    maybe_print_yaml_marker(fd);
    if (cpu < 0) {
        writeln(fd, "  Main thread:");
        return;
    }

    struct cpu_info *info = cpu_info + cpu;
    std::string line = stdprintf("  Thread %d on CPU %d (pkg %d, core %d, thr %d", cpu,
            info->cpu_number, info->package_id, info->core_id, info->thread_id);

    line += stdprintf(", family/model/stepping %02x-%02x-%02x, microcode ", info->family, info->model,
                      info->stepping);
    if (info->microcode)
        line += stdprintf("%#" PRIx64, info->microcode);
    else
        line += "N/A";
    if (info->ppin)
        line += stdprintf(", PPIN %016" PRIx64 "):", info->ppin);
    else
        line += ", PPIN N/A):";

    writeln(fd, line);

    if (verbosity > 1) {
        PerThreadData::Test *thr = sApp->test_thread_data(cpu);
        if (std::string time = format_duration(thr->fail_time); time.size())
            writeln(fd, "  - failed: { time: ", time,
                    ", loop-count: ", std::to_string(thr->inner_loop_count_at_fail),
                    " }");
        else if (verbosity > 2)
            writeln(fd, "  - loop-count: ", std::to_string(thr->inner_loop_count));
    }
}

void TapFormatLogger::print_thread_messages()
{
    for (int i = -1; i < num_cpus(); i++) {
        PerThreadData::Common *data = sApp->thread_data(i);
        struct mmap_region r = mmap_file(data->log_fd);

        if (r.size == 0 && !data->has_failed() && sApp->shmem->verbosity < 3)
            continue;           /* nothing to be printed, on any level */

        print_thread_header(file_log_fd, i, INT_MAX);
        int lowest_level = print_one_thread_messages(file_log_fd, data, r, INT_MAX);

        if (lowest_level <= sApp->shmem->verbosity && file_log_fd != real_stdout_fd) {
            print_thread_header(real_stdout_fd, i, sApp->shmem->verbosity);
            print_one_thread_messages(real_stdout_fd, data, r, sApp->shmem->verbosity);
        }

        munmap_file(r);
        truncate_log(data->log_fd);
    }
}

void TapFormatLogger::print_child_stderr()
{
    print_child_stderr_common([this](int fd) {
        maybe_print_yaml_marker(fd);
        writeln(fd, "  stderr messages: |");
    });
}

void YamlLogger::maybe_print_messages_header(int fd)
{
    bool *hdr = (fd == file_log_fd ? &file_printed_messages_header : &stdout_printed_messages_header);
    if (!*hdr) {
        writeln(fd, indent_spaces(), "  threads:");
        *hdr = true;
    }
}

std::string YamlLogger::thread_id_header(int cpu, int verbosity)
{
    struct cpu_info *info = cpu_info + cpu;
    std::string line = stdprintf("{ logical: %*d, package: %d, core: %*d, thread: %d",
                                 thread_core_spacing().logical, info->cpu_number, info->package_id,
                                 thread_core_spacing().core, info->core_id, info->thread_id);
    if (verbosity > 1) {
        auto add_value_or_null = [&line](const char *fmt, uint64_t value) {
            if (value)
                line += stdprintf(fmt, value);
            else
                line += "null";
        };
        line += stdprintf(", family: %d, model: %#02x, stepping: %d, microcode: ",
                          info->family, info->model, info->stepping);
        add_value_or_null("%#" PRIx64, info->microcode);
        line += ", ppin: ";
        add_value_or_null("\"%016" PRIx64 "\"", info->ppin);    // string to prevent loss of precision
    }
    line += " }";
    return line;
}

void YamlLogger::print_thread_header(int fd, int cpu, int verbosity)
{
    maybe_print_messages_header(fd);
    if (cpu < 0) {
        writeln(fd, indent_spaces(), "  - thread: main");
    } else {
        dprintf(fd, "%s  - thread: %d\n", indent_spaces().data(), cpu);
        dprintf(fd, "%s    id: %s\n", indent_spaces().data(), thread_id_header(cpu, verbosity).c_str());

        if (verbosity > 1) {
            PerThreadData::Test *thr = sApp->test_thread_data(cpu);
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
            const double effective_freq_mhz = thr->effective_freq_mhz;
            if (std::isfinite(effective_freq_mhz))
                dprintf(fd, "%s    freq_mhz: %.1f\n", indent_spaces().data(), effective_freq_mhz);
        }
    }
    writeln(fd, indent_spaces(), "    messages:");
}

int YamlLogger::print_test_knobs(int fd, mmap_region r)
{
    std::unordered_set<std::string_view> seen_keys;
    int print_count = 0;
    auto ptr = static_cast<const char *>(r.base);
    const char *end = ptr + r.size;
    const char *delim;

    for ( ; ptr < end; ptr = delim + 1) {
        delim = static_cast<const char *>(memchr(ptr, '\0', end - ptr));
        if (!delim)
            break;          // shouldn't happen...

        uint8_t code = uint8_t(*ptr++);
        if (log_type_from_code(code) != UsedKnobValue)
            continue;

        if (print_count++ == 0)
            writeln(fd, indent_spaces(), "  test-options:");

        std::string_view message(ptr, delim - ptr);
        size_t colon = message.find(':');
        assert(colon != std::string_view::npos);

        // check if we've already printed this key or not
        std::string_view key = message.substr(0, colon);
        if (auto [it, inserted] = seen_keys.insert(key); inserted)
            writeln(fd, indent_spaces(), "    ", message);
    }

    return print_count;
}

inline int YamlLogger::print_one_thread_messages(int fd, mmap_region r, int level)
{
    int lowest_level = INT_MAX;
    auto ptr = static_cast<const char *>(r.base);
    const char *end = ptr + r.size;
    const char *delim;

    for ( ; ptr < end; ptr = delim + 1) {
        delim = static_cast<const char *>(memchr(ptr, '\0', end - ptr));
        if (!delim)
            break;          // shouldn't happen...

        uint8_t code = uint8_t(*ptr++);
        int message_level = level_from_code(code);

        if (message_level > level)
            continue;

        std::string_view message(ptr, delim - ptr);
        if (message.empty())
            continue;       // shouldn't happen...

        switch (log_type_from_code(code)) {
        case UserMessages:
            format_and_print_message(fd, message_level, message, true);
            break;

        case Preformatted:
            IGNORE_RETVAL(write(fd, message.data(), message.size()));
            break;
        
        case SkipMessages:
            if (!skipInMainThread) {
                // Only print if the result line didn't already include this
                std::string skip_message;
                format_skip_message(skip_message, message);
                format_and_print_message(fd, 4, std::string_view{&skip_message[0], skip_message.size()}, true);
            }
            break;
        
        case UsedKnobValue:
            assert(sApp->shmem->log_test_knobs);
            continue;       // not break
        }

        if (message_level < lowest_level)
            lowest_level = message_level;
    }

    return lowest_level;
}

void YamlLogger::print_result_line()
{
    int loglevel = this->loglevel();
    if (loglevel == LOG_LEVEL_QUIET && file_log_fd != real_stdout_fd && sApp->shmem->verbosity < 1) {
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
            logging_printf(loglevel, "  skip-category: %s\n", "RuntimeSkipCategory");
            logging_printf(loglevel, "  skip-reason: %s\n",
                           "All CPUs skipped while executing 'test_run()' function, check log "
                           "for details");
        } else {
            std::string init_skip_message = get_skip_message(-1);
            if (init_skip_message.size() > 0) {
                logging_printf(loglevel, "  skip-category: %s\n",
                               char_to_skip_category(init_skip_message[0]));
                std::string_view message(&init_skip_message[1], init_skip_message.size()-1);
                if (loglevel <= sApp->shmem->verbosity)
                    format_and_print_message(real_stdout_fd, -1, message, false);
                if (file_log_fd != real_stdout_fd)
                    format_and_print_message(file_log_fd, -1, message, false);
            } else {
                logging_printf(loglevel, "  skip-category: %s\n", "UnknownSkipCategory");
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
             iso8601_time_now(Iso8601Format::WithoutMs));
}

void YamlLogger::print()
{
    Duration test_duration = MonotonicTimePoint::clock::now() - sApp->current_test_starttime;

    print_result_line();
    if (should_print_fail_info())
        logging_printf(LOG_LEVEL_QUIET, "%s", fail_info_details().c_str());
    logging_printf(LOG_LEVEL_VERBOSE(1), "  time-at-end:   %s\n", get_current_time().c_str());
    logging_printf(LOG_LEVEL_VERBOSE(1), "  test-runtime: %s\n",
                   format_duration(test_duration, FormatDurationOptions::WithoutUnit).c_str());

    double freqs = 0.0;
    for (int i = 0; i < num_cpus(); i++) {
        const PerThreadData::Test *data = sApp->test_thread_data(i);
        freqs += data->effective_freq_mhz;
    }

    const double freq_avg = freqs / num_cpus();
    if (std::isfinite(freq_avg) && freq_avg != 0.0)
        logging_printf(LOG_LEVEL_VERBOSE(1), "  avg-freq-mhz: %.1f\n", freq_avg);

    logging_flush();

    struct mmap_region main_mmap = mmap_file(sApp->main_thread_data()->log_fd);
    if (main_mmap.size && sApp->shmem->log_test_knobs) {
        int count = print_test_knobs(file_log_fd, main_mmap);
        if (count && real_stdout_fd != file_log_fd
                && sApp->shmem->verbosity >= UsedKnobValueLoggingLevel)
            print_test_knobs(real_stdout_fd, main_mmap);
    }

    // print the thread messages
    for (int i = -1; i < num_cpus(); i++) {
        PerThreadData::Common *data = sApp->thread_data(i);
        struct mmap_region r = i == -1 ? main_mmap : mmap_file(data->log_fd);

        if (r.size == 0 && !data->has_failed() && sApp->shmem->verbosity < 3)
            continue;           /* nothing to be printed, on any level */

        print_thread_header(file_log_fd, i, INT_MAX);
        int lowest_level = print_one_thread_messages(file_log_fd, r, INT_MAX);

        if (lowest_level <= sApp->shmem->verbosity && file_log_fd != real_stdout_fd) {
            print_thread_header(real_stdout_fd, i, sApp->shmem->verbosity);
            print_one_thread_messages(real_stdout_fd, r, sApp->shmem->verbosity);
        }

        munmap_file(r);
        truncate_log(data->log_fd);
    }

    print_child_stderr_common([](int fd) {
        writeln(fd, indent_spaces(), "  stderr messages: |");
    });

    logging_flush();
}

void YamlLogger::print_header(std::string_view cmdline, Duration test_duration, Duration test_timeout)
{
    logging_printf(LOG_LEVEL_QUIET, "command-line: '%s'\n", cmdline.data());
    logging_printf(LOG_LEVEL_QUIET, "version: " PROGRAM_VERSION "\n");
    logging_printf(LOG_LEVEL_VERBOSE(1), "os: %s\n", os_info().c_str());
    logging_printf(LOG_LEVEL_VERBOSE(1), "timing: { duration: %s, timeout: %s }\n",
                   format_duration(test_duration, FormatDurationOptions::WithoutUnit).c_str(),
                   format_duration(test_timeout, FormatDurationOptions::WithoutUnit).c_str());

    // print the CPU information
    int spacing = 1;
    if (num_cpus() > 9) {
        ++spacing;
        if (num_cpus() > 99)
            ++spacing;
    }
    logging_printf(LOG_LEVEL_VERBOSE(1), "cpu-info:\n");
    for (int i = 0; i < num_cpus(); ++i) {
        logging_printf(LOG_LEVEL_VERBOSE(1), "  %-*d: %s\n", spacing, i,
                       thread_id_header(i, LOG_LEVEL_VERBOSE(2)).c_str());
    }

    print_tests_header(AtStart);
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
    if (mode == AtStart && sApp->shmem->verbosity == 0 && file_log_fd != real_stdout_fd)
        return;

    if (file_log_fd != real_stdout_fd)
        writeln(real_stdout_fd, indent_spaces(), "tests:");
    state = Both;
}

/// prints the results from running the test \c{test} (test number \c{tc})
/// and returns the effective test result
TestResult logging_print_results(ChildExitStatus status, int *tc, const struct test *test)
{
    int n = ++*tc;
    switch (current_output_format()) {
    case SandstoneApplication::OutputFormat::key_value: {
        KeyValuePairLogger l(test, status);
        l.print(n);
        return l.testResult;
    }

    case SandstoneApplication::OutputFormat::tap: {
        TapFormatLogger l(test, status);
        l.print(n);
        return l.testResult;
    }

    case SandstoneApplication::OutputFormat::yaml: {
        YamlLogger l(test, status);
        l.print();
        return l.testResult;
    }

    case SandstoneApplication::OutputFormat::no_output:
        break;
    }

    return AbstractLogger(test, status).testResult;
}
