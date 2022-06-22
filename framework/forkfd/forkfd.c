/****************************************************************************
**
** Copyright (C) 2020 Intel Corporation.
** Copyright (C) 2015 Klarälvdalens Datakonsult AB, a KDAB Group company, info@kdab.com
**
** Permission is hereby granted, free of charge, to any person obtaining a copy
** of this software and associated documentation files (the "Software"), to deal
** in the Software without restriction, including without limitation the rights
** to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
** copies of the Software, and to permit persons to whom the Software is
** furnished to do so, subject to the following conditions:
**
** The above copyright notice and this permission notice shall be included in
** all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
** THE SOFTWARE.
**
****************************************************************************/

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include "forkfd.h"

/* Macros fine-tuning the build: */
//#define FORKFD_NO_FORKFD 1                /* disable the forkfd() function */
//#define FORKFD_NO_SPAWNFD 1               /* disable the spawnfd() function */
//#define FORKFD_DISABLE_FORK_FALLBACK 1    /* disable falling back to fork() from system_forkfd() */

#include <sys/types.h>
#if defined(__OpenBSD__) || defined(__NetBSD__)
#  include <sys/param.h>
#endif
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#  define HAVE_WAIT4    1
#  if defined(__BIONIC__) || (defined(__GLIBC__) && (__GLIBC__ << 8) + __GLIBC_MINOR__ >= 0x208 && \
       (!defined(__UCLIBC__) || ((__UCLIBC_MAJOR__ << 16) + (__UCLIBC_MINOR__ << 8) + __UCLIBC_SUBLEVEL__ > 0x90201)))
#    include <sys/eventfd.h>
#    ifdef EFD_CLOEXEC
#      define HAVE_EVENTFD  1
#    endif
#  endif
#  if defined(__BIONIC__) || (defined(__GLIBC__) && (__GLIBC__ << 8) + __GLIBC_MINOR__ >= 0x209 && \
       (!defined(__UCLIBC__) || ((__UCLIBC_MAJOR__ << 16) + (__UCLIBC_MINOR__ << 8) + __UCLIBC_SUBLEVEL__ > 0x90201)))
#    define HAVE_PIPE2    1
#  endif
#endif

#if _POSIX_VERSION-0 >= 200809L || _XOPEN_VERSION-0 >= 500
#  define HAVE_WAITID   1
#endif
#if !defined(WEXITED) || !defined(WNOWAIT)
#  undef HAVE_WAITID
#endif

#if (defined(__FreeBSD__) && defined(__FreeBSD_version) && __FreeBSD_version >= 1000032) || \
    (defined(__OpenBSD__) && OpenBSD >= 201505) || \
    (defined(__NetBSD__) && __NetBSD_Version__ >= 600000000)
#  define HAVE_PIPE2    1
#endif
#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__FreeBSD_kernel__) || \
    defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
#  define HAVE_WAIT4    1
#endif

#if defined(__APPLE__)
/* Up until OS X 10.7, waitid(P_ALL, ...) will return success, but will not
 * fill in the details of the dead child. That means waitid is not useful to us.
 * Therefore, we only enable waitid() support if we're targetting OS X 10.8 or
 * later.
 */
#  include <Availability.h>
#  include <AvailabilityMacros.h>
#  if MAC_OS_X_VERSION_MIN_REQUIRED <= 1070
#    define HAVE_BROKEN_WAITID 1
#  endif
#endif

#include "forkfd_atomic.h"

static int system_has_forkfd(void);
static int system_forkfd(int flags, pid_t *ppid, int *system);
static int system_vforkfd(int flags, pid_t *ppid, int (*)(void *), void *, int *system);
static int system_forkfd_wait(int ffd, struct forkfd_info *info, int ffdwoptions, struct rusage *rusage);

static int disable_fork_fallback(void)
{
#ifdef FORKFD_DISABLE_FORK_FALLBACK
    /* if there's no system forkfd, we have to use the fallback */
    return system_has_forkfd();
#else
    return 0;
#endif
}

#define CHILDREN_IN_SMALL_ARRAY     16
#define CHILDREN_IN_BIG_ARRAY       256
#define sizeofarray(array)          (sizeof(array)/sizeof(array[0]))
#define EINTR_LOOP(ret, call) \
    do {                      \
        ret = call;           \
    } while (ret == -1 && errno == EINTR)

struct pipe_payload
{
    struct forkfd_info info;
    struct rusage rusage;
};

typedef struct process_info
{
    ffd_atomic_int pid;
    int deathPipe;
} ProcessInfo;

struct BigArray;
typedef struct Header
{
    ffd_atomic_pointer(struct BigArray) nextArray;
    ffd_atomic_int busyCount;
} Header;

typedef struct BigArray
{
    Header header;
    ProcessInfo entries[CHILDREN_IN_BIG_ARRAY];
} BigArray;

typedef struct SmallArray
{
    Header header;
    ProcessInfo entries[CHILDREN_IN_SMALL_ARRAY];
} SmallArray;
static SmallArray children;

static struct sigaction old_sigaction;
static pthread_once_t forkfd_initialization = PTHREAD_ONCE_INIT;
static ffd_atomic_int forkfd_status = FFD_ATOMIC_INIT(0);

#ifdef HAVE_BROKEN_WAITID
static int waitid_works = 0;
#else
static const int waitid_works = 1;
#endif

static ProcessInfo *tryAllocateInSection(Header *header, ProcessInfo entries[], int maxCount)
{
    /* we use ACQUIRE here because the signal handler might have released the PID */
    int busyCount = ffd_atomic_add_fetch(&header->busyCount, 1, FFD_ATOMIC_ACQUIRE);
    if (busyCount <= maxCount) {
        /* there's an available entry in this section, find it and take it */
        int i;
        for (i = 0; i < maxCount; ++i) {
            /* if the PID is 0, it's free; mark it as used by swapping it with -1 */
            int expected_pid = 0;
            if (ffd_atomic_compare_exchange(&entries[i].pid, &expected_pid,
                                            -1, FFD_ATOMIC_RELAXED, FFD_ATOMIC_RELAXED))
                return &entries[i];
        }
    }

    /* there isn't an available entry, undo our increment */
    (void)ffd_atomic_add_fetch(&header->busyCount, -1, FFD_ATOMIC_RELAXED);
    return NULL;
}

static ProcessInfo *allocateInfo(Header **header)
{
    Header *currentHeader = &children.header;

    /* try to find an available entry in the small array first */
    ProcessInfo *info =
            tryAllocateInSection(currentHeader, children.entries, sizeofarray(children.entries));

    /* go on to the next arrays */
    while (info == NULL) {
        BigArray *array = ffd_atomic_load(&currentHeader->nextArray, FFD_ATOMIC_ACQUIRE);
        if (array == NULL) {
            /* allocate an array and try to use it */
            BigArray *allocatedArray = (BigArray *)calloc(1, sizeof(BigArray));
            if (allocatedArray == NULL)
                return NULL;

            if (ffd_atomic_compare_exchange(&currentHeader->nextArray, &array, allocatedArray,
                                             FFD_ATOMIC_RELEASE, FFD_ATOMIC_ACQUIRE)) {
                /* success */
                array = allocatedArray;
            } else {
                /* failed, the atomic updated 'array' */
                free(allocatedArray);
            }
        }

        currentHeader = &array->header;
        info = tryAllocateInSection(currentHeader, array->entries, sizeofarray(array->entries));
    }

    *header = currentHeader;
    return info;
}

#ifdef HAVE_WAITID
static int isChildReady(pid_t pid, siginfo_t *info)
{
    info->si_pid = 0;
    return waitid(P_PID, pid, info, WEXITED | WNOHANG | WNOWAIT) == 0 && info->si_pid == pid;
}
#endif

static void convertStatusToForkfdInfo(int status, struct forkfd_info *info)
{
    if (WIFEXITED(status)) {
        info->code = CLD_EXITED;
        info->status = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        info->code = CLD_KILLED;
#  ifdef WCOREDUMP
        if (WCOREDUMP(status))
            info->code = CLD_DUMPED;
#  endif
        info->status = WTERMSIG(status);
    }
}

#ifdef __GNUC__
__attribute__((unused))
#endif
static int convertForkfdWaitFlagsToWaitFlags(int ffdoptions)
{
    int woptions = WEXITED;
    if (ffdoptions & FFDW_NOWAIT)
        woptions |= WNOWAIT;
    if (ffdoptions & FFDW_NOHANG)
        woptions |= WNOHANG;
    return woptions;
}

static int tryReaping(pid_t pid, struct pipe_payload *payload)
{
    /* reap the child */
#if defined(HAVE_WAIT4)
    int status;
    if (wait4(pid, &status, WNOHANG, &payload->rusage) <= 0)
        return 0;
    convertStatusToForkfdInfo(status, &payload->info);
#else
#  if defined(HAVE_WAITID)
    if (waitid_works) {
        /* we have waitid(2), which gets us some payload values on some systems */
        siginfo_t info;
        info.si_pid = 0;
        int ret = waitid(P_PID, pid, &info, WEXITED | WNOHANG) == 0 && info.si_pid == pid;
        if (!ret)
            return ret;

        payload->info.code = info.si_code;
        payload->info.status = info.si_status;
#    ifdef __linux__
        payload->rusage.ru_utime.tv_sec = info.si_utime / CLOCKS_PER_SEC;
        payload->rusage.ru_utime.tv_usec = info.si_utime % CLOCKS_PER_SEC;
        payload->rusage.ru_stime.tv_sec = info.si_stime / CLOCKS_PER_SEC;
        payload->rusage.ru_stime.tv_usec = info.si_stime % CLOCKS_PER_SEC;
#    endif
        return 1;
    }
#  endif // HAVE_WAITID
    int status;
    if (waitpid(pid, &status, WNOHANG) <= 0)
        return 0;     // child did not change state
    convertStatusToForkfdInfo(status, &payload->info);
#endif // !HAVE_WAIT4

    return 1;
}

static void freeInfo(Header *header, ProcessInfo *entry)
{
    entry->deathPipe = -1;
    ffd_atomic_store(&entry->pid, 0, FFD_ATOMIC_RELEASE);

    (void)ffd_atomic_add_fetch(&header->busyCount, -1, FFD_ATOMIC_RELEASE);
    assert(header->busyCount >= 0);
}

static void notifyAndFreeInfo(Header *header, ProcessInfo *entry,
                              const struct pipe_payload *payload)
{
    ssize_t ret;
    EINTR_LOOP(ret, write(entry->deathPipe, payload, sizeof(*payload)));
    EINTR_LOOP(ret, close(entry->deathPipe));

    freeInfo(header, entry);
}

static void reapChildProcesses();
static void sigchld_handler(int signum, siginfo_t *handler_info, void *handler_context)
{
    /*
     * This is a signal handler, so we need to be careful about which functions
     * we can call. See the full, official listing in the POSIX.1-2008
     * specification at:
     *   http://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html#tag_15_04_03
     *
     * The handler_info and handler_context parameters may not be valid, if
     * we're a chained handler from another handler that did not use
     * SA_SIGINFO. Therefore, we must obtain the siginfo ourselves directly by
     * calling waitid.
     *
     * But we pass them anyway. Let's call the chained handler first, while
     * those two arguments have a chance of being correct.
     */
    if (old_sigaction.sa_handler != SIG_IGN && old_sigaction.sa_handler != SIG_DFL) {
        if (old_sigaction.sa_flags & SA_SIGINFO)
            old_sigaction.sa_sigaction(signum, handler_info, handler_context);
        else
            old_sigaction.sa_handler(signum);
    }

    if (ffd_atomic_load(&forkfd_status, FFD_ATOMIC_RELAXED) == 1) {
        int saved_errno = errno;
        reapChildProcesses();
        errno = saved_errno;
    }
}

static inline void reapChildProcesses()
{
    /* is this one of our children? */
    BigArray *array;
    siginfo_t info;
    struct pipe_payload payload;
    int i;

    memset(&info, 0, sizeof info);
    memset(&payload, 0, sizeof payload);

#ifdef HAVE_WAITID
    if (waitid_works) {
        /* be optimistic: try to see if we can get the child that exited */
search_next_child:
        /* waitid returns -1 ECHILD if there are no further children at all;
         * it returns 0 and sets si_pid to 0 if there are children but they are not ready
         * to be waited (we're passing WNOHANG). We should not get EINTR because
         * we're passing WNOHANG and we should definitely not get EINVAL or anything else.
         * That means we can actually ignore the return code and only inspect si_pid.
         */
        info.si_pid = 0;
        waitid(P_ALL, 0, &info, WNOHANG | WNOWAIT | WEXITED);
        if (info.si_pid == 0) {
            /* there are no further un-waited-for children, so we can just exit.
             */
            return;
        }

        for (i = 0; i < (int)sizeofarray(children.entries); ++i) {
            /* acquire the child first: swap the PID with -1 to indicate it's busy */
            int pid = info.si_pid;
            if (ffd_atomic_compare_exchange(&children.entries[i].pid, &pid, -1,
                                            FFD_ATOMIC_ACQUIRE, FFD_ATOMIC_RELAXED)) {
                /* this is our child, send notification and free up this entry */
                /* ### FIXME: what if tryReaping returns false? */
                if (tryReaping(pid, &payload))
                    notifyAndFreeInfo(&children.header, &children.entries[i], &payload);
                goto search_next_child;
            }
        }

        /* try the arrays */
        array = ffd_atomic_load(&children.header.nextArray, FFD_ATOMIC_ACQUIRE);
        while (array != NULL) {
            for (i = 0; i < (int)sizeofarray(array->entries); ++i) {
                int pid = info.si_pid;
                if (ffd_atomic_compare_exchange(&array->entries[i].pid, &pid, -1,
                                                FFD_ATOMIC_ACQUIRE, FFD_ATOMIC_RELAXED)) {
                    /* this is our child, send notification and free up this entry */
                    /* ### FIXME: what if tryReaping returns false? */
                    if (tryReaping(pid, &payload))
                        notifyAndFreeInfo(&array->header, &array->entries[i], &payload);
                    goto search_next_child;
                }
            }

            array = ffd_atomic_load(&array->header.nextArray, FFD_ATOMIC_ACQUIRE);
        }

        /* if we got here, we couldn't find this child in our list. That means this child
         * belongs to one of the chained SIGCHLD handlers. However, there might be another
         * child that exited and does belong to us, so we need to check each one individually.
         */
    }
#endif

    for (i = 0; i < (int)sizeofarray(children.entries); ++i) {
        int pid = ffd_atomic_load(&children.entries[i].pid, FFD_ATOMIC_ACQUIRE);
        if (pid <= 0)
            continue;
#ifdef HAVE_WAITID
        if (waitid_works) {
            /* The child might have been reaped by the block above in another thread,
             * so first check if it's ready and, if it is, lock it */
            if (!isChildReady(pid, &info) ||
                    !ffd_atomic_compare_exchange(&children.entries[i].pid, &pid, -1,
                                                 FFD_ATOMIC_RELAXED, FFD_ATOMIC_RELAXED))
                continue;
        }
#endif
        if (tryReaping(pid, &payload)) {
            /* this is our child, send notification and free up this entry */
            notifyAndFreeInfo(&children.header, &children.entries[i], &payload);
        }
    }

    /* try the arrays */
    array = ffd_atomic_load(&children.header.nextArray, FFD_ATOMIC_ACQUIRE);
    while (array != NULL) {
        for (i = 0; i < (int)sizeofarray(array->entries); ++i) {
            int pid = ffd_atomic_load(&array->entries[i].pid, FFD_ATOMIC_ACQUIRE);
            if (pid <= 0)
                continue;
#ifdef HAVE_WAITID
            if (waitid_works) {
                /* The child might have been reaped by the block above in another thread,
                 * so first check if it's ready and, if it is, lock it */
                if (!isChildReady(pid, &info) ||
                        !ffd_atomic_compare_exchange(&array->entries[i].pid, &pid, -1,
                                                     FFD_ATOMIC_RELAXED, FFD_ATOMIC_RELAXED))
                    continue;
            }
#endif
            if (tryReaping(pid, &payload)) {
                /* this is our child, send notification and free up this entry */
                notifyAndFreeInfo(&array->header, &array->entries[i], &payload);
            }
        }

        array = ffd_atomic_load(&array->header.nextArray, FFD_ATOMIC_ACQUIRE);
    }
}

static void ignore_sigpipe()
{
#ifdef O_NOSIGPIPE
    static ffd_atomic_int done = FFD_ATOMIC_INIT(0);
    if (ffd_atomic_load(&done, FFD_ATOMIC_RELAXED))
        return;
#endif

    struct sigaction action;
    memset(&action, 0, sizeof action);
    sigemptyset(&action.sa_mask);
    action.sa_handler = SIG_IGN;
    action.sa_flags = 0;
    sigaction(SIGPIPE, &action, NULL);

#ifdef O_NOSIGPIPE
    ffd_atomic_store(&done, 1, FFD_ATOMIC_RELAXED);
#endif
}

#if defined(__GNUC__) && (!defined(__FreeBSD__) || __FreeBSD__ < 10)
__attribute((destructor, unused)) static void cleanup();
#endif

static void cleanup()
{
    BigArray *array;
    /* This function is not thread-safe!
     * It must only be called when the process is shutting down.
     * At shutdown, we expect no one to be calling forkfd(), so we don't
     * need to be thread-safe with what is done there.
     *
     * But SIGCHLD might be delivered to any thread, including this one.
     * There's no way to prevent that. The correct solution would be to
     * cooperatively delete. We don't do that.
     */
    if (ffd_atomic_load(&forkfd_status, FFD_ATOMIC_RELAXED) == 0)
        return;

    /* notify the handler that we're no longer in operation */
    ffd_atomic_store(&forkfd_status, 0, FFD_ATOMIC_RELAXED);

    /* free any arrays we might have */
    array = ffd_atomic_load(&children.header.nextArray, FFD_ATOMIC_ACQUIRE);
    while (array != NULL) {
        BigArray *next = ffd_atomic_load(&array->header.nextArray, FFD_ATOMIC_ACQUIRE);
        free(array);
        array = next;
    }
}

static void forkfd_initialize()
{
#if defined(HAVE_BROKEN_WAITID)
    pid_t pid = fork();
    if (pid == 0) {
        _exit(0);
    } else if (pid > 0) {
        siginfo_t info;
        waitid(P_ALL, 0, &info, WNOWAIT | WEXITED);
        waitid_works = (info.si_pid != 0);
        info.si_pid = 0;

        // now really reap the child
        waitid(P_PID, pid, &info, WEXITED);
        waitid_works = waitid_works && (info.si_pid != 0);
    }
#endif

    /* install our signal handler */
    struct sigaction action;
    memset(&action, 0, sizeof action);
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_NOCLDSTOP | SA_SIGINFO;
    action.sa_sigaction = sigchld_handler;

    /* ### RACE CONDITION
     * The sigaction function does a memcpy from an internal buffer
     * to old_sigaction, which we use in the SIGCHLD handler. If a
     * SIGCHLD is delivered before or during that memcpy, the handler will
     * see an inconsistent state.
     *
     * There is no solution. pthread_sigmask doesn't work here because the
     * signal could be delivered to another thread.
     */
    sigaction(SIGCHLD, &action, &old_sigaction);

#ifndef O_NOSIGPIPE
    /* disable SIGPIPE too */
    ignore_sigpipe();
#endif

#ifdef __GNUC__
    (void) cleanup; /* suppress unused static function warning */
#else
    atexit(cleanup);
#endif

    ffd_atomic_store(&forkfd_status, 1, FFD_ATOMIC_RELAXED);
}

static int create_pipe(int filedes[], int flags)
{
    int ret = -1;
#ifdef HAVE_PIPE2
    /* use pipe2(2) whenever possible, since it can thread-safely create a
     * cloexec pair of pipes. Without it, we have a race condition setting
     * FD_CLOEXEC
     */

#  ifdef O_NOSIGPIPE
    /* try first with O_NOSIGPIPE */
    ret = pipe2(filedes, O_CLOEXEC | O_NOSIGPIPE);
    if (ret == -1) {
        /* O_NOSIGPIPE not supported, ignore SIGPIPE */
        ignore_sigpipe();
    }
#  endif
    if (ret == -1)
        ret = pipe2(filedes, O_CLOEXEC);
    if (ret == -1)
        return ret;

    if ((flags & FFD_CLOEXEC) == 0)
        fcntl(filedes[0], F_SETFD, 0);
#else
    ret = pipe(filedes);
    if (ret == -1)
        return ret;

    fcntl(filedes[1], F_SETFD, FD_CLOEXEC);
    if (flags & FFD_CLOEXEC)
        fcntl(filedes[0], F_SETFD, FD_CLOEXEC);
#endif
    if (flags & FFD_NONBLOCK)
        fcntl(filedes[0], F_SETFL, fcntl(filedes[0], F_GETFL) | O_NONBLOCK);
    return ret;
}

#ifndef FORKFD_NO_FORKFD
static int forkfd_fork_fallback(int flags, pid_t *ppid)
{
    Header *header;
    ProcessInfo *info;
    pid_t pid;
    int fd = -1;
    int death_pipe[2];
    int sync_pipe[2];
    int ret;
#ifdef __linux__
    int efd;
#endif

    (void) pthread_once(&forkfd_initialization, forkfd_initialize);

    info = allocateInfo(&header);
    if (info == NULL) {
        errno = ENOMEM;
        return -1;
    }

    /* create the pipes before we fork */
    if (create_pipe(death_pipe, flags) == -1)
        goto err_free; /* failed to create the pipes, pass errno */

#ifdef HAVE_EVENTFD
    /* try using an eventfd, which consumes less resources */
    efd = eventfd(0, EFD_CLOEXEC);
    if (efd == -1)
#endif
    {
        /* try a pipe */
        if (create_pipe(sync_pipe, FFD_CLOEXEC) == -1) {
            /* failed both at eventfd and pipe; fail and pass errno */
            goto err_close;
        }
    }

    /* now fork */
    pid = fork();
    if (pid == -1)
        goto err_close2; /* failed to fork, pass errno */
    if (ppid)
        *ppid = pid;

    /*
     * We need to store the child's PID in the info structure, so
     * the SIGCHLD handler knows that this child is present and it
     * knows the writing end of the pipe to pass information on.
     * However, the child process could exit before we stored the
     * information (or the handler could run for other children exiting).
     * We prevent that from happening by blocking the child process in
     * a read(2) until we're finished storing the information.
     */
    if (pid == 0) {
        /* this is the child process */
        /* first, wait for the all clear */
#ifdef HAVE_EVENTFD
        if (efd != -1) {
            eventfd_t val64;
            EINTR_LOOP(ret, eventfd_read(efd, &val64));
            EINTR_LOOP(ret, close(efd));
        } else
#endif
        {
            char c;
            EINTR_LOOP(ret, close(sync_pipe[1]));
            EINTR_LOOP(ret, read(sync_pipe[0], &c, sizeof c));
            EINTR_LOOP(ret, close(sync_pipe[0]));
        }

        /* now close the pipes and return to the caller */
        EINTR_LOOP(ret, close(death_pipe[0]));
        EINTR_LOOP(ret, close(death_pipe[1]));
        fd = FFD_CHILD_PROCESS;
    } else {
        /* parent process */
        info->deathPipe = death_pipe[1];
        fd = death_pipe[0];
        ffd_atomic_store(&info->pid, pid, FFD_ATOMIC_RELEASE);

        /* release the child */
#ifdef HAVE_EVENTFD
        if (efd != -1) {
            eventfd_t val64 = 42;
            EINTR_LOOP(ret, eventfd_write(efd, val64));
            EINTR_LOOP(ret, close(efd));
        } else
#endif
        {
            /*
             * Usually, closing would be enough to make read(2) return and the child process
             * continue. We need to write here: another thread could be calling forkfd at the
             * same time, which means auxpipe[1] might be open in another child process.
             */
            EINTR_LOOP(ret, close(sync_pipe[0]));
            EINTR_LOOP(ret, write(sync_pipe[1], "", 1));
            EINTR_LOOP(ret, close(sync_pipe[1]));
        }
    }

    return fd;

err_close2:
#ifdef HAVE_EVENTFD
    if (efd != -1) {
        EINTR_LOOP(ret, close(efd));
    } else
#endif
    {
        EINTR_LOOP(ret, close(sync_pipe[0]));
        EINTR_LOOP(ret, close(sync_pipe[1]));
    }
err_close:
    EINTR_LOOP(ret, close(death_pipe[0]));
    EINTR_LOOP(ret, close(death_pipe[1]));
err_free:
    /* free the info pointer */
    freeInfo(header, info);
    return -1;
}

/**
 * @brief forkfd returns a file descriptor representing a child process
 * @return a file descriptor, or -1 in case of failure
 *
 * forkfd() creates a file descriptor that can be used to be notified of when a
 * child process exits. This file descriptor can be monitored using select(2),
 * poll(2) or similar mechanisms.
 *
 * The @a flags parameter can contain the following values ORed to change the
 * behaviour of forkfd():
 *
 * @li @c FFD_NONBLOCK Set the O_NONBLOCK file status flag on the new open file
 * descriptor. Using this flag saves extra calls to fnctl(2) to achieve the same
 * result.
 *
 * @li @c FFD_CLOEXEC Set the close-on-exec (FD_CLOEXEC) flag on the new file
 * descriptor. You probably want to set this flag, since forkfd() does not work
 * if the original parent process dies.
 *
 * @li @c FFD_USE_FORK Tell forkfd() to actually call fork() instead of a
 * different system implementation that may be available. On systems where a
 * different implementation is available, its behavior may differ from that of
 * fork(), such as not calling the functions registered with pthread_atfork().
 * If that's necessary, pass this flag.
 *
 * The file descriptor returned by forkfd() supports the following operations:
 *
 * @li read(2) When the child process exits, then the buffer supplied to
 * read(2) is used to return information about the status of the child in the
 * form of one @c siginfo_t structure. The buffer must be at least
 * sizeof(siginfo_t) bytes. The return value of read(2) is the total number of
 * bytes read.
 *
 * @li poll(2), select(2) (and similar) The file descriptor is readable (the
 * select(2) readfds argument; the poll(2) POLLIN flag) if the child has exited
 * or signalled via SIGCHLD.
 *
 * @li close(2) When the file descriptor is no longer required it should be closed.
 */
int forkfd(int flags, pid_t *ppid)
{
    int fd;
    if (disable_fork_fallback())
        flags &= ~FFD_USE_FORK;

    if ((flags & FFD_USE_FORK) == 0) {
        int system_forkfd_works;
        fd = system_forkfd(flags, ppid, &system_forkfd_works);
        if (system_forkfd_works || disable_fork_fallback())
            return fd;
    }

    return forkfd_fork_fallback(flags, ppid);
}

/**
 * @brief vforkfd returns a file descriptor representing a child process
 * @return a file descriptor, or -1 in case of failure
 *
 * vforkfd() operates in the same way as forkfd() and the @a flags and @a ppid
 * arguments are the same. See the forkfd() documentation for details on the
 * possible values and information on the returned file descriptor.
 *
 * This function does not return @c FFD_CHILD_PROCESS. Instead, the function @a
 * childFn is called in the child process with the @a token parameter as
 * argument. If that function returns, its return value will be passed to
 * _exit(2).
 *
 * This function differs from forkfd() the same way that vfork() differs from
 * fork(): the parent process may be suspended while the child is has not yet
 * called _exit(2) or execve(2). Additionally, on some systems, the child
 * process may share memory with the parent process the same way an auxiliary
 * thread would, so extreme care should be employed on what functions the child
 * process uses before termination.
 *
 * The @c FFD_USE_FORK flag retains its behavior as described in the forkfd()
 * documentation, including that of actually using fork(2) and no other
 * implementation.
 *
 * Currently, only on Linux will this function have any behavior different from
 * forkfd(). In all other systems, it is equivalent to the following code:
 *
 * @code
 *     int ffd = forkfd(flags, &pid);
 *     if (ffd == FFD_CHILD_PROCESS)
 *         _exit(childFn(token));
 * @endcode
 */
int vforkfd(int flags, pid_t *ppid, int (*childFn)(void *), void *token)
{
    int fd;
    if ((flags & FFD_USE_FORK) == 0) {
        int system_forkfd_works;
        fd = system_vforkfd(flags, ppid, childFn, token, &system_forkfd_works);
        if (system_forkfd_works || disable_fork_fallback())
            return fd;
    }

    fd = forkfd_fork_fallback(flags, ppid);
    if (fd == FFD_CHILD_PROCESS) {
        /* child process */
        _exit(childFn(token));
    }
    return fd;
}
#endif // FORKFD_NO_FORKFD

#if _POSIX_SPAWN > 0 && !defined(FORKFD_NO_SPAWNFD)
int spawnfd(int flags, pid_t *ppid, const char *path, const posix_spawn_file_actions_t *file_actions,
            posix_spawnattr_t *attrp, char *const argv[], char *const envp[])
{
    Header *header;
    ProcessInfo *info;
    struct pipe_payload payload;
    pid_t pid;
    int death_pipe[2];
    int ret = -1;
    /* we can only do work if we have a way to start the child in stopped mode;
     * otherwise, we have a major race condition. */

    assert(!system_has_forkfd());

    (void) pthread_once(&forkfd_initialization, forkfd_initialize);

    info = allocateInfo(&header);
    if (info == NULL) {
        errno = ENOMEM;
        goto out;
    }

    /* create the pipe before we spawn */
    if (create_pipe(death_pipe, flags) == -1)
        goto err_free; /* failed to create the pipes, pass errno */

    /* start the process */
    if (flags & FFD_SPAWN_SEARCH_PATH) {
        /* use posix_spawnp */
        if (posix_spawnp(&pid, path, file_actions, attrp, argv, envp) != 0)
            goto err_close;
    } else {
        if (posix_spawn(&pid, path, file_actions, attrp, argv, envp) != 0)
            goto err_close;
    }

    if (ppid)
        *ppid = pid;

    /* Store the child's PID in the info structure.
     */
    info->deathPipe = death_pipe[1];
    ffd_atomic_store(&info->pid, pid, FFD_ATOMIC_RELEASE);

    /* check if the child has already exited */
    if (tryReaping(pid, &payload))
        notifyAndFreeInfo(header, info, &payload);

    ret = death_pipe[0];
    return ret;

err_close:
    EINTR_LOOP(ret, close(death_pipe[0]));
    EINTR_LOOP(ret, close(death_pipe[1]));

err_free:
    /* free the info pointer */
    freeInfo(header, info);

out:
    return -1;
}
#endif // _POSIX_SPAWN && !FORKFD_NO_SPAWNFD

int forkfd_wait4(int ffd, struct forkfd_info *info, int options, struct rusage *rusage)
{
    struct pipe_payload payload;
    int ret;

    if (system_has_forkfd()) {
        /* if this is one of our pipes, not a procdesc/pidfd, we'll get an EBADF */
        ret = system_forkfd_wait(ffd, info, options, rusage);
        if (disable_fork_fallback() || ret != -1 || errno != EBADF)
            return ret;
    }

    ret = read(ffd, &payload, sizeof(payload));
    if (ret == -1)
        return ret;     /* pass errno, probably EINTR, EBADF or EWOULDBLOCK */

    assert(ret == sizeof(payload));
    if (info)
        *info = payload.info;
    if (rusage)
        *rusage = payload.rusage;

    return 0;           /* success */
}


int forkfd_close(int ffd)
{
    return close(ffd);
}

#if defined(__FreeBSD__) && __FreeBSD__ >= 9
#  include "forkfd_freebsd.c"
#elif defined(__linux__)
#  include "forkfd_linux.c"
#else
int system_has_forkfd()
{
    return 0;
}

int system_forkfd(int flags, pid_t *ppid, int *system)
{
    (void)flags;
    (void)ppid;
    *system = 0;
    return -1;
}

int system_forkfd_wait(int ffd, struct forkfd_info *info, int options, struct rusage *rusage)
{
    (void)ffd;
    (void)info;
    (void)options;
    (void)rusage;
    return -1;
}
#endif
#ifndef SYSTEM_FORKFD_CAN_VFORK
int system_vforkfd(int flags, pid_t *ppid, int (*childFn)(void *), void *token, int *system)
{
    /* we don't have a way to vfork(), so fake it */
    int ret = system_forkfd(flags, ppid, system);
    if (ret == FFD_CHILD_PROCESS) {
        /* child process */
        _exit(childFn(token));
    }
    return ret;
}
#endif
#undef SYSTEM_FORKFD_CAN_VFORK
