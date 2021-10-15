/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <ucontext.h>
#include <unistd.h>

#include <sandstone_p.h>

static const char environment_var[] = "STACK_SIZE_UPDATED";

static constexpr bool UseProcSelfExe =
#ifdef __linux__
        true
#else
        false
#endif
        ;

static __attribute__((cold)) void print_warning(const char *argv0)
{
    fprintf(stderr,
            "%s: warning: stack size in this system is too small and this tool could not\n"
            "find a way to increase it. Some tests may fail at runtime.\n", argv0);
}

void setup_stack_size(int argc, char **argv)
{
    ucontext_t uc = {};
    if (getcontext(&uc) == 0) {
        if (uc.uc_stack.ss_size >= THREAD_STACK_SIZE)
            return;     // we're good!
    } else {
        uc.uc_stack.ss_size = 0;
    }

    bool recursed = false;
    if (const char *env = getenv(environment_var); env && *env) {
        pid_t pid = atoi(env);
        recursed = (pid == getpid());
    }

    struct rlimit stacklim;
    if (getrlimit(RLIMIT_STACK, &stacklim) != 0)
        return print_warning(argv[0]);

    if (stacklim.rlim_cur >= THREAD_STACK_SIZE) {
        if (uc.uc_stack.ss_size)
            print_warning(argv[0]);     // getcontext above had succeeded
        return;
    }

    // prevent infinite recursion
    if (recursed)
        return print_warning(argv[0]);

    // update the stack values
    stacklim.rlim_cur = THREAD_STACK_SIZE;
    if (stacklim.rlim_max < THREAD_STACK_SIZE)
        stacklim.rlim_max = THREAD_STACK_SIZE;  // this may fail!
    if (setrlimit(RLIMIT_STACK, &stacklim) != 0)
        return print_warning(argv[0]);

    char *buf;
    IGNORE_RETVAL(asprintf(&buf, "%s=%d", environment_var, int(getpid())));
    putenv(buf);

    if (UseProcSelfExe)
        execv("/proc/self/exe", argv);
    else
        execvp(argv[0], argv);

    // if we get here, exec failed
    unsetenv(environment_var);
    free(buf);
    return print_warning(argv[0]);
}
