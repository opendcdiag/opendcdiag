/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sandstone_system.h>
#include <sandstone.h>

#include <initializer_list>

#include <signal.h>
#include <sys/wait.h>

static constexpr std::initializer_list<int> termination_signals = {
    SIGHUP, SIGINT, SIGTERM, SIGPIPE
};

#  if (defined(__WAIT_INT) && defined(__linux__)) || defined(__APPLE__)
// glibc prior to 2.24 defined WTERMSIG with compatibility with BSD union wait
// Apple libc does the same
static constexpr uint32_t SignalMask = 0x7f;
#  else
static constexpr uint32_t SignalMask = WTERMSIG(~0);
#  endif
static constexpr int SignalBits = __builtin_clz(SignalMask + 1);
static_assert(SignalMask >> SignalBits == 0, "Sanity check");
static std::atomic<uint32_t> signal_control;

static void signal_handler(int signum)
{
    // communicate which signal we've received
    uint32_t expected = 0;
    if (signal_control.compare_exchange_strong(expected, W_EXITCODE(1, signum), std::memory_order_relaxed)) {
        // initial clean up
    } else {
        // just increment the counter
        signal_control.fetch_add(W_EXITCODE(1, 0), std::memory_order_relaxed);
    }
}

SignalState last_signal()
{
    uint32_t cur_sig_state = signal_control.load(std::memory_order_relaxed);
    int signal = WTERMSIG(cur_sig_state);
    int count = cur_sig_state >> SignalBits;
    return { .signal = signal, .count = count };
}

static void setup_signals(std::initializer_list<int> signals)
{
    struct sigaction sa = {};
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND;
    sa.sa_handler = signal_handler;
    for (int sig : signals)
        sigaction(sig, &sa, nullptr);
}

void setup_signals()
{
     setup_signals(termination_signals);
}

void setup_child_signals()
{
    // create a new session so the parent will get SIGHUP/SIGINT instead of us
    IGNORE_RETVAL(setsid());

    // restore termination signals
    struct sigaction sa = {};
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_DFL;
    for (int sig : termination_signals)
        sigaction(sig, &sa, nullptr);
}

void enable_interrupt_catch()
{
    setup_signals({ SIGINT });
}

void disable_interrupt_catch()
{
    signal(SIGINT, SIG_DFL);
}

