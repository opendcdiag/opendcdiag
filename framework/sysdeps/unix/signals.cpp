/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sandstone_system.h>
#include <sandstone.h>

#include <initializer_list>

#include <signal.h>

static constexpr std::initializer_list<int> termination_signals = {
    SIGHUP, SIGINT, SIGTERM, SIGPIPE
};

static std::atomic<uint64_t> signal_control;

// runs with a blocked signal mask, so this function doesn't need to be atomic
static void signal_handler(int signum)
{
    // communicate which signal we've received
    uint64_t value = signal_control.load(std::memory_order_relaxed);
    if (value == 0) {
        // first time we've received a signal, indicate which one
        value = uint64_t(signum) << 32;
    }

    ++value;
    signal_control.store(value, std::memory_order_relaxed);
}

SignalState last_signal()
{
    uint64_t value = signal_control.load(std::memory_order_relaxed);
    int signal = int(value >> 32);
    int count = int(value);
    return { .signal = signal, .count = count };
}

static void setup_signals(std::initializer_list<int> signals)
{
    struct sigaction sa = {};
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND;
    sa.sa_handler = signal_handler;

    for (int sig : signals)
        sigaddset(&sa.sa_mask, sig);
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
