/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_SYSTEM_H
#define SANDSTONE_SYSTEM_H

#include <stdint.h>

/* resource.cpp */
void resource_init_global();

/* signals.cpp */
struct SignalState
{
    intptr_t signal;
    intptr_t count;
};

void signals_init_global();
void signals_init_child();
#ifdef _WIN32
inline SignalState last_signal()
{
    // On Windows, we don't (currently) catch any signals
    return { };
}
inline void enable_interrupt_catch() {}
inline void disable_interrupt_catch() {}
#else
SignalState last_signal();
void enable_interrupt_catch();
void disable_interrupt_catch();
#endif

/* stacksize.cpp */
#ifdef _WIN32
static inline void setup_stack_size(int, char **)
{
    // On Windows, we know the OS obeys the -Wl,--stack= argument
}
#else
void setup_stack_size(int argc, char **argv);
#endif

#endif // SANDSTONE_SYSTEM_H
