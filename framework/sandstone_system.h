/*
 * Copyright 2022 Intel Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_SYSTEM_H
#define SANDSTONE_SYSTEM_H

#include <stdint.h>

/* signals.cpp */
struct SignalState
{
    intptr_t signal;
    intptr_t count;
};

void setup_signals();
void setup_child_signals();
SignalState last_signal();
void enable_interrupt_catch();      // Unix only
void disable_interrupt_catch();     // Unix only

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
