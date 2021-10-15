/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sandstone.h"
#include "sandstone_p.h"

void debug_init_child()
{
}

void debug_init_global(const char *on_hang_arg, const char *on_crash_arg)
{
    (void) on_hang_arg;
    (void) on_crash_arg;
}

void debug_crashed_child(pid_t child)
{
    (void) child;
}

void debug_hung_child(pid_t child)
{
    (void) child;
}
