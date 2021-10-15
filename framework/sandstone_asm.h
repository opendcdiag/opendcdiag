/*
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SANDSTONE_ASM_H
#define SANDSTONE_ASM_H

#include "sandstone.h"

#ifdef __cplusplus
#  define asmlinkage extern "C"
#else
#  define asmlinkage
#endif

#define BEGIN_ASM_FUNCTION(name, ...)                                                       \
    extern const unsigned char __attribute__((visibility("internal"))) name, name ## _end;  \
    extern const size_t __attribute__((visibility("internal"))) name ## _size;              \
    static void __attribute__((naked, noreturn, used, nothrow, flatten, ##__VA_ARGS__)) __ ## name(void) \
    {                                                                                       \
        asm (".set " SANDSTONE_STRINGIFY(name) "_end, 1999f\n\t"                            \
             ".set " SANDSTONE_STRINGIFY(name) "_size, 1997f\n"                             \
            SANDSTONE_STRINGIFY(name) ":\n"                                                 \
            "1998:");

#define BEGIN_ASM16_FUNCTION(name, ...)                             \
    BEGIN_ASM_FUNCTION(name, section(".text16"), ##__VA_ARGS__)     \
        asm (".code16");

#define END_ASM_FUNCTION()                  \
        asm( \
            ".align 16,0xcc\n\t"            \
            "1999:\n\t"                     \
            ".section .rodata\n\t"          \
            ".align 8\n"                    \
            "1997:\n\t"                     \
            ".quad 1999b - 1998b\n\t"       \
            ".previous\n\t"                  \
            ".code64\n\t"                   \
        );                                  \
        __builtin_unreachable();            \
    }


#endif // SANDSTONE_ASM_H
