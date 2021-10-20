/*
 * SPDX-License-Identifier: Apache-2.0
 */

        .file "sandstone-sections.S"

#ifdef __MACH__
.macro add_section_symbols name
        .section        __DATA, \name\().a
        .global         ___start_\name
        .align 8
___start_\name\():
        .section        __DATA, \name
dummy_\name\():
        .section        __DATA, \name\().z
        .global         ___stop_\name
___stop_\name\():
.endm

        add_section_symbols tests
        add_section_symbols test_group
#endif // __MACH__

#ifdef __ELF__
        .section        .note.GNU-stack,"",@progbits
#endif // __ELF__
