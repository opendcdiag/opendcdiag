# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

if (host_machine.cpu_family() == 'x86_64')
    sysdeps_arch_files = files(
        'interrupt_monitor.cpp',
        'kvm.c',
        'msr.c',
    )
else
    sysdeps_arch_files = files(
        '../generic/kvm.c',
        '../generic/msr.c',
    )
endif

_sysdeps_a = static_library(
    'sysdeps_linux',
    sysdeps_unix_files,
    sysdeps_arch_files,
    files(
        'cpu_affinity.cpp',
        'malloc.cpp',
        'memfpt.cpp',
        'physicaladdress.cpp',
    ),
    build_by_default: false,
    include_directories : [
        framework_incdir,
    ],
    c_args : [
        '-DLINUX',
        '-D__linux__',
        default_c_warn,
        debug_c_flags,
    ],
    cpp_args : [
        default_cpp_warn,
        debug_c_flags,
    ],
)

if get_option('cpp_link_args').contains('-static')
    ar = find_program('ar')
    objcopy = find_program('objcopy')

    # Need to extract malloc.o from libc.a and transform it
    # Step 1: find libc.a by asking the compiler
    libc_a = run_command(cc.cmd_array(), '-print-file-name=libc.a',
           check: true
    )

    # Step 2: run our extractor script
    glibc_malloc_o = custom_target(
        'glibc_malloc.o',
        input: [
            libc_a.stdout().strip(),
            files('malloc.cpp'),
        ],
        output: 'glibc_malloc.o',
        command: [
            shell,
            files('extract-malloc.sh'),
            'AR=' + ar.full_path(),
            'OBJCOPY=' + objcopy.full_path(),
            '--',
            '@INPUT@',
            '@OUTPUT@',
        ]
    )
    # Step 3: add this file to the sysdeps library
    sysdeps_a = static_library(
        'sysdeps_linux_static',
        glibc_malloc_o,
        build_by_default: false,
        objects: _sysdeps_a.extract_all_objects(recursive: false),
    )
else
    sysdeps_a = _sysdeps_a
endif # if static
