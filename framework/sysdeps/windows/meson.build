# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

sysdeps_a = static_library(
    'sysdeps_win32',
    files(
        'aligned_alloc.c',
        'child_debug.cpp',
        'cpu_affinity.cpp',
        'fcntl.c',
        'mman.c',
        'signals.cpp',
        'splitlock_detect.c',
        'tmpfile.c',
        'ucrt-mapping.c',
        'unistd.c',
        '../generic/kvm.c',
        '../generic/memfpt.c',
        '../generic/msr.c',
        '../generic/physicaladdress.c',
    ),
    build_by_default: false,
    include_directories : [
        framework_incdir,
    ],
    c_args : [
        default_c_flags,
        default_c_warn,
    ],
    cpp_args : [
        default_cpp_flags,
        default_cpp_warn,
    ],
)
