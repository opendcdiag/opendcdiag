# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

framework_files += \
    files(
        'aligned_alloc.cpp',
        'child_debug.cpp',
        'cpu_affinity.cpp',
        'fcntl.c',
        'fnmatch.c',
        'gettid.cpp',
        'mman.c',
        'resource.cpp',
        'signals.cpp',
        'splitlock_detect.c',
        'tmpfile.c',
        'ucrt-mapping.c',
        'unistd.c',
        'win32_perror.c',
        '../generic/kvm.c',
        '../generic/memfpt.c',
        '../generic/msr.c',
        '../generic/physicaladdress.c',
    )

if run_command([shell, '-c', 'echo $ENABLE_WINE_WORKAROUNDS'], capture: true).stdout().strip() == '1'
    default_cpp_flags += [ '-DENABLE_WINE_WORKAROUNDS', ]
endif
