# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

if (host_machine.cpu_family() == 'x86_64')
    framework_files += files(
        'interrupt_monitor.cpp',
        'msr.c',
    )
else
    framework_files += files(
        '../generic' / 'msr.c',
    )
endif

framework_files += \
    files(
        'cpu_affinity.cpp',
        'physicaladdress.cpp',
    )
