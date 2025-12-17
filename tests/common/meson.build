# Copyright 2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

# here we put tests common for all device types
tests_set_common = []

tests_set_common += files(
    'mce_check/mce_check.cpp',
)

if target_machine.system() == 'linux' and host_machine.cpu_family() == 'x86_64'
    tests_set_common += files(
        'smi_count/smi_count.cpp',
    )
endif

tests_common_a = static_library(
    'tests_common',
    sources: tests_set_common,
    build_by_default: true,
    include_directories: [
        framework_incdir,
    ],
    c_args: [
        default_c_flags,
    ],
    cpp_args: [
        default_cpp_flags,
    ],
)

sandstone_tests += [ tests_common_a ]
