# Copyright 2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

tests_set_idxd = files(
    'idxd_dummy_config.cpp',
)

tests_idxd_a = static_library(
    'tests_idxd',
    sources: tests_set_idxd,
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

sandstone_tests += [ tests_idxd_a ]
