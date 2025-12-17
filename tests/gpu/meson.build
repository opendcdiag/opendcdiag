# Copyright 2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

setmod = import('sourceset')

tests_config = configuration_data()
tests_set_base = setmod.source_set()

tests_common_c_args = [
    debug_c_flags,
    default_c_warn,
    default_c_flags,
]

tests_common_cpp_args = [
    debug_c_flags,
    default_cpp_warn,
    default_cpp_flags,
]

tests_common_incdirs = [
    framework_incdir,
]

# fill with tests
# tests_set_base.add(
#     files(
#
#     )
# )

tests_config_base = tests_set_base.apply(tests_config)

tests_base_a = static_library(
    'tests_base',
    sources : tests_config_base.sources(),
    build_by_default: false,
    include_directories : [
        tests_common_incdirs,
    ],
    dependencies: [
        tests_config_base.dependencies(),
    ],
    c_args : [
        tests_common_c_args,
    ],
    cpp_args : [
        tests_common_cpp_args,
    ],
)

sandstone_tests += [
    tests_base_a,
]
