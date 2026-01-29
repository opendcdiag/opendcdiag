# Copyright 2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

setmod = import('sourceset')

tests_config = configuration_data()
tests_set_base = setmod.source_set()

target_device = get_option('target_device')

level_zero_kernels_generator_script = find_program(
    'compile-embed-ze-kernel.py',
    dirs : [ meson.project_source_root() / 'framework' / 'device' / 'gpu' / 'scripts', ],
)

level_zero_kernels_generator = generator(
    level_zero_kernels_generator_script,
    arguments : [
        '@BASENAME@', '@INPUT@', target_device
    ],
    capture : true,
    output : '@BASENAME@_source.h',
)

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

if target_device == 'spirv'
    tests_common_cpp_args += [
        '-DSPIRV_KERNELS_FORMAT',
    ]
endif

tests_common_incdirs = [
    framework_incdir,
]

# fill with tests
tests_set_base.add(
    files(

    )
)

# fill with OpenCL kernels if used by tests
level_zero_kernel_sources = files(

)

tests_config_base = tests_set_base.apply(tests_config)
# level_zero_kernels_headers = level_zero_kernels_generator.process(level_zero_kernel_sources)

tests_base_a = static_library(
    'tests_base',
    sources : [
        tests_config_base.sources(),
        # level_zero_kernels_headers,
    ],
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
