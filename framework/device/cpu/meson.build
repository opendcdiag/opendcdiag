# Copyright 2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

# Must be a configure_file, not custom_target, so it's created at
# meson time and thus before everything
generated_files += configure_file(
    output: 'cpu_features.h',
    encoding: 'ascii',
    input: files(
        'simd.conf',
    ),
    capture: true,
    command: [
        perl,
        files('scripts/x86simd_generate.pl'),
        '@INPUT@',
        '@OUTPUT@',
    ],
)

framework_files += files(
    'cpu_device.cpp',
    'topology.cpp',
    'logging_cpu.cpp',
)

unittests_sources += files(
    'unit-tests/thermal_monitor_tests.cpp',
)

premain_files = files(
    'premain.cpp',
)

framework_main_a = static_library(
    'framework_main',
    premain_files,
    build_by_default: false,
    include_directories: [
        framework_incdir,
    ],
    cpp_args: [
        debug_c_flags,
        march_generic_flags,
        default_cpp_flags,
        default_cpp_warn,
    ],
)

extra_objects += framework_main_a.extract_all_objects(recursive: false)
