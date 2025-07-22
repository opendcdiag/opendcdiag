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
)

if get_option('selftests')
    framework_files += files(
        'selftest.cpp'
    )
endif

unittests_sources += files(
    'unit-tests/thermal_monitor_tests.cpp',
)
