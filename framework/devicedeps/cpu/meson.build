# Copyright 2024 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

# Must be a configure_file, not custom_target, so it's created at
# meson time and thus before everything
generated_cpu_features_h = configure_file(
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

framework_files += [
    'devicedeps/cpu/cpu_device.cpp',
    'devicedeps/cpu/topology.cpp',
]
device_flags = [
    '-DSANDSTONE_DEVICE_CPU',
]

default_c_flags += [
    device_flags
]

default_cpp_flags += [
    device_flags
]
