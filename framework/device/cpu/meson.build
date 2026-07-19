# Copyright 2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

# Changes from Qualcomm Technologies, Inc. are provided under the following license:
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause-Clear


if host_machine.cpu_family() != 'aarch64'
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
else
    # Same as above: a configure_file, so cpu_features.h exists at meson time
    # and thus before everything. aarch64 has no CPUID-leaf table to generate
    # from, so the header is copied from cpu_features_aarch64.h instead.
    generated_files += configure_file(
        input: 'cpu_features_aarch64.h',
        output: 'cpu_features.h',
        copy: true,
    )
endif

framework_files += files(
    'cpu_device.cpp',
    'topology.cpp',
    'logging_cpu.cpp',
    'slicing.cpp',
)

unittests_sources += files(
    'unit-tests/thermal_monitor_tests.cpp',
    'unit-tests/topology_tests.cpp',
    'slicing.cpp',
)

premain_files += files(
    'premain.cpp',
)
