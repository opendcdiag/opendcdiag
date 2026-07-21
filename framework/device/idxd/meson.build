# Copyright 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

accel_config_dep = dependency('libaccel-config', required: true)

target_deps += [
    accel_config_dep,
]

framework_files += files(
    'build_topology.cpp',
    'idxd_config.cpp',
    'idxd_device.cpp',
    'topology.cpp',
    'logging_idxd.cpp',
)

unittests_sources += files(
    'unit-tests/idxd_features_tests.cpp',
)
