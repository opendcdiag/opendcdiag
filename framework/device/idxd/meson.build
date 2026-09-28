# Copyright 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

dep_static = get_option('dependency_link') == 'static'

accel_config_dep = dependency('libaccel-config', required: true, static: dep_static)

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
