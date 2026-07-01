# Copyright 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

accel_config_dep = dependency('libaccel-config', required: true)

target_deps += [
    accel_config_dep,
]

framework_files += files(
    'idxd_device.cpp',
    'topology.cpp',
    'logging_idxd.cpp',
)
