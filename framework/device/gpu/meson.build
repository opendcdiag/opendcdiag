# Copyright 2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

ze_dep = cpp.find_library('ze_loader')

framework_files += files(
    'build_topology.cpp',
    'gpu_device.cpp',
    'topology.cpp',
    'logging_gpu.cpp',
    'ze_enumeration.cpp',
    'ze_utils.cpp',
)

unittests_sources += files(
    'unit-tests/topology_tests.cpp',
    'build_topology.cpp',
)

target_deps += [
    ze_dep
]
