# Copyright 2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

ze_dep = cpp.find_library('ze_loader')

framework_files += files(
    'gpu_device.cpp',
    'topology.cpp',
    'logging_gpu.cpp',
)

target_deps += [
    ze_dep
]
