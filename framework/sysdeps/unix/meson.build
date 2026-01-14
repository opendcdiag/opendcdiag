# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

framework_files += files(
    'child_debug.cpp',
    'resource.cpp',
    'signals.cpp',
    'splitlock_detect.c',
    'stacksize.cpp',
    'tmpfile.c',
    'virt.cpp',
)

# same check as linux/meson.build
if get_option('cpp_link_args').contains('-static')
    framework_config.set10('SANDSTONE_STATIC', true)
endif
