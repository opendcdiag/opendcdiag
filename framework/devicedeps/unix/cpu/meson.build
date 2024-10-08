# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

framework_files += files(
    'effective_cpu_freq.hpp',
)

# same check as linux/meson.build
if get_option('cpp_link_args').contains('-static')
    framework_config.set10('SANDSTONE_STATIC', true)
endif
