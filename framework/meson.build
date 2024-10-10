# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

framework_config = configuration_data()
framework_config.set10('SANDSTONE_STATIC', false) # sysdeps may override

device_type = get_option('device_type')
if device_type == ''
    device_type = 'cpu'
endif

sysdeps_dir = 'sysdeps' / target_machine.system()
devicedeps_dir = 'devicedeps' / device_type
devicedeps_sys_dir = devicedeps_dir / target_machine.system()

if target_machine.system() == 'cygwin'
    sysdeps_dir = 'sysdeps/windows'
    devicedeps_dir = 'devicedeps' / device_type / 'windows'
endif

framework_incdir = [
    top_incdir,
    include_directories(
        [
            '.',
            sysdeps_dir,
            devicedeps_dir,
            devicedeps_sys_dir,
        ],
    ),
]

framework_files = files()

# Run device-specific build steps early to ensure that any auto-generated
# file is available before anything else.
subdir(devicedeps_dir)

generated_builtin_test_list = []
builtin_test_list_inputs = get_option('builtin_test_list')
generated_builtin_test_list += custom_target(
    'sandstone_test_lists.h',
    input: [],
    output: [
        'sandstone_test_lists.h',
        'sandstone_test_lists.cpp',
    ],
    command: [
        python,
        files('scripts/generate_test_list.py'),
        '@OUTPUT@',
        meson.project_source_root(),
        builtin_test_list_inputs,
    ],
)

if cc.has_type('_Float16') and cpp.has_type('_Float16')
    framework_config.set('SANDSTONE_FP16_TYPE', '_Float16')
elif cc.has_type('__fp16') and cpp.has_type('__fp16')
    framework_config.set('SANDSTONE_FP16_TYPE', '__fp16')
endif

framework_config.set10('SANDSTONE_BUILTIN_TEST_LIST', get_option('builtin_test_list') != '')
framework_config.set_quoted('SANDSTONE_EXECUTABLE_NAME', get_option('executable_name'))
framework_config.set_quoted('SANDSTONE_FALLBACK_EXEC', get_option('fallback_exec'))

framework_config.set10('SANDSTONE_NO_LOGGING', get_option('logging_format') == 'no_output')
framework_config.set(
    'SANDSTONE_DEFAULT_LOGGING',
    'SandstoneApplication::OutputFormat::' + get_option('logging_format'),
)

framework_config.set10(
    'SANDSTONE_RESTRICTED_CMDLINE',
    get_option('framework_options').contains('restricted-cmdline'),
)
if get_option('framework_options').contains('no-child-debug')
    framework_config.set10('SANDSTONE_CHILD_DEBUG_CRASHES', 0)
    framework_config.set10('SANDSTONE_CHILD_DEBUG_HANGS', 0)
    framework_config.set10('SANDSTONE_CHILD_BACKTRACE', 0)
else
    framework_config.set10(
        'SANDSTONE_CHILD_DEBUG_CRASHES',
        not get_option('framework_options').contains('no-child-debug-crashes'),
    )
    framework_config.set10(
        'SANDSTONE_CHILD_DEBUG_HANGS',
        not get_option('framework_options').contains('no-child-debug-hangs'),
    )
    framework_config.set10(
        'SANDSTONE_CHILD_BACKTRACE',
        not get_option('framework_options').contains('no-child-backtrace'),
    )
endif

framework_config.set10('SANDSTONE_SSL_BUILD', get_option('ssl_link_type') != 'none')
framework_config.set10(
    'SANDSTONE_SSL_LINKED',
    get_option('ssl_link_type') == 'static'
    or get_option('ssl_link_type') == 'dynamic',
)

framework_files += [
    'Floats.cpp',
    'generated_vectors.c',
    'logging.cpp',
    'mmap_region.c',
    'random.cpp',
    'sandstone.cpp',
    'sandstone_chrono.cpp',
    'sandstone_context_dump.cpp',
    'sandstone_data.cpp',
    'sandstone_test_groups.cpp',
    'sandstone_tests.cpp',
    'sandstone_thread.cpp',
    'sandstone_utils.cpp',
    'static_vectors.c',
    'test_knobs.cpp',
]

if framework_config.get('SANDSTONE_SSL_BUILD') == 1
    # Look for libcrypto
    crypto_dep = dependency(
        'libcrypto',
        version: '>= 3.0',
        required: false,
        static: get_option('ssl_link_type') == 'static',
    )
    if crypto_dep.found()
        framework_files += ['sandstone_ssl.cpp', 'sandstone_ssl_rand.cpp']

        if framework_config.get('SANDSTONE_SSL_LINKED') == 0
            # If we're trying to dlopen() only, we need to be more careful
            crypto_dep = crypto_dep.partial_dependency(
                compile_args: true,
                includes: true,
                link_args: false,
                links: false,
            )
        endif
    else
        # If we cannot find libcrypto, disable SSL build
        framework_config.set10('SANDSTONE_SSL_BUILD', 0)
    endif
endif

if get_option('selftests')
    framework_files += files('selftest.cpp')
else
    default_c_flags += [
        '-DNO_SELF_TESTS',
    ]
    default_cpp_flags += [
        '-DNO_SELF_TESTS',
    ]
endif

if target_machine.system() != 'windows' and target_machine.system() != 'cygwin'
    framework_files += [
        'forkfd/forkfd.c',
    ]
endif
if target_machine.system() == 'darwin'
    framework_files += [
        'sandstone_sections.S',
    ]
endif

if target_machine.system() != 'windows' and target_machine.system() != 'cygwin'
    subdir('sysdeps/unix')
    subdir('devicedeps' / device_type / 'unix')
endif
subdir(sysdeps_dir)
subdir(devicedeps_sys_dir)

framework_config_h = configure_file(
    input: 'sandstone_config.h.in',
    output: 'sandstone_config.h',
    configuration: framework_config,
)

framework_main_a = static_library(
    'framework_main',
    files(
        'main.cpp',
    ),
    build_by_default: false,
    include_directories: [
        framework_incdir,
    ],
    cpp_args: [
        debug_c_flags,
        march_generic_flags,
        default_cpp_flags,
        default_cpp_warn,
    ],
)

framework_a = static_library(
    'framework',
    framework_files,
    generated_builtin_test_list,
    generated_cpu_features_h,
    build_by_default: false,
    include_directories: [
        framework_incdir,
    ],
    objects: [
        framework_main_a.extract_all_objects(recursive: false),
    ],
    dependencies: [
        boost_dep,
    ],
    c_args: [
        debug_c_flags,
        march_flags,
        default_c_flags,
        default_c_warn,
    ],
    cpp_args: [
        debug_c_flags,
        march_flags,
        default_cpp_flags,
        default_cpp_warn,
    ],
)

unittests_sources += files(
    'unit-tests/sandstone_data_tests.cpp',
    'unit-tests/sandstone_test_utils_tests.cpp',
    'unit-tests/sandstone_utils_tests.cpp',
    'unit-tests/test_knob_tests.cpp',
    'unit-tests/tests_dummy.cpp',
    'unit-tests/thermal_monitor_tests.cpp',
    'unit-tests/topology_tests.cpp',
    'sandstone_chrono.cpp',
    'sandstone_data.cpp',
    'sandstone_utils.cpp',
    'test_knobs.cpp',
)
