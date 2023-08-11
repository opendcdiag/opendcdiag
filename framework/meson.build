# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

framework_config = configuration_data()
framework_config.set10('SANDSTONE_STATIC', false) # sysdeps may override

sysdeps_dir = 'sysdeps/' + target_machine.system()

if target_machine.system() == 'cygwin'
    sysdeps_dir = 'sysdeps/windows'
endif

framework_incdir = [
    top_incdir,
    include_directories([
        '.',
        'test_selectors',
        sysdeps_dir,
    ])
]


# Must be a configure_file, not custom_target, so it's created at
# meson time and thus before everything
generated_cpu_features_h = configure_file(
    output : 'cpu_features.h',
    encoding : 'ascii',
    input : files(
        'simd.conf',
    ),
    capture : true,
    command : [
        perl, files('scripts/x86simd_generate.pl'), '@INPUT@', '@OUTPUT@',
    ],
)

generated_builtin_test_list = []
builtin_test_list_inputs = get_option('builtin_test_list')
generated_builtin_test_list += custom_target(
    'sandstone_test_lists.h',
    input : [ ],
    output : [
        'sandstone_test_lists.h',
        'sandstone_test_lists.cpp',
    ],
    command : [
        python, files('scripts/generate_test_list.py'), '@OUTPUT@', meson.project_source_root(), builtin_test_list_inputs,
    ],
)

if cc.has_type('_Float16') and cpp.has_type('_Float16')
        framework_config.set('SANDSTONE_FP16_TYPE', '_Float16')
elif cc.has_type('__fp16') and cpp.has_type('__fp16')
        framework_config.set('SANDSTONE_FP16_TYPE', '__fp16')
endif

framework_config.set10('SANDSTONE_GA', get_option('flavor') == 'ga')
framework_config.set10('SANDSTONE_GA_DEV', get_option('flavor') == 'ga-dev')

framework_config.set10('SANDSTONE_BUILTIN_TEST_LIST', get_option('builtin_test_list') != '')
framework_config.set_quoted('SANDSTONE_EXECUTABLE_NAME', get_option('executable_name'))
framework_config.set_quoted('SANDSTONE_FALLBACK_EXEC', get_option('fallback_exec'))

framework_config.set10('SANDSTONE_NO_LOGGING', get_option('logging_format') == 'no_output')
framework_config.set('SANDSTONE_DEFAULT_LOGGING', 'SandstoneApplication::OutputFormat::' + get_option('logging_format'))

framework_config.set10('SANDSTONE_RESTRICTED_CMDLINE', get_option('framework_options').contains('restricted-cmdline'))
framework_config.set10('SANDSTONE_NO_TRIAGE', get_option('framework_options').contains('no-triage'))
if get_option('framework_options').contains('no-child-debug')
    framework_config.set10('SANDSTONE_CHILD_DEBUG_CRASHES', 0)
    framework_config.set10('SANDSTONE_CHILD_DEBUG_HANGS', 0)
    framework_config.set10('SANDSTONE_CHILD_BACKTRACE', 0)
else
    framework_config.set10('SANDSTONE_CHILD_DEBUG_CRASHES', not get_option('framework_options').contains('no-child-debug-crashes'))
    framework_config.set10('SANDSTONE_CHILD_DEBUG_HANGS', not get_option('framework_options').contains('no-child-debug-hangs'))
    framework_config.set10('SANDSTONE_CHILD_BACKTRACE', not get_option('framework_options').contains('no-child-backtrace'))
endif

framework_config.set10('SANDSTONE_SSL_BUILD', get_option('ssl_link_type') != 'none')
framework_config.set10('SANDSTONE_SSL_LINKED',
  get_option('ssl_link_type') == 'static' or get_option('ssl_link_type') == 'dynamic')

framework_files = files(
    'Floats.cpp',
    'generated_vectors.c',
    'logging.cpp',
    'mmap_region.c',
    'random.cpp',
    'sandstone.cpp',
    'sandstone_chrono.cpp',
    'sandstone_data.cpp',
    'sandstone_test_groups.cpp',
    'sandstone_thread.cpp',
    'sandstone_utils.cpp',
    'static_vectors.c',
    'test_knobs.cpp',
    'test_selectors/SelectorFactory.cpp',
    'test_selectors/WeightedSelectorBase.cpp',
    'sandstone_context_dump.cpp',
    'topology.cpp',
)

if framework_config.get('SANDSTONE_SSL_BUILD') == 1
  # Look for libcrypto
  crypto_dep = dependency('libcrypto',
                        version: '>= 3.0',
                        required: false,
                        static: get_option('ssl_link_type') == 'static')
  if crypto_dep.found()
      framework_files += ['sandstone_ssl.cpp']
  else
      # If we cannot find libcrypto, disable SSL build
      framework_config.set10('SANDSTONE_SSL_BUILD', 0)
  endif
endif

if get_option('selftests')
    framework_files += files('selftest.cpp')
else
    default_c_flags += [ '-DNO_SELF_TESTS', ]
    default_cpp_flags += [ '-DNO_SELF_TESTS', ]
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
endif
subdir(sysdeps_dir)

framework_config_h = configure_file(
    input : 'sandstone_config.h.in',
    output : 'sandstone_config.h',
    configuration : framework_config,
)

framework_main_a = static_library(
    'framework_main',
    files(
        'main.cpp',
    ),
    build_by_default: false,
    include_directories : [
        framework_incdir,
    ],
    cpp_args : [
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
    include_directories : [
        framework_incdir,
    ],
    objects: [
        framework_main_a.extract_all_objects(recursive: false),
    ],
    dependencies: [
        boost_dep,
    ],
    c_args : [
        debug_c_flags,
        march_flags,
        default_c_flags,
        default_c_warn,
    ],
    cpp_args : [
        debug_c_flags,
        march_flags,
        default_cpp_flags,
        default_cpp_warn,
    ],
)

unittests_sources += files(
    'sandstone_chrono.cpp',
    'sandstone_data.cpp',
    'sandstone_utils.cpp',
    'test_knobs.cpp',
    'test_selectors/SelectorFactory.cpp',
    'test_selectors/WeightedSelectorBase.cpp',
    'unit-tests/WeightedTestSelector_tests.cpp',
    'unit-tests/sandstone_data_tests.cpp',
    'unit-tests/sandstone_test_utils_tests.cpp',
    'unit-tests/sandstone_utils_tests.cpp',
    'unit-tests/tests_dummy.cpp',
    'unit-tests/test_knob_tests.cpp',
    'unit-tests/thermal_monitor_tests.cpp',
    'unit-tests/topology_tests.cpp',
)
