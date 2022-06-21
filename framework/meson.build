# -*- indent-tabs-mode: t -*-
# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

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

if target_machine.system() != 'windows' and target_machine.system() != 'cygwin'
	subdir('sysdeps/unix')
endif
subdir(sysdeps_dir)

generated_cpu_features_h = configure_file(
	output : 'cpu_features.h',
	encoding : 'ascii',
	input : [
		 'scripts/x86simd_generate.pl',
		 'simd.conf',
	],
	capture : true,
	command : [
		perl, '@INPUT0@', '@INPUT1@', '@OUTPUT@',
	],
)

generated_weighted_runs = configure_file(
	input : [
		'scripts/weighted_runs_list2header.py',
		'weighted_runs.list',
	],
	output : 'weighted_runs.h',
	encoding : 'ascii',
	capture : true,
	command : [
		python, '@INPUT0@', '@INPUT1@',
	]
)

if cc.has_type('_Float16') and cpp.has_type('_Float16')
	default_c_flags   += ['-DSANDSTONE_HAS_FLOAT16_TYPE']
	default_cpp_flags += ['-DSANDSTONE_HAS_FLOAT16_TYPE']
endif

if cc.has_type('__fp16') and cpp.has_type('__fp16')
	default_c_flags   += ['-DSANDSTONE_HAS__FP16_TYPE']
	default_cpp_flags += ['-DSANDSTONE_HAS__FP16_TYPE']
endif

framework_config.set10('SANDSTONE_GA', get_option('flavor') == 'ga')
framework_config.set10('SANDSTONE_GA_DEV', get_option('flavor') == 'ga-dev')

framework_config.set10('SANDSTONE_NO_LOGGING', get_option('flavor') == 'ga')
framework_config.set10('SANDSTONE_I18N_LOGGING', get_option('flavor') == 'ga')
framework_config.set10('SANDSTONE_RESTRICTED_CMDLINE', get_option('cmdline') == 'restricted')

framework_config.set10('SANDSTONE_DEBUG', get_option('b_ndebug') == 'false')

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
		'-DFALLBACK_EXEC="' + get_option('fallback_exec') + '"',
		debug_c_flags,
		march_generic_flags,
		default_cpp_flags,
		default_cpp_warn,
	],
)

framework_files = files(
	'Floats.c',
	'generated_vectors.c',
	'logging.cpp',
	'mmap_region.c',
	'random.cpp',
	'sandstone.cpp',
	'sandstone_data.cpp',
	'sandstone_test_groups.cpp',
	'sandstone_utils.cpp',
	'static_vectors.c',
	'test_knobs.cpp',
	'test_selectors/SelectorFactory.cpp',
	'test_selectors/WeightedSelectorBase.cpp',
	'sandstone_context_dump.cpp',
	'topology.cpp',
)

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

# Default logging options
logging_c_flags = []

if get_option('logging_format') == 'tap'
	logging_c_flags += '-DSANDSTONE_TAP_LOGGING'
elif get_option('logging_format') == 'yaml'
	logging_c_flags += '-DSANDSTONE_YAML_LOGGING'
elif get_option('logging_format') == 'none'
	logging_c_flags += '-DSANDSTONE_NO_LOGGING'
else
	warning('Requested logging_format unknown, using hard-coded default format')
endif

framework_a = static_library(
	'framework',
	framework_files,
	build_by_default: false,
	include_directories : [
		framework_incdir,
	],
	objects: [
		sysdeps_a.extract_all_objects(recursive: true),
		framework_main_a.extract_all_objects(recursive: false),
	],
	c_args : [
		debug_c_flags,
		march_flags,
		default_c_flags,
		default_c_warn,
		logging_c_flags,
	],
	cpp_args : [
		debug_c_flags,
		march_flags,
		default_cpp_flags,
		default_cpp_warn,
		logging_c_flags,
	],
)

unittests_sources += files(
	'sandstone_data.cpp',
	'sandstone_utils.cpp',
	'test_knobs.cpp',
	'test_selectors/SelectorFactory.cpp',
	'test_selectors/WeightedSelectorBase.cpp',
	'unit-tests/WeightedTestSelector_tests.cpp',
	'unit-tests/sandstone_data_tests.cpp',
	'unit-tests/sandstone_test_utils_tests.cpp',
	'unit-tests/sandstone_utils_tests.cpp',
	'unit-tests/test_knob_tests.cpp',
	'unit-tests/thermal_monitor_tests.cpp',
)
