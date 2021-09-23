# SPDX-License-Identifier: Apache-2.0

sysdeps_unix_a = static_library(
	'sysdeps_unix',
	files(
		'child_debug.cpp',
		'mmap_region.c',
		'splitlock_detect.c',
		'stacksize.cpp',
		'tmpfile.c',
	),
	build_by_default: false,
	include_directories : [
		framework_incdir,
	],
	c_args : [
		default_c_flags,
		default_c_warn,
		debug_c_flags,
	],
	cpp_args : [
		default_cpp_flags,
		default_cpp_warn,
		debug_c_flags,
	],
)
