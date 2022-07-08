# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

dep_static = get_option('dependency_link') == 'static'

setmod = import('sourceset')

tests_config = configuration_data()
tests_set_base = setmod.source_set()
tests_set_hsw = setmod.source_set()
tests_set_skx = setmod.source_set()

tests_common_c_args = [
	debug_c_flags,
	default_c_warn,
	default_c_flags,
]

tests_common_cpp_args = [
	debug_c_flags,
	default_cpp_warn,
	default_cpp_flags,
]

tests_common_incdirs = [
	framework_incdir,
]

if target_machine.cpu_family() != 'x86_64'
	# non-x86 Eigen does not get as much attention so this annoying
	# warning was left behind
	tests_common_cpp_args += '-Wno-deprecated-copy'
endif

tests_set_base.add(
	files(
		'ifs/ifs.c',
	)
)

if framework_config.get('SANDSTONE_SSL_BUILD') == true
	tests_set_base.add(
		when : crypto_dep,
		if_true: files(
			# Tests that depends on openssl
		)
	)
endif

eigen3_dep = dependency('eigen3', static : dep_static)
tests_set_base.add(
	when : eigen3_dep,
	if_true : files(
		'eigen_gemm/double14.cpp',
		'eigen_gemm/gemm_cdouble_dynamic_square.cpp',
		'eigen_gemm/gemm_double_dynamic_square.cpp',
		'eigen_gemm/gemm_float_dynamic_square.cpp',
		'eigen_sparse/eigen_sparse.cpp',
		'eigen_svd/svd.cpp',
		'eigen_svd/svd_cdouble_noavx512.cpp',
		'eigen_svd/svd_double.cpp',
		'eigen_svd/svd_fvectors.cpp',
		'eigen_svd_jacobi/svd.cpp',
		'eigen_svd_jacobi/svd_cdouble.cpp',
		'eigen_svd_jacobi/svd_double.cpp',
		'eigen_svd_jacobi/svd_fvectors.cpp',
	)
)

tests_set_skx.add(
	when : eigen3_dep,
	if_true : files(
		'eigen_svd/svd_cdouble.cpp',
	)
)

zstd_dep = dependency('libzstd', static : dep_static)
tests_set_base.add(
	when : zstd_dep,
	if_true : files(
		'zstd/test.c',
	)
)

zlib_dep = dependency('zlib', static : dep_static)
tests_set_base.add(
	when : zlib_dep,
	if_true : files(
		'zlib/fuzz.c',
		'zlib/test.c',
	)
)

tests_config_base = tests_set_base.apply(tests_config)

tests_base_a = static_library(
	'tests_base',
	sources : tests_config_base.sources(),
	dependencies : tests_config_base.dependencies(),
	build_by_default: false,
	include_directories : [
		tests_common_incdirs,
	],
	c_args : [
		tests_common_c_args,
		march_flags,
	],
	cpp_args : [
		tests_common_cpp_args,
		march_flags,
	],
)

sandstone_tests += [
	tests_base_a,
]

if host_machine.cpu_family() == 'x86_64'
	tests_config_hsw = tests_set_hsw.apply(tests_config)

	tests_hsw_a = static_library(
		'tests_hsw',
		sources : tests_config_hsw.sources(),
		dependencies : tests_config_hsw.dependencies(),
		build_by_default: false,
		include_directories : [
			tests_common_incdirs,
		],
		c_args : [
			tests_common_c_args,
			'-march=haswell',
			'-mtune=skylake',
			'-mrtm',
		],
		cpp_args : [
			tests_common_cpp_args,
			'-march=haswell',
			'-mtune=skylake',
			'-mrtm',
			'-DEigen=EigenAVX2',
		],
	)

	tests_config_skx = tests_set_skx.apply(tests_config)

	tests_skx_a = static_library(
		'tests_skx',
		sources : tests_config_skx.sources(),
		dependencies : tests_config_skx.dependencies(),
		build_by_default: false,
		include_directories : [
			tests_common_incdirs,
		],
		c_args : [
			tests_common_c_args,
			'-march=skylake-avx512',
		],
		cpp_args : [
			tests_common_cpp_args,
			'-march=skylake-avx512',
			'-DEigen=EigenAVX512',
		],
	)

	sandstone_tests += [
		tests_hsw_a,
		tests_skx_a,
	]
endif
