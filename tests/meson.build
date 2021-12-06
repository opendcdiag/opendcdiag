# SPDX-License-Identifier: Apache-2.0

dep_static = get_option('dependency_link') == 'static'

setmod = import('sourceset')

tests_config_data = configuration_data()
tests_base_set = setmod.source_set()
tests_hsw_set = setmod.source_set()
tests_skx_set = setmod.source_set()

tests_common_c_args = [
	default_c_warn,
	default_c_flags,
	debug_c_flags,
]

tests_common_cpp_args = [
	default_cpp_warn,
	default_cpp_flags,
	debug_c_flags,
]

tests_common_incdirs = [
	framework_incdir,
]

eigen3_dep = dependency('eigen3', static : dep_static)
tests_base_set.add(
	when : eigen3_dep,
	if_true : files(
		'eigen_gemm/double14.cpp',
		'eigen_gemm/gemm_cdouble_dynamic_square.cpp',
		'eigen_gemm/gemm_double_dynamic_square.cpp',
		'eigen_gemm/gemm_float_dynamic_square.cpp',
		'eigen_svd/svd_cdouble_noavx512.cpp',
	)
)

tests_hsw_set.add(
	when : eigen3_dep,
	if_true : files(
		'eigen_sparse/eigen_sparse.cpp',
		'eigen_svd/svd.cpp',
		'eigen_svd/svd_double.cpp',
		'eigen_svd/svd_fvectors.cpp',
		'eigen_svd_jacobi/svd.cpp',
		'eigen_svd_jacobi/svd_cdouble.cpp',
		'eigen_svd_jacobi/svd_double.cpp',
		'eigen_svd_jacobi/svd_fvectors.cpp',
	)
)

tests_skx_set.add(
	when : eigen3_dep,
	if_true : files(
		'eigen_svd/svd_cdouble.cpp',
	)
)

zstd_dep = dependency('libzstd', static : dep_static)
tests_base_set.add(
	when : zstd_dep,
	if_true : files(
		'zstd/test.c',
	)
)

zlib_dep = dependency('zlib', static : dep_static)
tests_base_set.add(
	when : zlib_dep,
	if_true : files(
		'zlib/fuzz.c',
		'zlib/test.c',
	)
)

tests_base_config = tests_base_set.apply(tests_config_data)

tests_base_a = static_library(
	'tests_base',
	sources : tests_base_config.sources(),
	dependencies : tests_base_config.dependencies(),
	build_by_default: false,
	include_directories : [
		tests_common_incdirs,
	],
	c_args : [
		march_base,
		tests_common_c_args,
	],
	cpp_args : [
		march_base,
		tests_common_cpp_args,
	],
)

tests_hsw_config = tests_hsw_set.apply(tests_config_data)

tests_hsw_a = static_library(
	'tests_hsw',
	sources : tests_hsw_config.sources(),
	dependencies : tests_hsw_config.dependencies(),
	build_by_default: false,
	include_directories : [
		tests_common_incdirs,
	],
	c_args : [
		'-march=haswell',
		'-mrtm',
		tests_common_c_args,
	],
	cpp_args : [
		'-march=haswell',
		'-mrtm',
		'-DEigen=EigenAVX2',
		tests_common_cpp_args,
	],
)

tests_skx_config = tests_skx_set.apply(tests_config_data)

tests_skx_a = static_library(
	'tests_skx',
	sources : tests_skx_config.sources(),
	dependencies : tests_skx_config.dependencies(),
	build_by_default: false,
	include_directories : [
		tests_common_incdirs,
	],
	c_args : [
		'-march=skylake-avx512',
		tests_common_c_args,
	],
	cpp_args : [
		'-march=skylake-avx512',
		'-DEigen=EigenAVX512',
		tests_common_cpp_args,
	],
)

sandstone_tests += [
	tests_base_a,
	tests_hsw_a,
	tests_skx_a,
]
