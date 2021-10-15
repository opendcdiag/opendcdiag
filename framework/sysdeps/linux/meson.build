# SPDX-License-Identifier: Apache-2.0

_sysdeps_a = static_library(
	'sysdeps_linux',
	files(
		'cpu_affinity.cpp',
		'interrupt_monitor.cpp',
		'kvm.c',
		'malloc.cpp',
		'memfpt.cpp',
		'msr.c',
		'physicaladdress.cpp',
	),
	include_directories : [
		framework_incdir,
	],
	c_args : [
		'-DLINUX',
		'-D__linux__',
		default_c_warn,
		debug_c_flags,
	],
	cpp_args : [
		default_cpp_warn,
		debug_c_flags,
	],
)

if get_option('cpp_link_args').contains('-static')
	ar = find_program('ar')
	nm = find_program('nm')
	objcopy = find_program('objcopy')

	# Need to extract malloc.o from libc.a and transform it
	# Step 1: extract it:
	libc_a = run_command(cc.cmd_array(), '-print-file-name=libc.a')

	orig_glibc_malloc_o = custom_target(
		'extract-malloc.o',
		output: 'malloc.o',
		input: libc_a.stdout().strip(),
		command: [
			ar, 'x', '--output', '@OUTDIR@', '@INPUT@', '@OUTPUT@',
		]
	)
	# Step 2: transform it by localizing (-L) all the symbols from our malloc.cpp
	glibc_malloc_o = custom_target(
		'glibc_malloc.o',
		input: [
			_sysdeps_a.extract_objects('malloc.cpp'),
			orig_glibc_malloc_o,
		],
		output: 'glibc_malloc.o',
		command: [
			shell, '-c', objcopy.full_path() + ' `' +
			nm.full_path() + ' --defined $0 | sed -En "/^.* T /s//-L /p"` $1 $2',
			'@INPUT@', '@OUTPUT@',
		]
	)
	# Step 3: add this file to the sysdeps library
	sysdeps_a = static_library(
		'sysdeps_linux_static',
		glibc_malloc_o,
		objects: _sysdeps_a.extract_all_objects(recursive: false),
	)
else
	sysdeps_a = _sysdeps_a
endif # if static
