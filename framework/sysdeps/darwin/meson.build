sysdeps_a = static_library(
    'sysdeps_darwin',
    sysdeps_unix_files,
    files(
        'cpu_affinity.cpp',
        'malloc.cpp',
        'pthread_barrier.cpp',
        '../generic/kvm.c',
        '../generic/memfpt.c',
        '../generic/msr.c',
        '../generic/physicaladdress.c',
    ),
    build_by_default: false,
    include_directories : [
        framework_incdir,
    ],
    c_args : [
        default_c_warn,
        debug_c_flags,
    ],
    cpp_args : [
        default_cpp_warn,
        debug_c_flags,
    ],
)
