#!/usr/bin/python3
# Copyright 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

import argparse
import tempfile
import subprocess
import sys
import os

# ocloc's -cpp_file option would emit the array for us, but only for the .bin file.
# We would still have to do it manually for spirv. For this reason I prefer to create
# both arrays by hand and at least maintain format coherency <ChangeMyMind>
def compile_spirv(source_file):
    with tempfile.NamedTemporaryFile(suffix='.bc') as fp:
        compile_args = ['clang++', '-c', '-target', 'spir64', '-O0', '-emit-llvm', '-DSPIRV_KERNELS_FORMAT', '-o', fp.name, source_file]
        compile_proc = subprocess.Popen(compile_args, stdout=subprocess.PIPE)
        stdout = compile_proc.communicate()[0]
        if compile_proc.returncode != 0:
            return compile_proc.returncode, stdout

        spirv_args = ['llvm-spirv', fp.name]
        spirv_proc = subprocess.Popen(spirv_args, stdout=subprocess.PIPE)
        stdout = spirv_proc.communicate()[0]
        if spirv_proc.returncode != 0:
            return spirv_proc.returncode, stdout

        binary_contents = open(fp.name[:-3] + '.spv', mode='rb').read()
        return 0, binary_contents


def compile_bin(source_file, device):
    # TODO what does -gen_file option actually do? What is .gen file? Could it be useful in our code?
    ocloc_args = ['ocloc', '-file', source_file, '-device', device, '-output_no_suffix']
    ocloc_proc = subprocess.Popen(ocloc_args, stdout=subprocess.PIPE)
    stdout = ocloc_proc.communicate()[0]
    if ocloc_proc.returncode != 0:
        return ocloc_proc.returncode, stdout

    binary_contents = open(os.path.splitext(os.path.basename(source_file))[0] + '.bin', mode='rb').read()
    return 0, binary_contents


def embed(array_name, compilation_output):
    print('// DO NOT EDIT, AUTO-GENERATED\n')
    print('#include <cstdint>\n')
    print(f'namespace {array_name} {{')
    print(f'static constexpr uint8_t kernel_source[] = {{\n', end='    ')

    bytes_output = list(compilation_output)
    for b in bytes_output[:-1]:
        print(f'{hex(b)}', end=', ')
    print(f'{hex(bytes_output[-1])}')

    print('};')
    print('static constexpr auto kernel_size = std::size(kernel_source);')
    print('}\n')

if __name__ == '__main__':
    p = argparse.ArgumentParser(
        description='Compile OpenCL kernel and translate to a C byte array')
    p.add_argument('array_name', help='Name of the C byte array')
    p.add_argument('source', help='Path to OpenCL source file')
    p.add_argument('device', help='Device type (bmg/spirv/...)')

    args = p.parse_args()

    if (args.device == "spirv"):
        ret, out = compile_spirv(args.source)
    else:
        ret, out = compile_bin(args.source, args.device)

    if (ret == 0):
        embed(args.array_name, out)
    else:
        sys.exit(out.decode())
