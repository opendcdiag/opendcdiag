#!/bin/bash -e
# Copyright 2023 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
#
while [[ "$1" = *=* ]]; do
    # Evaluate variable assignments, like AR= and OBJCOPY=
    eval "$1"
    shift
done
if [[ "$1" = "--" ]]; then
    shift
fi

if [[ $# -lt 3 ]]; then
    cat <<EOF
Extracts malloc.o from static libc and localizes symbols defined in malloc.cpp.
Syntax:
    $0 [variable-assignments] /path/to/libc.a /path/to/malloc.cpp /path/to/output/malloc.o
Variable assignments can be:
  AR=/path/to/ar
EOF
    exit 0
fi

# Positional arguments
libc_a=$1
malloc_cpp=$2
output=$3
output_dirname=${output%/*}
output_basename=${output##*/}

# Define $AR and $OBJCOPY if they aren't defined.
: ${AR:=ar}
: ${OBJCOPY:=objcopy}

# Generate the -L arguments based on DECLARE_OVERRIDE inside malloc.cpp
objcopy_args=(`sed -En "/^DECLARE_OVERRIDE\((\w+)\).*/s//-L\1/p" "$malloc_cpp"`)

# Extract malloc.o from libc.a
"$AR" x --output "$output_dirname" "$libc_a" malloc.o

# Rename if necessary
[[ "$output_basename" = malloc.o ]] || mv -- "$output_dirname/malloc.o" "$output"

# Transform it
"$OBJCOPY" "${objcopy_args[@]}" "$output"
