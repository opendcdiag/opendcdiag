#!/usr/bin/bats
# -*- mode: sh -*-
# Copyright 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
load ../testenv
load helpers

function setup_file() {
    setup_sandstone

    # Probe whether --ulog is supported: if recognized, a bad arg produces
    # "FILE=OFFSET"; if not recognized, it produces an unknown-option error.
    run $SANDSTONE --ulog noequal --ulog noequal --ulog noequal
    if [[ "$output" != *"FILE=OFFSET"* ]]; then
        export ulog_skip_reason="--ulog not supported in this build"
        return
    fi

    # MAP_SHARED_VALIDATE|MAP_SYNC requires a DAX-capable filesystem; tmpfs also
    # works. Check by inspecting the filesystem type of the temp directory.
    local probe_file fstype
    probe_file=$(mktempfile ulog-probe-XXXXXX)
    fstype=$(stat -f -c %T "$probe_file" 2>/dev/null)
    rm -f "$probe_file"
    if [[ -n "$fstype" && "$fstype" != "tmpfs" ]]; then
        export ulog_skip_reason="--ulog mmap requires a DAX-capable or tmpfs filesystem (got: $fstype)"
    fi
}

function ulog_skip_if_unsupported() {
    if [[ -n "${ulog_skip_reason-}" ]]; then
        skip "$ulog_skip_reason"
    fi
}

# Create a zero-filled (sparse) temp file of the given size in bytes (default: 4096).
function ulog_make_file() {
    ulog_skip_if_unsupported
    local size=${1:-4096}
    local f
    f=$(mktempfile ulog-XXXXXX)
    truncate -s "$size" "$f"
    echo "$f"
}

# Verify the three ulog slots at the given file+offset pairs.
# Usage: ulog_check_slots test_name file0 offset0 file1 offset1 file2 offset2
# Requires yamldump to be pre-declared and populated by sandstone_selftest.
function ulog_check_slots() {
    local test_name=$1
    local v0 v1 v2
    v0=$(od -A n -t x4 -N 4 -j "$3" "$2"); v0="${v0// /}"
    v1=$(od -A n -t u4 -N 4 -j "$5" "$4")
    v2=$(od -A n -t u4 -N 4 -j "$7" "$6")

    # slot 0: first 6 hex digits must match the test's shortid from --list-test-ids;
    # last 2 hex digits must be "00" (not a retest)
    local shortid
    shortid=$($SANDSTONE --selftests --list-test-ids | awk -v t="$test_name" '$1==t{print $2}')
    [[ "${v0:0:6}" == "$shortid" ]]
    [[ "${v0:6:2}" == "00" ]]

    # slot 1: must equal the seed value from the YAML
    local seed_value
    extract_from_yaml "/tests/0/state/seed"
    seed_value="${value#*:}"
    (( v1 == seed_value ))

    # slot 2: reserved, must be zero
    (( v2 == 0 ))
}

@test "--ulog wrong argument count (1)" {
    ulog_skip_if_unsupported
    run $SANDSTONE --ulog file=0
    [[ $status -eq 64 ]]
    [[ "$output" == *"--ulog requires exactly 3"* ]]
}

@test "--ulog wrong argument count (2)" {
    ulog_skip_if_unsupported
    run $SANDSTONE --ulog file=0 --ulog file=1
    [[ $status -eq 64 ]]
    [[ "$output" == *"--ulog requires exactly 3"* ]]
}

@test "--ulog missing equal sign" {
    ulog_skip_if_unsupported
    run $SANDSTONE --ulog noequal --ulog noequal --ulog noequal
    [[ $status -eq 64 ]]
    [[ "$output" == *"FILE=OFFSET"* ]]
}

@test "--ulog invalid offset" {
    ulog_skip_if_unsupported
    run $SANDSTONE --ulog file=abc --ulog file=abc --ulog file=abc
    [[ $status -eq 64 ]]
    [[ "$output" == *"invalid offset"* ]]
}

@test "--ulog nonexistent file" {
    ulog_skip_if_unsupported
    local f=/nonexistent/path/to/file
    run $SANDSTONE --ulog $f=0 --ulog $f=0 --ulog $f=0
    [[ $status -ne 0 ]]
    [[ "$output" == *"cannot open"* ]]
}

@test "--ulog writes test info (three files)" {
    declare -A yamldump
    ulog_skip_if_unsupported

    local f
    f1=$(ulog_make_file)
    f2=$(ulog_make_file)
    f3=$(ulog_make_file)

    # We need the LCG random number generator because its state fits into
    # the 32 bits we have reserved to it.
    sandstone_selftest -s LCG -e selftest_pass \
        --ulog "$f1=0" --ulog "$f2=0" --ulog "$f3=0"

    ulog_check_slots selftest_pass "$f1" 0 "$f2" 0 "$f3" 0
}

function ulog_same_file_common() {
    declare -A yamldump
    ulog_skip_if_unsupported

    local o1=$1
    local o2=$2
    local o3=$3
    local f
    f=$(ulog_make_file $((o3 + 4096)))

    # We need the LCG random number generator because its state fits into
    # the 32 bits we have reserved to it.
    sandstone_selftest -s LCG -e selftest_pass \
        --ulog "$f=$o1" --ulog "$f=$o2" --ulog "$f=$o3"

    ulog_check_slots selftest_pass "$f" $o1 "$f" $o2 "$f" $o3
}

@test "--ulog same file same page" {
    ulog_same_file_common 0 4 8
}

@test "--ulog same file different pages" {
    ulog_same_file_common 0 4096 8192
}

@test "--ulog same file different pages, non-zero offsets" {
    ulog_same_file_common 256 4100 10240
}

@test "--ulog same file far pages" {
    # On Windows, our mmap() allocates to 64kB granularity
    ulog_same_file_common 0 65536 131072
}

@test "--ulog same file different large pages" {
    ulog_same_file_common 0 $((4*1024*1024)) $((8*1024*1024))
}

@test "--ulog verify short ID" {
    declare -A yamldump
    ulog_skip_if_unsupported
    ulimit -Sc 0 || :   # disable core dumps, we don't need them here

    local f
    f=$(ulog_make_file)

    # Build a map of test name → shortid
    local -A testids
    while read -r name hexid; do
        testids[$name]=$hexid
    done < <($SANDSTONE --selftests --list-test-ids | sed 's/\r$//')

    # Run a selection of simple, fast tests
    local tests=(
        selftest_pass selftest_timedpass selftest_logs selftest_skip
        selftest_failinit selftest_fail selftest_logerror
        selftest_abortinit selftest_abort selftest_sigsegv selftest_oserror
        selftest_freeze
    )
    local name
    for name in $tests; do
        sandstone_selftest -e "$name" --quick --retest-on-failure=0 --timeout=2s \
            --on-hang=kill --on-crash=kill --ulog "$f=0" --ulog "$f=4" --ulog "$f=8"
        local v0
        v0=$(od -A n -t x4 -N 4 -j 0 "$f"); v0="${v0// /}"
        [[ "${v0:0:6}" == "${testids[$name]}" ]]
        [[ "${v0:6:2}" == "00" ]]
    done
}

@test "--ulog retest count" {
    declare -A yamldump
    ulog_skip_if_unsupported

    local f
    f=$(ulog_make_file)

    sandstone_selftest -e selftest_failinit --retest-on-failure=1 \
        --ulog "$f=0" --ulog "$f=4" --ulog "$f=8"
    [[ $status -eq 1 ]]

    local v0 shortid
    v0=$(od -A n -t x4 -N 4 -j 0 "$f"); v0="${v0// /}"
    shortid=$($SANDSTONE --selftests --list-test-ids | awk -v t=selftest_failinit '$1==t{print $2}')

    # The last written value reflects the retest: shortid in upper bits, count=1 in low byte
    [[ "${v0:0:6}" == "$shortid" ]]
    [[ "${v0:6:2}" == "01" ]]
}
