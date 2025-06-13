#!/usr/bin/bats
# -*- mode: sh -*-
# Copyright 2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
load ../testenv
load helpers
MAX_PROC=`nproc`

@test "crash backtrace multi-slice" {
    # We need GDB and at least two cores
    check_gdb_usable
    export SANDSTONE_MOCK_TOPOLOGY='0 1'
    run $SANDSTONE --cpuset=t0 --dump-cpu-info
    if [[ "$output" != *$'\n1\t'* ]]; then
        skip "Test only works with multiple cores or a debug build"
    fi

    declare -A yamldump
    selftest_crash_context_common --cpuset=t0 -n2 --timeout=5m -e selftest_sigsegv --on-crash=backtrace --max-cores-per-slice=1

    # We should have as output two main threads and two worker threads
    test_yaml_regexp "/tests/0/threads/0/thread" "main"
    test_yaml_regexp "/tests/0/threads/0/messages/0/level" "info"
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" "Backtrace:.*"

    test_yaml_regexp "/tests/0/threads/1/thread" "main 1"
    test_yaml_regexp "/tests/0/threads/1/messages/0/level" "info"
    test_yaml_regexp "/tests/0/threads/1/messages/0/text" "Backtrace:.*"

    test_yaml_regexp "/tests/0/threads/2/thread" "0"
    test_yaml_regexp "/tests/0/threads/3/thread" "1"
}

@test "no slicing if too few cores per socket" {
    declare -A yamldump

    export SANDSTONE_MOCK_TOPOLOGY=`seq 0 $MAX_PROC | xargs`
    echo "SANDSTONE_MOCK_TOPOLOGY=\"$SANDSTONE_MOCK_TOPOLOGY\""
    sandstone_yq --disable=\*

    local cpus=${yamldump[/cpu-info@len]}
    [[ ${cpus-0} = $MAX_PROC ]]

    local sockets=`query_jq -r '[ ."cpu-info"[].package ] | unique | length'`
    if $is_debug; then
        [[ ${sockets-0} = $MAX_PROC ]]
    fi

    if ((cpus / sockets < 8)); then
        # slicing without topology
        n=$(((cpus + 31) / 32))
        test_yaml_numeric "/test-plans/fullsocket@len" "value == $n"
        test_yaml_numeric "/test-plans/heuristic@len" "value == $n"
    else
        skip "Test only works with Debug builds (to mock the topology) or systems with very few cores per package"
    fi
}

@test "slicing packages" {
    declare -A yamldump

    # attempt to run on two sockets
    export SANDSTONE_MOCK_TOPOLOGY='0 1 0:1 1:1 2 2:1 3 3:1'
    run $SANDSTONE --cpuset=p1 --dump-cpu-info
    if [[ $status -ne 0 ]]; then
        skip "Test only works with Debug builds (to mock the topology) or multi-socket systems"
    fi

    sandstone_yq --disable=\* --max-cores-per-slice=2

    local sockets=`query_jq -r '[ ."cpu-info"[].package ] | unique | length'`
    local socket0count=`query_jq -r '[."cpu-info"[] | select(.package == 0)] | length'`

    test_yaml_numeric "/test-plans/fullsocket@len" "value = $sockets"
    test_yaml_numeric "/test-plans/fullsocket/0/starting_cpu" 'value == 0'
    test_yaml_numeric "/test-plans/fullsocket/0/count" "value = $socket0count"
    test_yaml_numeric "/test-plans/fullsocket/1/starting_cpu" "value == $socket0count"
}

@test "slicing cores" {
    declare -A yamldump

    # attempt to run on two sockets
    export SANDSTONE_MOCK_TOPOLOGY='0 0:1 0:2 1'
    run $SANDSTONE --cpuset=p1 --dump-cpu-info
    if [[ $status -ne 0 ]]; then
        skip "Test only works with Debug builds (to mock the topology) w/ 4 CPUs or multi-socket systems"
    fi

    sandstone_yq --disable=\* --max-cores-per-slice=2 --cpuset=p0c0,p0c1,p0c2,p1c0
    test_yaml_numeric "/test-plans/fullsocket@len" 'value == 2'
    test_yaml_numeric "/test-plans/heuristic@len" 'value == 3'
}
