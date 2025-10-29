#!/usr/bin/bats
# -*- mode: sh -*-
# Copyright 2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
load ../testenv
load helpers
MAX_PROC=`nproc`

function cpuset_unique_modules() {
    # Make a list of cores that are in unique modules
    VALIDATION=0 sandstone_yq --cpuset=t0 '--disable=*' > /dev/null

    query_jq -r '."cpu-info" | unique_by(.module)[0:'$1'][]
        | "p" + (.package|tostring) + "c" + (.core|tostring) + "t0"'
}

@test "crash backtrace multi-slice" {
    # We need GDB and at least two cores
    check_gdb_usable
    export SANDSTONE_MOCK_TOPOLOGY='c0 c1'

    set `cpuset_unique_modules`
    if [[ $# -lt 2 ]]; then
        skip "Test only works with multiple cores/modules or a debug build"
    fi

    declare -A yamldump
    IFS=,
    selftest_crash_context_common "--cpuset=$*" -n2 --timeout=5m -e selftest_sigsegv --on-crash=backtrace --max-cores-per-slice=1

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

@test "ps on selftest_freeze multi-slice" {
    local psver=`LC_ALL=C.UTF-8 ps --version`
    if [[ "$psver" != *procps* ]]; then
        skip "Test requires procps (Linux)"
    fi

    export SANDSTONE_MOCK_TOPOLOGY='c0 c1'
    set `cpuset_unique_modules`
    if [[ $# -lt 2 ]]; then
        skip "Test only works with multiple cores/modules or a debug build"
    fi

    local newline=$'\n'
    declare -A yamldump

    IFS=,
    sandstone_selftest -vvv "--cpuset=$*" -n2 --on-crash=kill --on-hang=ps -e selftest_freeze --timeout=500 --max-cores-per-slice=1
    [[ "$status" -eq 2 ]]
    test_yaml_regexp "/exit" invalid
    test_yaml_regexp "/tests/0/result" 'timed out'
    test_yaml_regexp "/tests/0/threads/0/messages/0/level" 'info'
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" ".*\bPID\b.*\bCOMMAND\b.*${newline}.*\bcontrol\b.*"
    test_yaml_regexp "/tests/0/threads/1/messages/0/level" 'info'
    test_yaml_regexp "/tests/0/threads/1/messages/0/text" ".*\bPID\b.*\bCOMMAND\b.*${newline}.*\bcontrol\b.*"
}

@test "no slicing if too few cores per socket" {
    declare -A yamldump

    export SANDSTONE_MOCK_TOPOLOGY=`seq -s " " -f "p%g" 0 $((MAX_PROC - 1))`
    echo "SANDSTONE_MOCK_TOPOLOGY=\"$SANDSTONE_MOCK_TOPOLOGY\""
    sandstone_yq --disable=\*

    local cpus=${yamldump[/cpu-info@len]}
    [[ ${cpus-0} = $MAX_PROC ]]

    local sockets=`query_jq -r '[ ."cpu-info"[].package ] | unique | length'`
    if $is_debug; then
        # check that the tool reported as many sockets as we expect it to
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
    export SANDSTONE_MOCK_TOPOLOGY='p0c0 p0c1 p1c0 p1c1 p2c0 p2c1 p3c0 p3c1'
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

@test "slicing NUMA domains" {
    declare -A yamldump

    # attempt to run on one socket with multiple NUMA domains
    MAX_PROC=`nproc`
    if (( `nproc` >= 8 )); then
        export SANDSTONE_MOCK_TOPOLOGY='n0c0 n0c1 n0c2 n0c3 n1c64 n1c65 n1c66 n1c67'
    elif (( MAX_PROC >= 4 )); then
        export SANDSTONE_MOCK_TOPOLOGY='n0c0 n0c1 n1c64 n1c65'
    else
        skip "Test needs at least 4 different CPUs to test"
    fi
    sandstone_yq --cpuset=p0 --disable=\* --max-cores-per-slice=$MAX_PROC

    # did we see different NUMA domains?
    local domains=(`query_jq -r '[ ."cpu-info"[].numa_node ] | unique | .[]'`)
    test_yaml_numeric "/test-plans/isolate_numa@len" "value == ${#domains[@]}"

    if [[ "${#domains[@]}" == 1 ]]; then
        skip "Test only works with Debug builds (to mock the topology) or in systems with different NUMA domains"
    fi

    local i idx
    for ((i = 0, idx = 0; i < ${#domains[@]}; ++i)); do
        local d=${domains[$i]}
        local cpucount=`query_jq -r '[ ."cpu-info"[] | select(.numa_node == '$d') ] | length'`
        test_yaml_numeric "/test-plans/isolate_numa/$i/starting_cpu" "value == $idx"
        test_yaml_numeric "/test-plans/isolate_numa/$i/count" "value == $cpucount"
        idx=$((idx + cpucount))
    done
}

@test "slicing cores" {
    declare -A yamldump

    # attempt to run on four cores (on different modules), but accept two
    export SANDSTONE_MOCK_TOPOLOGY='p0c0 p0c1 p0c2 p0c3'
    set `cpuset_unique_modules 4`

    local cores_per_slice=2
    if [[ $# -eq 2 ]]; then
        cores_per_slice=1
    elif [[ $# -lt 2 ]]; then
        skip "Test only works with Debug builds (to mock the topology) or at least 2 different modules"
    fi

    IFS=,
    sandstone_yq --disable=\* --max-cores-per-slice=$cores_per_slice "--cpuset=$*"
    test_yaml_numeric "/test-plans/heuristic@len" 'value == 2'

    # The first slice has $cores_per_slice cores
    test_yaml_numeric "/test-plans/heuristic/0/starting_cpu" 'value == 0'
    test_yaml_numeric "/test-plans/heuristic/0/count" "value == $cores_per_slice"

    # The second has the remainder (1 or 2)
    test_yaml_numeric "/test-plans/heuristic/1/starting_cpu" "value == $cores_per_slice"
    test_yaml_numeric "/test-plans/heuristic/1/count" "value == $# - $cores_per_slice"
}

@test "slicing core types" {
    declare -A yamldump

    # mock a hybrid system
    export SANDSTONE_MOCK_TOPOLOGY='c0yp c0t1yp c4ye c5ye c16yp c17yp c20ye c21ye'

    # --cpuset=p0 to avoid having slicing per sockets
    # --max-cores-per-slice=$MAX_PROC to make the heuristic and NUMA-isolating
    # slices match
    sandstone_yq --disable=\* --cpuset=p0 --max-cores-per-slice=$MAX_PROC

    # Using uniq(1) instead of jq's unique function to retain the input order
    local core_types=(`query_jq -r '."cpu-info"[] | select(.core_type != null).core_type' | uniq`)
    echo "Found core types:" ${core_types[@]}
    if [[ ${#core_types[@]} -eq 0 ]]; then
        skip "Test only works with Debug builds (to mock the topology) or on systems reporting core type"
    fi

    local starting_cpu=0 slice=0
    local core_type
    for core_type in ${core_types[@]}; do
        # How many NUMA nodes in this core type?
        local numa_nodes=(`query_jq -r --arg c $core_type '[."cpu-info"[] | select(.core_type == $c) .numa_node] | unique[]'`)
        echo "NUMA nodes for $core_type-cores:" "${numa_nodes[@]}"
        for node in ${numa_nodes[@]}; do
            # How many CPUs should be in this slice?
            local count=`query_jq -r --arg c $core_type --argjson n $node \
                         '[."cpu-info"[] | select(.core_type == $c and .numa_node == $n)] | length'`
            echo "$core_type-core CPUs in NUMA node $node:" "$count"

            test_yaml_expr "/test-plans/isolate_numa/$slice/starting_cpu" = $starting_cpu
            test_yaml_expr "/test-plans/isolate_numa/$slice/count" = $count
            test_yaml_expr "/test-plans/heuristic/$slice/starting_cpu" = $starting_cpu
            test_yaml_expr "/test-plans/heuristic/$slice/count" = $count

            slice=$((slice + 1))
            starting_cpu=$((starting_cpu + count))
        done
    done

    # Confirm we've reviewed all CPUs and plans
    test_yaml_expr "/test-plans/isolate_numa@len" = $slice
    test_yaml_expr "/test-plans/heuristic@len" = $slice
    test_yaml_expr "/test-plans/fullsocket/0/count" = $starting_cpu
}
