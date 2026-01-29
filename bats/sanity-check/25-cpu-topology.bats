#!/usr/bin/bats
# -*- mode: sh -*-
# Copyright 2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
load ../testenv
load helpers
MAX_PROC=`nproc`

setup_file() {
    if [[ -e /sys/devices/system/cpu/cpu0 ]] && [[ -e /sys/devices/system/cpu/cpu$n ]]; then
        false "Don't run this bats under taskset"
    fi
}

numa_nodes() {
    echo '('
    if type -p numactl >/dev/null; then
        numactl -H | awk '/node [0-9]+ cpus:/ {
            node=$2;
            sub(/.*: /, "");
            split($0, cpus);
            for (cpu in cpus)
                printf "  [%d]=%d\n", cpus[cpu], node
            }'
    fi
    echo ')'
}

test_run_fakesockets() {
    if $is_debug; then
        if (( MAX_PROC < 4 )); then
            skip "Need at least 4 logical processors to run this test"
        fi
        SANDSTONE_MOCK_TOPOLOGY="p0c0 p0c1 p1c0 p1c1" "$@"
    else
        # Maybe we're running on a real multi-socket system
        run $SANDSTONE --cpuset=p1 --dump-cpu-info
        if (( status != 0 )); then
            skip "Test only works with Debug builds (to mock the topology) or multi-socket systems"
        fi
        "$@" --cpuset=c0t0,c1t0
    fi
}

test_fail_socket1() {
    test_run_fakesockets "$@"

    # only one socket should have had problems
    test_yaml_regexp "/tests/0/fail/cpu-mask" 'None|\.+:\.*X[.X]*(:.+)?'
}

@test "cpu-info packages (fake)" {
    declare -A yamldump
    $is_debug || skip "Test only works with Debug builds to mock the topology"

    export SANDSTONE_MOCK_TOPOLOGY=`seq -s " " -f "p%g" 0 $MAX_PROC`
    echo "SANDSTONE_MOCK_TOPOLOGY=\"$SANDSTONE_MOCK_TOPOLOGY\""
    run_sandstone_yaml --disable=\*

    local i
    for ((i=0; i < ${yamldump[/cpu-info@len]}; ++i)); do
        test_yaml_numeric "/cpu-info/$i/package" "value == $i"
    done
}

@test "cpu-info cores and threads (fake)" {
    declare -A yamldump
    $is_debug || skip "Test only works with Debug builds to mock the topology"

    export SANDSTONE_MOCK_TOPOLOGY=`seq -s " " -f "c%gt1" 0 $MAX_PROC`
    echo "SANDSTONE_MOCK_TOPOLOGY=\"$SANDSTONE_MOCK_TOPOLOGY\""
    run_sandstone_yaml --disable=\*

    local i
    for ((i=0; i < ${yamldump[/cpu-info@len]}; ++i)); do
        test_yaml_numeric "/cpu-info/$i/core" "value == $i"
        test_yaml_numeric "/cpu-info/$i/thread" "value == 1"
    done
}

@test "cpu-info real topology" {
    if ! [[ -d /sys/devices/system/cpu ]]; then
        skip "Test only works on Linux with /sys mounted"
    fi
    declare -A yamldump
    run_sandstone_yaml --disable=\*

    # Get the NUMA node assignments
    eval local -A numa=`numa_nodes`

    local machine=`uname -m`
    local i
    for ((i=0; i < ${yamldump[/cpu-info@len]}; ++i)); do (
        local v
        local n=${yamldump[/cpu-info/$i/logical]}
        cd /sys/devices/system/cpu/cpu$n/

        test_yaml_expr "/cpu-info/$i/package" -eq `cat topology/physical_package_id`
        test_yaml_expr "/cpu-info/$i/core" -eq `cat topology/core_id`

        v=`cat topology/thread_siblings_list`
        (
            bats::on_failure() { echo thread_siblings_list: $v; }
            if [[ "$v" == "$n" ]] || [[ "$v" == "$n"[,-]* ]]; then
                test_yaml_expr "/cpu-info/$i/thread" = 0
            else
                test_yaml_expr "/cpu-info/$i/thread" = 1
            fi
        )

        # Our module ID from CPUID differs from what Linux reports in topology/cluster_id

        if [[ $machine = x86_64 ]]; then
            if v=`cat microcode/version 2>/dev/null`; then
                v=$(($v))   # expand hex values
                test_yaml_numeric "/cpu-info/$i/microcode" "value == $v"
            fi
            if v=`cat topology/ppin 2>/dev/null`; then
                test_yaml_expr "/cpu-info/$i/ppin" = "${v#0x}"
            else
                test_yaml_expr "/cpu-info/$i/ppin" = None
            fi
        fi

        v=${numa[$n]}
        if [[ -n "$v" ]]; then
            test_yaml_expr "/cpu-info/$i/numa_node" = $v
        fi
    ); done
}

@test "NUMA node parsing when first block skipped" {
    declare -A yamldump
    if ! [[ /sys/devices/system/node ]]; then
        skip "Test only works on Linux with /sys mounted"
    fi
    if ! [[ /sys/devices/system/node/node1 ]]; then
        skip "Test needs two or more NUMA nodes"
    fi
    if ! type -p taskset > /dev/null; then
        skip "taskset not installed"
    fi

    local node0=`cat /sys/devices/system/node/node0/cpulist`
    if ! [[ "$node0" = *,* ]]; then
        skip "Test only works with non-contiguous CPU ranges in NUMA nodes (node0 is $node0)"
    fi

    local node1=`cat /sys/devices/system/node/node1/cpulist`
    local TASKSET="-c ${node1},${node0#*,}"

    run_sandstone_yaml --disable=\*
    local i
    for ((i=0; i < ${yamldump[/cpu-info@len]}; ++i)); do
        test_yaml_expr "/cpu-info/$i/numa_node" -ne -1
    done
}

@test "obey taskset single" {
    if $is_windows; then
        skip "taskset does not apply to Windows"
    fi
    if ! type -p taskset > /dev/null; then
        skip "taskset not installed"
    fi

    # Choose a CPU at random
    local nproc=`nproc`
    local cpu=$((RANDOM % nproc))
    local TASKSET="-c $cpu"

    # Don't use sandstone_selftest because we don't want -n$MAX_PROC
    VALIDATION=dump
    declare -A yamldump
    run_sandstone_yaml -vvv --max-test-loop-count=1 --selftests -e selftest_timedpass

    test_yaml_numeric "/cpu-info/0/logical" "value == $cpu"
    test_yaml_numeric "/tests/0/threads@len" 'value == 2' # only main thread + 1
}

@test "obey taskset multi" {
    if $is_windows; then
        skip "taskset does not apply to Windows"
    fi
    if ! type -p taskset > /dev/null; then
        skip "taskset not installed"
    fi

    # Tell taskset to select all even-numbered logical CPUs (hopefully
    # none are offline)
    local nproc=`nproc`
    local TASKSET="-c 0-${nproc}:2"

    # Don't use sandstone_selftest because we don't want -n$MAX_PROC
    VALIDATION=dump
    declare -A yamldump
    run_sandstone_yaml -vvv --max-test-loop-count=1 --no-slicing --selftests -e selftest_timedpass

    test_yaml_numeric "/tests/0/threads@len" "value == $nproc / 2 + 1"
    for ((i = 0; i < nproc/2; ++i)); do
        test_yaml_numeric "/cpu-info/$i/logical" "(value % 2) == 0"
    done

    # Verify there are no more CPUs:
    [[ "${yamldump[/cpu-info/$i/logical]-unset}" = unset ]]
}

selftest_log_skip_init_socket_common() {
    local slicename=$1
    local testname=$2
    declare -A yamldump
    test_run_fakesockets sandstone_selftest --max-cores-per-slice=2 -e $testname
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" $testname

    # Because only 1 socket skipped, this is actually a pass
    test_yaml_regexp "/tests/0/result" pass
    test_yaml_absent "/tests/0/skip-category"
    test_yaml_absent "/tests/0/skip-reason"

    # But there should still be a skip message
    test_yaml_regexp "/tests/0/threads/0/thread" "$slicename"
}

@test "selftest_log_skip_init_socket0" {
    selftest_log_skip_init_socket_common 'main' selftest_log_skip_init_socket0
}

@test "selftest_log_skip_init_socket1" {
    selftest_log_skip_init_socket_common 'main 1' selftest_log_skip_init_socket1
}

@test "selftest_failinit_socket1 --max-cores-per-slice" {
    declare -A yamldump
    test_fail_socket1 sandstone_selftest -e selftest_failinit_socket1 --max-cores-per-slice=2
    [[ "$status" -eq 1 ]]
    test_yaml_regexp "/exit" fail
    test_yaml_regexp "/tests/0/result" fail
    i=$((-1 + yamldump[/tests/0/threads/0/messages@len]))
    test_yaml_regexp "/tests/0/threads/0/messages/$i/level" error
    test_yaml_regexp "/tests/0/threads/0/messages/$i/text" 'E> Init function failed.*'
}

selftest_fail_socket1_common() {
    declare -A yamldump
    test_fail_socket1 sandstone_selftest -e selftest_fail_socket1 "$@"
    [[ "$status" -eq 1 ]]
    test_yaml_regexp "/exit" fail
    test_yaml_regexp "/tests/0/result" fail

    # only one socket should have failed
    test_yaml_regexp "/tests/0/threads/0/id/package" 1
    test_yaml_regexp "/tests/0/threads/0/state" "failed"
    test_yaml_regexp "/tests/0/threads/0/thread" 2
}

@test "selftest_fail_socket1" {
    selftest_fail_socket1_common
}
@test "selftest_fail_socket1 --max-cores-per-slice" {
    selftest_fail_socket1_common --max-cores-per-slice=2
}

selftest_freeze_socket1_common() {
    declare -A yamldump
    test_fail_socket1 sandstone_selftest -vvv --on-crash=kill --on-hang=kill -e selftest_freeze_socket1 --timeout=1s "$@"
    [[ "$status" -eq 2 ]]
    test_yaml_regexp "/exit" invalid
    test_yaml_regexp "/tests/0/result" 'timed out'
    test_yaml_numeric "/tests/0/test-runtime" 'value >= 1000'

    for ((i = 0; i <= yamldump[/tests/0/threads@len]; ++i)); do
        if [[ "${yamldump[/tests/0/threads/$i/thread]}" != main* ]]; then
            break
        fi
    done
    for ((j = 0; j < i; ++j)); do
        if ((j < i - 1)); then
            test_yaml_numeric "/tests/0/threads/$j/runtime" 'value > 0'
            test_yaml_absent "/tests/0/threads/$j/messages/0/text"
        else
            test_yaml_numeric "/tests/0/threads/$j/runtime" 'value > 1000'
            test_yaml_regexp "/tests/0/threads/$j/messages/0/text" '.* Child .* did not exit.*'
        fi
        if ! $is_windows; then
            test_yaml_regexp "/tests/0/threads/$j/resource-usage" '\{.*\}'
        fi
    done

    # only one socket should have frozen
    for (( ; i <= yamldump[/tests/0/threads@len]; ++i)); do
        if [[ "${yamldump[/tests/0/threads/$i/id/package]}" = 1 ]]; then
            test_yaml_regexp "/tests/0/threads/$i/state" failed
            n=$((-1 + yamldump[/tests/0/threads/$i/messages@len]))
            test_yaml_regexp "/tests/0/threads/$i/messages/$n/text" '.*Thread is stuck'
        else
            [[ "${yamldump[/tests/0/threads/$i/state]}" != failed ]]
        fi
    done
}

@test "selftest_freeze_socket1" {
    selftest_freeze_socket1_common
}
@test "selftest_freeze_socket1 --max-cores-per-slice" {
    selftest_freeze_socket1_common --max-cores-per-slice=2
}

crash_context_socket1_common() {
    declare -A yamldump
    test_fail_socket1 selftest_crash_context_common -e selftest_sigsegv_socket1 --on-crash=context "$@"

    # only one socket should have crashed
    local threadidx=$((yamldump[/tests/0/threads@len] - 1))
    test_yaml_numeric "/tests/0/threads/$threadidx/id/package" 'value == 1'
}

@test "crash context socket1" {
    crash_context_socket1_common
}
@test "crash context socket1 --max-cores-per-slice" {
    crash_context_socket1_common  --max-cores-per-slice=1
}

function selftest_cpuset() {
    local expected_logical=$1
    local expected_package=$2
    local expected_core=$3
    local expected_thread=$4
    shift 4

    declare -A yamldump
    sandstone_selftest -vvv -e selftest_skip "$@"
    [[ "$status" -eq 0 ]]
    test_yaml_numeric "/cpu-info/0/logical" "value == $expected_logical"
    test_yaml_numeric "/cpu-info/0/package" "value == $expected_package"
    test_yaml_numeric "/cpu-info/0/core" "value == $expected_core"
    test_yaml_numeric "/cpu-info/0/thread" "value == $expected_thread"
}

@test "cpuset=number (first)" {
    # Get the first logical processor
    local -a cpuinfo=(`$SANDSTONE --dump-cpu-info | sed -n '/^[0-9]/{p;q;}'`)
    selftest_cpuset ${cpuinfo[0]} ${cpuinfo[1]} ${cpuinfo[2]} ${cpuinfo[3]} --cpuset=${cpuinfo[0]}
}

@test "cpuset=number (last)" {
    # Get the last logical processor
    local -a cpuinfo=(`$SANDSTONE --dump-cpu-info | sed -n '$p'`)
    selftest_cpuset ${cpuinfo[0]} ${cpuinfo[1]} ${cpuinfo[2]} ${cpuinfo[3]} --cpuset=${cpuinfo[0]}
}

@test "cpuset=topology (first)" {
    # Get the first logical processor
    local -a cpuinfo=(`$SANDSTONE --dump-cpu-info | sed -n '/^[0-9]/{p;q;}'`)
    selftest_cpuset ${cpuinfo[0]} ${cpuinfo[1]} ${cpuinfo[2]} ${cpuinfo[3]} \
        --cpuset=p${cpuinfo[1]}c${cpuinfo[2]}t${cpuinfo[3]}
}

@test "cpuset=topology (last)" {
    # Get the last logical processor
    local -a cpuinfo=(`$SANDSTONE --dump-cpu-info | sed -n '$p'`)
    selftest_cpuset ${cpuinfo[0]} ${cpuinfo[1]} ${cpuinfo[2]} ${cpuinfo[3]} \
        --cpuset=p${cpuinfo[1]}c${cpuinfo[2]}t${cpuinfo[3]}
}

selftest_cpuset_unsorted() {
    local MAX_PROC=`nproc`
    local cpuset=$1
    shift
    declare -A yamldump
    sandstone_selftest -e selftest_skip --cpuset="$cpuset"
    [[ "$status" -eq 0 ]]

    # Get all the processor numbers
    i=0
    for expected_logical; do
        test_yaml_numeric "/cpu-info/$i/logical" "value == $expected_logical"
        i=$((i + 1))
    done
    test_yaml_absent "/cpu-info/$i/logical"
}

@test "cpuset=number (inverse order)" {
    # make a list in inverse order
    local -a cpuset=($($SANDSTONE --dump-cpu-info | sort -rn |
                           awk '/^[0-9]/ { printf "%d,", $1; }'))
    cpuset=${cpuset%,}          # remove last comma
    local -a cpuinfo=(`$SANDSTONE --dump-cpu-info | awk '/^[0-9]/ { print $1; }'`)

    selftest_cpuset_unsorted "$cpuset" "${cpuinfo[@]}"
}

@test "cpuset=number (inverse sorted order)" {
    # sort the CPU list by package, then core then thread
    # This differs from the above on Linux, on hyperthreaded machines
    local -a cpuset=($($SANDSTONE --dump-cpu-info | sort -rnk2,3 |
                           awk '/^[0-9]/ { printf "%d,", $1; }'))
    cpuset=${cpuset%,}          # remove last comma
    local -a cpuinfo=(`$SANDSTONE --dump-cpu-info | awk '/^[0-9]/ { print $1; }'`)

    selftest_cpuset_unsorted "$cpuset" "${cpuinfo[@]}"
}

@test "cpuset=even" {
    #Get the even number of logical cpus
    local -a cpuinfo=(`$SANDSTONE --dump-cpu-info | awk '$1%2==0 &&  /^[0-9]/ {print $1}'`)
    selftest_cpuset_unsorted "even" "${cpuinfo[@]}"
}

@test "cpuset=odd" {
    #Get the odd number of logical cpus
    local -a cpuinfo=(`$SANDSTONE --dump-cpu-info | awk '$1%2!=0 && /^[0-9]/ {printf "%d " ,$1}'`)
    selftest_cpuset_unsorted "odd" "${cpuinfo[@]}"
}

selftest_cpuset_hybrid() {
    local wanted=$1
    shift

    # 1 P-core and 3 E-cores
    export SANDSTONE_MOCK_TOPOLOGY='c0yp c8ye c9ye c10ye'
    declare -A yamldump
    sandstone_yq --disable=\*

    # Count the core types (if any are known)
    local -A corecount
    corecount['e']=`query_jq '[."cpu-info"[] | select(.core_type == "e")] | length'`
    corecount['p']=`query_jq '[."cpu-info"[] | select(.core_type == "p")] | length'`

    if [[ ${corecount[$wanted]-0} = 0 ]]; then
        # No such core of this type, we'll get an error on --cpuset
        echo >&3 "# No core of type '$wanted' in this system and couldn't mock it"

        run $SANDSTONE --cpuset=type=$wanted '--disable=*'
        [[ $status = 64 ]]
        [[ "$output" = *"error: --cpuset matched nothing"* ]]
    else
        if [[ $# -eq 0 ]]; then
            set -- '--disable=*'
        fi
        sandstone_selftest --cpuset=type=$wanted "$@"
        test_yaml_numeric '/cpu-info@len' "value == ${corecount[$wanted]}"
        for ((i = 0; i < ${corecount[$wanted]}; ++i)); do
            test_yaml_expr "/cpu-info/$i/core_type" = "$wanted"
        done
    fi
}

@test "cpuset=type=e" {
    selftest_cpuset_hybrid e
}

@test "cpuset=type=p" {
    selftest_cpuset_hybrid p
}

selftest_cpuset_negated() {
    local arg=$1
    local not=$2

    # get all the CPUs, except $not
    local -a cpuinfo=(`$SANDSTONE --dump-cpu-info |
            awk -v "not=$not" '/^[0-9]/ && $1 != not { print $1; }'`)
    selftest_cpuset_unsorted "$arg" "${cpuinfo[@]}"
}

@test "cpuset=number (not first)" {
    # Get the first logical processor
    local -a cpuinfo=(`$SANDSTONE --dump-cpu-info | sed -n '/^[0-9]/{p;q;}'`)
    selftest_cpuset_negated \!${cpuinfo[0]} ${cpuinfo[0]}
}

@test "cpuset=topology (not first)" {
    # Get the first logical processor
    local -a cpuinfo=(`$SANDSTONE --dump-cpu-info | sed -n '/^[0-9]/{p;q;}'`)
    selftest_cpuset_negated \!p${cpuinfo[1]}c${cpuinfo[2]}t${cpuinfo[3]} ${cpuinfo[0]}
}

@test "cpuset=number (not last)" {
    # Get the last logical processor
    local -a cpuinfo=(`$SANDSTONE --dump-cpu-info | sed -n '$p'`)
    selftest_cpuset_negated \!${cpuinfo[0]} ${cpuinfo[0]}
}

@test "cpuset=topology (not last)" {
    # Get the last logical processor
    local -a cpuinfo=(`$SANDSTONE --dump-cpu-info | sed -n '$p'`)
    selftest_cpuset_negated \!p${cpuinfo[1]}c${cpuinfo[2]}t${cpuinfo[3]} ${cpuinfo[0]}
}

# Test if multiple --cpuset accumulate properly
# e.g. --cpuset=p0 --cpuset=c0 should be the same as --cpuset=p0c0
function selftest_cpuset_accumulate() {
    local separate=$1
    local accumulated=$2
    local expression=$3

    local cpuset=`$SANDSTONE $separate --dump-cpu-info \
                 | awk '/^[0-9]/ { printf "%d,", $1; }'`
    cpuset=${cpuset%,}          # remove last comma
    local -a cpuinfo=(`$SANDSTONE --dump-cpu-info --cpuset=$accumulated \
                     | awk '/^[0-9]/ && '"$expression"' { print $1; }'`)

    selftest_cpuset_unsorted "$cpuset" "${cpuinfo[@]}"
}

@test "cpuset accumulate (p0 c0)" {
    export SANDSTONE_MOCK_TOPOLOGY='p0c0 p0c1'

    run $SANDSTONE --cpuset=p0c0,p1c1 --dump-cpu-info
    if (( status != 0 )); then
        skip "Test only works with Debug builds (to mock the topology) or package 0 with cores 0 and 1"
    fi

    selftest_cpuset_accumulate "--cpuset=p0 --cpuset=c0" "p0c0" "1"
    selftest_cpuset_accumulate "--cpuset=c0 --cpuset=p0" "p0c0" "1"
}

@test "cpuset accumulate (p0 c0,c1)" {
    export SANDSTONE_MOCK_TOPOLOGY='p0c0 p0c1'

    run $SANDSTONE --cpuset=p0c0,p1c1 --dump-cpu-info
    if (( status != 0 )); then
        skip "Test only works with Debug builds (to mock the topology) or package 0 with cores 0 and 1"
    fi

    selftest_cpuset_accumulate "--cpuset=p0 --cpuset=c0,c1" "p0c0,p0c1" "1"
}

@test "cpuset accumulate (p0 !c0 / p0 !c1)" {
    export SANDSTONE_MOCK_TOPOLOGY='p0c0 p0c1'

    run $SANDSTONE --cpuset=p0c0,p1c1 --dump-cpu-info
    if (( status != 0 )); then
        skip "Test only works with Debug builds (to mock the topology) or package 0 with cores 0 and 1"
    fi

    selftest_cpuset_accumulate "--cpuset=p0 --cpuset=!c0" "p0" "\$3!=0"
    selftest_cpuset_accumulate "--cpuset=p0 --cpuset=!c1" "p0" "\$3!=1"
}

@test "num_packages" {
    export SANDSTONE_MOCK_TOPOLOGY='p0c0 p0c1 p1c0 p1c1'

    # Get the first and last logical processors (might be what we mocked)
    local -a first=(`$SANDSTONE --dump-cpu-info | sed -n '/^[0-9]/{p;q;}'`)
    local -a last=(`$SANDSTONE --dump-cpu-info | sed -n '$p'`)

    declare -A yamldump
    sandstone_selftest -e selftest_skip --cpuset=p${first[1]}
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" '.*"packages":\s*1\b.*'

    if [[ ${first[1]} -eq ${last[1]} ]]; then
        skip "Test only works with Debug builds (to mock the topology) or multi-socket systems"
    fi

    sandstone_selftest -e selftest_skip --cpuset=p${first[1]}c0,p${last[1]}c0 --no-slicing
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" '.*"packages":\s*2\b.*'

    # now let's try 4 sockets
    export SANDSTONE_MOCK_TOPOLOGY='p0 p1 p2 p3'
    run $SANDSTONE --cpuset=p3 --dump-cpu-info
    if [[ $status -eq 0 ]]; then
        sandstone_selftest -e selftest_skip --cpuset=p0c0,p1c0,p2c0,p3c0 --no-slicing
        test_yaml_regexp "/tests/0/threads/0/messages/0/text" '.*"packages":\s*4\b.*'
    fi
}

# Confirm that we are roughly using the threads we said we would
@test "thread usage" {
    local -a cpuset=(`$SANDSTONE --dump-cpu-info | awk '/^[0-9]/ { print $1 }'`)
    nproc=${#cpuset[@]}

    # Don't use sandstone_selftest to avoid -n$MAX_PROC
    VALIDATION=dump
    declare -A yamldump
    run_sandstone_yaml --disable=mce_check --selftests --timeout=20s --retest-on-failure=0 -e selftest_logs_getcpu

    # Did we get anything?
    if [[ ${yamldump[/tests/0/result]} = skip ]]; then
        skip "Test did not report results: ${yamldump/tests/0/threads/0/messages/0/text}"
    fi

    test_yaml_numeric "/tests/0/threads@len" "value == $nproc"
    for ((i = 0; i < yamldump[/tests/0/threads@len]; ++i)); do
        test_yaml_regexp "/tests/0/threads/$i/messages/0/text" "I> ${cpuset[$i]}\$"
    done
}

# Confirm we are rescheduling properly
@test "thread queue reschedule" {
    PLATFORM=$(uname -m)
    if [[ "${PLATFORM}" != "x86_64" ]]; then
        skip "Not supported"
    fi

    if $is_windows; then
       skip "Reschedule isn't supported "
    fi

    run $SANDSTONE --selftests -e selftest_logs_reschedule --reschedule=queue
    [[ $status == 64 ]] && false

    local -a cpuset=(`$SANDSTONE --dump-cpu-info | awk '/^[0-9]/ { print $1 }'`)
    nproc=${#cpuset[@]}

    declare -A yamldump
    sandstone_selftest -e selftest_logs_reschedule -n4 -s LCG:232155056 --reschedule=queue

    # Did we get anything?
    if [[ ${yamldump[/tests/0/result]} = skip ]]; then
        skip "Test did not report results: ${yamldump/tests/0/threads/0/messages/0/text}"
    fi

    # Same seed will always give us the same combination for rescheduling
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" "I> ${cpuset[0]}\$"
    test_yaml_regexp "/tests/0/threads/0/messages/1/text" "I> ${cpuset[1]}\$"

    test_yaml_regexp "/tests/0/threads/1/messages/0/text" "I> ${cpuset[1]}\$"
    test_yaml_regexp "/tests/0/threads/1/messages/1/text" "I> ${cpuset[2]}\$"

    test_yaml_regexp "/tests/0/threads/2/messages/0/text" "I> ${cpuset[2]}\$"
    test_yaml_regexp "/tests/0/threads/2/messages/1/text" "I> ${cpuset[0]}\$"

    test_yaml_regexp "/tests/0/threads/3/messages/0/text" "I> ${cpuset[3]}\$"
    test_yaml_regexp "/tests/0/threads/3/messages/1/text" "I> ${cpuset[3]}\$"
}

@test "selftest test smt skip" {
    declare -A yamldump
    # if all thread ids are 0(--cpuset=t0) skip the test
    sandstone_selftest -e selftest_requires_smt --cpuset=t0

    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/tests/0/result" 'skip'
    test_yaml_regexp "/tests/0/skip-category" 'CpuTopologyIssue'
    test_yaml_regexp "/tests/0/skip-reason" 'Test requires SMT \(hyperthreading\)'
}

@test "selftest test smt run" {
    # core0 has 2 threads(0 and 1) where as core1 and core2 have only thread0
    export SANDSTONE_MOCK_TOPOLOGY="p0c0t0 p0c0t1 p0c1t0 p0c2t0"
    echo "SANDSTONE_MOCK_TOPOLOGY=\"$SANDSTONE_MOCK_TOPOLOGY\""

    declare -A yamldump
    # run the test
    sandstone_yq -e selftest_requires_smt --selftests --disable=mce_check

    local threads1=`query_jq '."cpu-info"[] | select(.thread != 0) .logical'`

    if [[ -z "$threads1" ]]; then
        skip "Test only works with Debug builds to mock the topology or CPUs with hyperthreading"
    else
        test_yaml_regexp "/tests/0/result" 'pass'
    fi
}
