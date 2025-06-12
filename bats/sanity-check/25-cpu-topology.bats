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

test_run_fakesockets() {
    if $is_debug; then
        if (( MAX_PROC < 4 )); then
            skip "Need at least 4 logical processors to run this test"
        fi
        SANDSTONE_MOCK_TOPOLOGY="0 1 0:1 1:1" "$@"
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

@test "num_packages" {
    declare -A yamldump
    sandstone_selftest -e selftest_skip --cpuset=p0
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" '.*"packages":\s*1\b.*'

    # attempt to run on two sockets
    export SANDSTONE_MOCK_TOPOLOGY='0 1 0:1 1:1'
    run $SANDSTONE --cpuset=p1 --dump-cpu-info
    if [[ $status -ne 0 ]]; then
        skip "Test only works with Debug builds (to mock the topology) or multi-socket systems"
    fi

    sandstone_selftest -e selftest_skip --cpuset=p0c0,p1c0 --no-slicing
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" '.*"packages":\s*2\b.*'

    # now let's try 4 sockets
    export SANDSTONE_MOCK_TOPOLOGY='0 1 2 3'
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
    run $SANDSTONE -n1 --selftests -e selftest_logs_reschedule --reschedule=queue
    if [[ $status == 64 ]]; then
       skip "Not supported"
    fi

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
