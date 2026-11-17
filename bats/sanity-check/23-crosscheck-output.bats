#!/usr/bin/bats
# Copyright 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
load ../testenv
load helpers

setup_file() {
    [[ "$SANDSTONE_DEVICE_TYPE" = CPU ]] || skip "CPU submission fixtures require a CPU build"
}

vote_run() {
    local workers=$1
    shift
    sandstone_selftest -vvv --max-messages=100 -n"$workers" -e selftest_crosscheck_votes "$@"
}

cpu_run() {
    # Sequential test threads keep separate snapshots even when the OS thread is reused.
    local workers=$1 scenario=$2 fixture=selftest_crosscheck_votes_sequential
    shift 2
    sandstone_selftest -vvv --max-messages=100 -n"$workers" -e "$fixture" \
        -O "$fixture.cpu_case=$scenario" "$@"
    if [[ "$status" -eq 0 && "$output" = *"Cannot pin cross-check fixture"* ]]; then
        skip "Cannot pin CPU submission fixture to the required CPUs"
    fi
}

require_cpus() {
    # Probe the executable's allowed CPU set without the shared harness's -n cap.
    local MAX_PROC= required=$1
    sandstone_selftest --disable='*'
    [[ "$status" -eq 0 ]]
    ((${yamldump[/cpu-info@len]} >= required)) || skip "Requires $required available CPUs"
}

check_passing_retry() {
    [[ "$status" -eq 1 ]]
    test_yaml_regexp /exit fail
    test_yaml_numeric /tests@len 'value == 2'
    test_yaml_regexp /tests/0/result fail
    test_yaml_regexp /tests/0/state/retry False
    test_yaml_regexp /tests/1/result pass
    test_yaml_regexp /tests/1/state/retry True
    test_yaml_numeric /tests/1/state/iteration 'value == 1'
    [[ "$output" != *"snapshots survived"* ]]
    [[ "$output" != *"captures survived"* ]]
}

vote_failure() {
    [[ "$status" -eq 1 ]]
    test_yaml_regexp /tests/0/result fail
    test_yaml_regexp /exit fail
    test_yaml_regexp /tests/0/fail/cpu-mask '[._:X1-9a-f]*[X1-9a-f][._:X1-9a-f]*'
    local path mismatches=0
    for path in "${!yamldump[@]}"; do
        if [[ "$path" = /tests/0/threads/*/messages/*/data-miscompare/description ]]; then
            test_yaml_expr "$path" = 'Cross-check output mismatch'
            ((++mismatches))
        fi
    done
    ((mismatches > 0))
    test_crosscheck_message 0 'I> vote cleanup retained snapshots'
    # Reject OS-error diagnostics anywhere, not just on the mismatch reporter.
    [[ "$output" != *"operating system error"* ]]
    (($# == 0)) || vote_expect_mask "$@"
}

# Expected mask entries are selected device indices, never worker indices.
vote_expect_mask() {
    local device i key package core cpu group thread expected='' padding char bits
    local -A selected=() totals=() failures=() masks=() package_masks=()
    local -a cores=() packages=()
    for device in "$@"; do
        cpu=${yamldump[/cpu-info/$device/logical]}
        group=${yamldump[/cpu-info/$device/logical-group]:-0}
        selected[$group:$cpu]=1
    done
    for ((i=0; i<${yamldump[/cpu-info@len]}; ++i)); do
        package=${yamldump[/cpu-info/$i/package]}
        core=${yamldump[/cpu-info/$i/core]}
        thread=${yamldump[/cpu-info/$i/thread]}
        cpu=${yamldump[/cpu-info/$i/logical]}
        group=${yamldump[/cpu-info/$i/logical-group]:-0}
        key=$package:$core
        if [[ ! ${totals[$key]+set} ]]; then
            cores+=("$key")
            totals[$key]=0 failures[$key]=0 masks[$key]=0
            if [[ ! ${package_masks[$package]+set} ]]; then
                packages+=("$package")
                package_masks[$package]=''
            fi
        fi
        totals[$key]=$(( ${totals[$key]} + 1 ))
        if [[ ${selected[$group:$cpu]:-0} = 1 ]]; then
            failures[$key]=$(( ${failures[$key]} + 1 ))
            masks[$key]=$(( ${masks[$key]} | (1 << thread) ))
        fi
    done
    local maxcores=0
    for key in "${cores[@]}"; do
        package=${key%%:*}
        bits=${masks[$key]}
        if ((bits == 0)); then
            char=.
        elif (( ${failures[$key]} == ${totals[$key]} )); then
            char=X
        else
            printf -v char '%x' "$bits"
        fi
        package_masks[$package]+=$char
        ((${#package_masks[$package]} <= maxcores)) || maxcores=${#package_masks[$package]}
    done
    for package in "${packages[@]}"; do
        printf -v padding '%*s' "$((maxcores - ${#package_masks[$package]}))" ''
        expected+=${expected:+:}${package_masks[$package]}${padding// /_}
    done
    test_yaml_expr /tests/0/fail/cpu-mask = "$expected"
}

vote_no_deferred() {
    test_yaml_absent /tests/0/fail/crosscheck-no-majority
    [[ "$output" != *"one test thread submitted; no deferred comparison"* ]]
    local thread message path
    for ((thread=0; thread<${yamldump[/tests/0/threads@len]}; ++thread)); do
        for ((message=0; message<${yamldump[/tests/0/threads/$thread/messages@len]:-0}; ++message)); do
            path=/tests/0/threads/$thread/messages/$message/data-miscompare/details
            # Only deferred comparisons carry value-class membership.
            test_yaml_absent "$path/value_class"
            test_yaml_absent "$path/reference_value_class"
            test_yaml_absent "$path/value_classes_description"
        done
    done
}

test_crosscheck_message() {
    local thread=$1 expected=$2 count=${3:-1} attempt=${4:-0} message path matches=0 level=skip
    # Info/error text retains its prefix; skip text has a separate YAML level.
    case "$expected" in
        'I> '*) level=info ;;
        'E> '*) level=error ;;
    esac
    # Submissions, cleanup, and failure callbacks add messages before/after each
    # mismatch; init snapshots can report through the main thread.
    for ((message=0; message<${yamldump[/tests/$attempt/threads/$thread/messages@len]:-0}; ++message)); do
        path=/tests/$attempt/threads/$thread/messages/$message
        if [[ ${yamldump[$path/text]:-} = "$expected" ]]; then
            test_yaml_expr "$path/text" = "$expected"
            test_yaml_expr "$path/level" = "$level"
            ((++matches))
        fi
    done
    if [[ "$matches" -ne "$count" ]]; then
        echo "Expected $count parsed messages for attempt $attempt thread $thread, got $matches: $expected"
        return 1
    fi
}

crosscheck_no_mismatch() {
    local attempt thread message
    for ((attempt=0; attempt<${yamldump[/tests@len]}; ++attempt)); do
        for ((thread=0; thread<${yamldump[/tests/$attempt/threads@len]:-0}; ++thread)); do
            for ((message=0; message<${yamldump[/tests/$attempt/threads/$thread/messages@len]:-0}; ++message)); do
                test_yaml_absent "/tests/$attempt/threads/$thread/messages/$message/data-miscompare"
            done
        done
    done
}

check_crosscheck_device_description() {
    local path=$1 device=$2 cpu=${yamldump[/cpu-info/$2/logical]}
    # Topology is a flow-map string, not a nested object; spacing is device-specific.
    test_yaml_regexp "$path" "\\{ .*logical: *$cpu(,| ).*\\}" || return
    test_yaml_absent "$path/logical" || return
    if $is_windows; then
        test_yaml_regexp "$path" ".*logical-group: *${yamldump[/cpu-info/$device/logical-group]},.*" || return
    fi
}

find_crosscheck_mismatch() {
    local thread=$1 name=${2:-vote_a} device=${3:-} message path cpu
    if [[ -n "$device" ]]; then
        cpu=${yamldump[/cpu-info/$device/logical]}
        if $is_windows; then
            cpu=$((cpu + 64 * ${yamldump[/cpu-info/$device/logical-group]}))
        fi
    fi
    # Fixture messages precede immediate/deferred failures differently, and a
    # failure callback inserts messages between multiple mismatches on one worker.
    for ((message=0; message<${yamldump[/tests/0/threads/$thread/messages@len]:-0}; ++message)); do
        path=/tests/0/threads/$thread/messages/$message/data-miscompare
        if [[ ${yamldump[$path/details/output]:-} = "$name"
                && ( -z "$device" || ${yamldump[$path/details/host_cpu]:-} = "$cpu" ) ]]; then
            crosscheck_mismatch=$path
            test_yaml_expr "$path/description" = 'Cross-check output mismatch' || return
            test_yaml_expr "$path/details/output" = "$name" || return
            if [[ -n "$device" ]]; then
                check_crosscheck_device_description "$path/details/device_description" "$device" || return
                test_yaml_numeric "$path/details/host_cpu" "value == $cpu" || return
            fi
            return 0
        fi
    done
    echo "No parsed cross-check mismatch details for thread $thread"
    return 1
}

check_escaped_crosscheck_details() {
    local scenario=$1 cpu reference_cpu crosscheck_mismatch
    [[ "$status" -eq 1 ]]
    test_yaml_regexp /tests/0/result fail
    vote_expect_mask 1
    find_crosscheck_mismatch 1 $'thread\'s output: words\nsecond line\n' 1
    # format_yaml uses YAML literal blocks with a trailing newline for multiline values.
    test_yaml_expr "$crosscheck_mismatch/details/output" = $'thread\'s output: words\nsecond line\n'
    test_yaml_expr "$crosscheck_mismatch/details/first_description" = \
        $'first submission\'s description: value\nretained detail\n'
    cpu=${yamldump[/cpu-info/1/logical]}
    reference_cpu=${yamldump[/cpu-info/0/logical]}
    if $is_windows; then
        cpu=$((cpu + 64 * ${yamldump[/cpu-info/1/logical-group]}))
        reference_cpu=$((reference_cpu + 64 * ${yamldump[/cpu-info/0/logical-group]}))
    fi
    check_crosscheck_device_description "$crosscheck_mismatch/details/device_description" 1
    test_yaml_numeric "$crosscheck_mismatch/details/host_cpu" "value == $cpu"
    if [[ "$scenario" = 10 ]]; then
        test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'later submission vs first submission'
        reference_cpu=$cpu
        vote_no_deferred
    else
        test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = \
            'strict majority baseline (not proven correct)'
        test_yaml_numeric "$crosscheck_mismatch/details/value_class" 'value == 0'
        test_yaml_numeric "$crosscheck_mismatch/details/reference_value_class" 'value == 1'
        test_yaml_regexp "$crosscheck_mismatch/details/value_classes_description" '.*value class 0:.*value class 1:.*'
        local device
        for device in 0 1 2; do
            test_yaml_regexp "$crosscheck_mismatch/details/value_classes_description" \
                ".*logical: *${yamldump[/cpu-info/$device/logical]}(,| ).*"
        done
    fi
    local reference_device=0
    [[ "$scenario" != 10 ]] || reference_device=1
    check_crosscheck_device_description "$crosscheck_mismatch/details/reference_device_description" "$reference_device"
    test_yaml_numeric "$crosscheck_mismatch/details/reference_host_cpu" "value == $reference_cpu"
    local field
    for field in 'actual data' 'expected data'; do
        # Quiet output may omit the byte dump; an exhausted dump is YAML null.
        if [[ ${yamldump[$crosscheck_mismatch/$field]+present} ]]; then
            test_yaml_expr "$crosscheck_mismatch/$field" = None
        else
            test_yaml_absent "$crosscheck_mismatch/$field"
        fi
    done
}

@test "crosscheck init and test thread agreement use test thread snapshots" {
    declare -A yamldump
    vote_run 1 -O selftest_crosscheck_votes.init=0
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result pass
    test_crosscheck_message 0 "I> Cross-check output 'vote_a': one test thread submitted; no deferred comparison"
    ((MAX_PROC >= 2)) || return 0
    vote_run 2
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result pass
    [[ "$output" != *"one test thread submitted; no deferred comparison"* ]]
}

@test "crosscheck init and test thread zero fail immediately on disagreement" {
    ((MAX_PROC >= 2)) || skip "Requires two workers"
    declare -A yamldump
    vote_run 2 -O selftest_crosscheck_votes.init=1
    vote_failure 0
    local crosscheck_mismatch
    find_crosscheck_mismatch 1 vote_a 0
    test_yaml_expr "$crosscheck_mismatch/details/first_description" = 'CPU computation in init'
    test_yaml_regexp /tests/0/threads/1/state failed
    test_yaml_absent /tests/0/threads/2/state
    test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'later submission vs first submission'
    test_crosscheck_message 1 'I> output failure callback fired for worker 0'
    test_crosscheck_message 2 'I> output failure callback fired for worker 1' 0
    vote_no_deferred
}

@test "crosscheck worker zero can be the majority outlier" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    vote_run 3 -O selftest_crosscheck_votes.values=1
    vote_failure 0
    test_yaml_absent /tests/0/fail/crosscheck-no-majority
    [[ "$output" != *"Topology analysis shows observed implicated-device patterns"* ]]
    test_yaml_regexp /tests/0/threads/1/state failed
    test_yaml_absent /tests/0/threads/2/state
    test_yaml_absent /tests/0/threads/3/state
    local crosscheck_mismatch
    find_crosscheck_mismatch 1 vote_a 0
    test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'strict majority baseline (not proven correct)'
    test_crosscheck_message 1 'I> output failure callback fired for worker 0'
}

@test "crosscheck matching init and thread zero add no fourth vote to a three-thread majority" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    vote_run 3 -O selftest_crosscheck_votes.init=1 -O selftest_crosscheck_votes.values=1
    vote_failure 0
    local crosscheck_mismatch
    find_crosscheck_mismatch 0 vote_a 0
    test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'strict majority baseline (not proven correct)'
    test_yaml_expr "$crosscheck_mismatch/details/first_description" = 'CPU computation in init'
    test_yaml_absent /tests/0/fail/crosscheck-no-majority
}

@test "crosscheck one test thread's init and run disagreement is not a two-vote tie" {
    declare -A yamldump
    vote_run 1 -O selftest_crosscheck_votes.init=1
    vote_failure 0
    local crosscheck_mismatch
    find_crosscheck_mismatch 1 vote_a 0
    test_yaml_expr "$crosscheck_mismatch/details/first_description" = 'CPU computation in init'
    test_yaml_regexp /tests/0/threads/1/state failed
    test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'later submission vs first submission'
    vote_no_deferred
}

@test "crosscheck ties and distinct values implicate every conflicting test thread's CPU" {
    ((MAX_PROC >= 2)) || skip "Requires two workers"
    declare -A yamldump
    local workers values worker
    for workers in 2 3 4; do
        ((MAX_PROC >= workers)) || continue
        case "$workers" in
            2) values=4 ;; # 0,1
            3) values=36 ;; # 0,1,2
            4) values=80 ;; # 0,0,1,1
        esac
        vote_run "$workers" -O "selftest_crosscheck_votes.values=$values"
        vote_failure
        test_yaml_expr /tests/0/fail/crosscheck-no-majority = True
        [[ "$output" = *"Cross-check had no strict majority: conflicting devices are suspects."* ]]
        [[ "$output" = *"Topology analysis shows observed implicated-device patterns, not independent proof of faulty hardware"* ]]
        [[ "$output" = *"does not identify which conflicting result is incorrect"* ]]
        local -a devices=()
        for ((worker=0; worker<workers; ++worker)); do devices+=("$worker"); done
        vote_expect_mask "${devices[@]}"
        for ((worker=1; worker<=workers; ++worker)); do
            test_yaml_regexp "/tests/0/threads/$worker/state" failed
            local crosscheck_mismatch
            find_crosscheck_mismatch "$worker" vote_a "$((worker - 1))"
            test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'no strict majority; conflicting peer'
        done
    done
}

@test "crosscheck submitted outputs vote even when their test threads later skip" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    local after
    for after in 0 1; do
        vote_run 3 -O selftest_crosscheck_votes.skips=1 \
            -O selftest_crosscheck_votes.values=1 -O "selftest_crosscheck_votes.after=$after"
        if [[ "$after" = 0 ]]; then
            [[ "$status" -eq 0 ]]
            test_yaml_regexp /tests/0/result pass
            test_crosscheck_message 0 'I> vote worker 0 final state -2'
            crosscheck_no_mismatch
        else
            vote_failure 0
            test_crosscheck_message 0 'I> vote worker 0 final state 2'
            local crosscheck_mismatch
            find_crosscheck_mismatch 1 vote_a 0
            test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'strict majority baseline (not proven correct)'
        fi
        test_crosscheck_message 1 'original vote worker skip'
    done
}

@test "crosscheck losing worker zero does not suppress remaining disagreement" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    vote_run 3 -O selftest_crosscheck_votes.skips=1 -O selftest_crosscheck_votes.values=16
    vote_failure
    test_crosscheck_message 0 'I> vote worker 0 final state -2'
    test_yaml_regexp /tests/0/threads/2/state failed
    test_yaml_regexp /tests/0/threads/3/state failed
}

@test "crosscheck single submissions pass and all worker skips still clean up" {
    declare -A yamldump
    vote_run 1
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result pass
    test_crosscheck_message 0 "I> Cross-check output 'vote_a': one test thread submitted; no deferred comparison"
    test_crosscheck_message 0 'I> vote cleanup retained snapshots'
    vote_run 1 -O selftest_crosscheck_votes.init=0 -O selftest_crosscheck_votes.skips=1
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result skip
    test_crosscheck_message 0 'I> vote cleanup retained snapshots'
    crosscheck_no_mismatch
    [[ "$output" != *"one test thread submitted; no deferred comparison"* ]]
    ((MAX_PROC >= 2)) || return 0
    vote_run 2 -O selftest_crosscheck_votes.skips=3 -O selftest_crosscheck_votes.after=1 \
        -O selftest_crosscheck_votes.values=4
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result skip
    test_crosscheck_message 0 'I> vote cleanup retained snapshots'
    crosscheck_no_mismatch
    vote_no_deferred
}

@test "crosscheck final attribution includes failures across output names" {
    ((MAX_PROC >= 3)) || skip "Requires three selected CPUs"
    declare -A yamldump
    vote_run 3 -O selftest_crosscheck_votes.values=1 -O selftest_crosscheck_votes.two_names=1
    vote_failure 0 1
    test_yaml_regexp /tests/0/threads/1/state failed
    test_yaml_regexp /tests/0/threads/2/state failed
    test_yaml_absent /tests/0/threads/3/state
    local crosscheck_mismatch
    find_crosscheck_mismatch 1 vote_a 0
    find_crosscheck_mismatch 2 vote_z 1
}

@test "crosscheck optional names include disjoint workers and init-only names" {
    declare -A yamldump
    local shape
    vote_run 1 -O selftest_crosscheck_votes.repeat=1
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result pass
    for shape in 4 5; do
        vote_run 1 -O "selftest_crosscheck_votes.shape=$shape" \
            -O selftest_crosscheck_votes.init=0
        [[ "$status" -eq 0 ]]
        test_yaml_regexp /tests/0/result pass
    done
    ((MAX_PROC >= 2)) || return 0
    for shape in 1 4; do
        vote_run 2 -O "selftest_crosscheck_votes.shape=$shape" \
            -O selftest_crosscheck_votes.values=4
        [[ "$status" -eq 0 ]]
        test_yaml_regexp /tests/0/result pass
        crosscheck_no_mismatch
    done
}

@test "crosscheck type or count errors abort after cleanup and cannot be waived" {
    ((MAX_PROC >= 2)) || skip "Requires two workers"
    declare -A yamldump
    local shape
    for shape in 2 3; do
        vote_run 2 --ignore-os-errors -O "selftest_crosscheck_votes.shape=$shape"
        [[ "$status" -eq 1 ]]
        test_yaml_regexp /tests/0/result crash
        test_yaml_absent /tests/0/fail/crosscheck-no-majority
        test_crosscheck_message 1 "E> Cross-check output 'vote_a': element type or count mismatch"
        crosscheck_no_mismatch
        local worker
        for worker in 0 1; do
            test_crosscheck_message "$((worker + 1))" "I> output failure callback fired for worker $worker" 0
        done
        test_crosscheck_message 0 'I> output failure callback fired for worker -1' 0
        test_crosscheck_message 0 'I> vote cleanup retained snapshots'
    done
}

@test "crosscheck data failure survives structural errors cleanup skip and OS-error waiver" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    vote_run 3 --ignore-os-errors -O selftest_crosscheck_votes.shape=2 \
        -O selftest_crosscheck_votes.two_names=1 -O selftest_crosscheck_votes.cleanup_skip=1
    vote_failure 1
    local crosscheck_mismatch
    find_crosscheck_mismatch 2 vote_z 1
}

@test "crosscheck cleanup failure takes precedence over deferred structural errors" {
    ((MAX_PROC >= 2)) || skip "Requires two workers"
    declare -A yamldump
    vote_run 2 --ignore-os-errors -O selftest_crosscheck_votes.shape=2 \
        -O selftest_crosscheck_votes.cleanup_failure=1
    [[ "$status" -eq 1 ]]
    test_yaml_regexp /tests/0/result fail
    test_crosscheck_message 0 'E> original vote cleanup error'
    test_crosscheck_message 1 "E> Cross-check output 'vote_a': element type or count mismatch"
    crosscheck_no_mismatch
}

@test "crosscheck optional names count only actual submitters toward a strict majority" {
    ((MAX_PROC >= 4)) || skip "Requires four workers"
    declare -A yamldump
    vote_run 4 -O selftest_crosscheck_votes.shape=1 -O selftest_crosscheck_votes.values=80
    vote_failure 1
    test_yaml_absent /tests/0/threads/1/state
    test_yaml_regexp /tests/0/threads/2/state failed
    test_yaml_absent /tests/0/threads/3/state
    test_yaml_absent /tests/0/threads/4/state
    local crosscheck_mismatch
    find_crosscheck_mismatch 2 vote_a 1
    test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'strict majority baseline (not proven correct)'
}

@test "crosscheck later submission mismatch fails without a second test thread" {
    declare -A yamldump
    vote_run 1 -O selftest_crosscheck_votes.later=0
    vote_failure
    local crosscheck_mismatch
    find_crosscheck_mismatch 1 vote_a 0
    test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'later submission vs first submission'
}

@test "crosscheck temporal failure stops deferred disagreements and structural diagnostics" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    vote_run 3 -O selftest_crosscheck_votes.later=2 -O selftest_crosscheck_votes.shape=2 \
        -O selftest_crosscheck_votes.two_names=1
    vote_failure
    local crosscheck_mismatch
    find_crosscheck_mismatch 3 vote_a 2
    test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'later submission vs first submission'
    vote_no_deferred
    test_crosscheck_message 1 "E> Cross-check output 'vote_a': element type or count mismatch" 0
    local path
    for path in "${!yamldump[@]}"; do
        if [[ "$path" = /tests/0/threads/*/messages/*/data-miscompare/details/output ]]; then
            test_yaml_expr "$path" != vote_z
        fi
    done
}

@test "crosscheck init mismatch and init skip do not start workers" {
    declare -A yamldump
    vote_run 1 -O selftest_crosscheck_votes.init=0 -O selftest_crosscheck_votes.later=-2
    [[ "$status" -eq 1 ]]
    local crosscheck_mismatch
    find_crosscheck_mismatch 0 vote_a 0
    test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'later submission vs first submission'
    test_crosscheck_message 0 'I> vote cleanup retained snapshots' 0
    vote_run 1 -O selftest_crosscheck_votes.init=0 -O selftest_crosscheck_votes.init_skip=1
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result skip
    test_crosscheck_message 0 'I> vote cleanup retained snapshots' 0
}

@test "crosscheck deferred outlier uses completion CPU not first submission CPU" {
    ((MAX_PROC >= 3)) || skip "Requires three selected CPUs"
    declare -A yamldump
    cpu_run 3 1
    vote_failure 1
    test_yaml_regexp /tests/0/threads/1/state failed
    test_yaml_absent /tests/0/threads/2/state
    test_yaml_absent /tests/0/threads/3/state
    local crosscheck_mismatch
    find_crosscheck_mismatch 1 vote_a 1
    test_yaml_expr "$crosscheck_mismatch/details/first_description" = 'independent test thread snapshot'
    test_yaml_numeric "$crosscheck_mismatch/details/thread" 'value == 0'
    local first_cpu=${yamldump[/cpu-info/0/logical]}
    if $is_windows; then
        first_cpu=$((first_cpu + 64 * ${yamldump[/cpu-info/0/logical-group]}))
    fi
    test_yaml_numeric "$crosscheck_mismatch/details/first_submission_host_cpu" \
        "value == $first_cpu"
    test_yaml_expr "$crosscheck_mismatch/details/placement_description" = 'test thread completion CPU/device'
    test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'strict majority baseline (not proven correct)'
    test_crosscheck_message 1 'I> output failure callback fired for worker 0'
    test_crosscheck_message 2 'I> output failure callback fired for worker 1' 0
}

@test "crosscheck sequential test threads on the same CPU retain separate votes" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    cpu_run 3 2 --no-slicing
    vote_failure 0
    test_yaml_regexp /tests/0/threads/1/state failed
    local thread
    for thread in 2 3; do
        test_yaml_absent "/tests/0/threads/$thread/state"
    done
    local crosscheck_mismatch
    find_crosscheck_mismatch 1 vote_a 0
    test_yaml_numeric "$crosscheck_mismatch/details/thread" 'value == 0'
    test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'strict majority baseline (not proven correct)'
    test_yaml_regexp "$crosscheck_mismatch/details/value_classes_description" '.*thread 0:.*thread 1:.*thread 2:.*'
    test_crosscheck_message 1 'I> output failure callback fired for worker 0'
}

@test "crosscheck logging preserves the first failure tuple and restores reporting context" {
    ((MAX_PROC >= 2)) || skip "Requires two selected CPUs"
    declare -A yamldump
    local logging
    for logging in 1 2; do
        vote_run 2 -O selftest_crosscheck_votes.shape=5 -O "selftest_crosscheck_votes.logging=$logging"
        [[ "$status" -eq 1 ]]
        test_yaml_regexp /tests/0/result fail
        test_crosscheck_message 0 'I> logging preserved first CPU time and loop tuple'
        test_crosscheck_message 1 'I> output failure callback fired for worker 0'
        test_crosscheck_message 1 'E> logging later ordinary tuple fixture'
        if [[ "$logging" = 2 ]]; then
            test_crosscheck_message 0 'I> logging reporting context restored persistent flags'
        fi
    done
}

@test "crosscheck equal submissions after migration retain one test thread snapshot" {
    ((MAX_PROC >= 2)) || skip "Requires two selected CPUs"
    declare -A yamldump
    cpu_run 2 3
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result pass
    crosscheck_no_mismatch
    test_crosscheck_message 1 'I> test thread retained its original snapshot after migration'
    test_crosscheck_message 0 'I> test_cleanup retained one test thread snapshot and completion device 1'
    test_crosscheck_message 0 "I> Cross-check output 'vote_a': one test thread submitted; no deferred comparison"
}

@test "crosscheck unequal migrated repeat immediately fails on detection CPU" {
    ((MAX_PROC >= 2)) || skip "Requires two selected CPUs"
    declare -A yamldump
    cpu_run 2 4
    vote_failure 1
    local crosscheck_mismatch
    find_crosscheck_mismatch 1 vote_a 1
    test_yaml_expr "$crosscheck_mismatch/details/first_description" = 'original A snapshot'
    test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'later submission vs first submission'
    test_crosscheck_message 0 'I> test_cleanup retained one test thread snapshot and completion device 1'
    test_crosscheck_message 1 'I> test thread retained its original snapshot after migration' 0
    vote_no_deferred
    test_yaml_absent /tests/0/threads/2/state
}

@test "crosscheck test thread zero checks init snapshot after migration without another vote" {
    ((MAX_PROC >= 2)) || skip "Requires two selected CPUs"
    declare -A yamldump
    cpu_run 2 3 -O selftest_crosscheck_votes_sequential.init=0 \
        -O selftest_crosscheck_votes_sequential.init_cpu=1
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result pass
    test_crosscheck_message 0 'I> test_cleanup retained one test thread snapshot and completion device 1'
    test_crosscheck_message 0 "I> Cross-check output 'vote_a': one test thread submitted; no deferred comparison"
    crosscheck_no_mismatch
}

@test "crosscheck cancellation captures completion placement before normal return" {
    ((MAX_PROC >= 2)) || skip "Requires two selected CPUs"
    declare -A yamldump
    cpu_run 2 13
    [[ "$status" -eq 1 ]]
    test_yaml_regexp /tests/0/result fail
    test_crosscheck_message 0 'I> test_cleanup retained one test thread snapshot and completion device 1'
    crosscheck_no_mismatch
    vote_no_deferred
}

@test "crosscheck concurrent immediate failures on the same CPU record one device mask" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    vote_run 3 -O selftest_crosscheck_votes.cpu_case=14
    if [[ "$status" -eq 0 && "$output" = *"Cannot pin cross-check fixture"* ]]; then
        skip "Cannot pin test threads to the same CPU"
    fi
    vote_failure 0
    local worker crosscheck_mismatch
    for worker in 0 1 2; do
        find_crosscheck_mismatch "$((worker + 1))" vote_a 0
        test_yaml_numeric "$crosscheck_mismatch/details/thread" "value == $worker"
    done
    vote_no_deferred
}

@test "crosscheck strict majority compares whole arrays rather than individual elements" {
    ((MAX_PROC >= 3)) || skip "Requires three selected CPUs"
    declare -A yamldump
    cpu_run 3 9
    vote_failure 0 1 2
    local thread crosscheck_mismatch
    for thread in 1 2 3; do
        find_crosscheck_mismatch "$thread" vote_a "$((thread - 1))"
        test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'no strict majority; conflicting peer'
    done
}

@test "crosscheck immediate mismatch preserves arbitrary metadata with exhausted reporting budgets" {
    ((MAX_PROC >= 2)) || skip "Requires two selected CPUs"
    declare -A yamldump
    local budget
    for budget in 0 1; do
        # Zero is unlimited; the fixture consumes the single available data byte.
        sandstone_selftest -q -n2 --max-messages="$budget" --max-logdata=1 \
            -e selftest_crosscheck_votes_sequential \
            -O selftest_crosscheck_votes_sequential.cpu_case=10
        check_escaped_crosscheck_details 10
    done
}

@test "crosscheck deferred mismatch preserves arbitrary metadata with exhausted reporting budgets" {
    ((MAX_PROC >= 3)) || skip "Requires three selected CPUs"
    declare -A yamldump
    local budget
    for budget in 0 1; do
        sandstone_selftest -q -n3 --max-messages="$budget" --max-logdata=1 \
            -e selftest_crosscheck_votes_sequential \
            -O selftest_crosscheck_votes_sequential.cpu_case=11
        check_escaped_crosscheck_details 11
        test_yaml_absent /tests/0/fail/crosscheck-no-majority
    done
}

@test "crosscheck serialized internal thread-ratio fixture preserves attribution and reset" {
    ((MAX_PROC >= 2)) || skip "Requires two selected CPUs"
    declare -A yamldump
    local ratio workers attempt
    for ratio in 1 0.5 -1; do
        workers=1
        [[ "$ratio" != 1 ]] || workers=2
        sandstone_selftest -vvv -fno -n2 --thread-ratio="$ratio" --max-messages=100 \
            -e selftest_crosscheck_votes_sequential -e selftest_crosscheck_votes_sequential \
            -O selftest_crosscheck_votes_sequential.cpu_case=12
        [[ "$status" -eq 0 ]]
        test_yaml_numeric /tests@len 'value == 2'
        test_yaml_regexp /tests/0/result pass
        test_yaml_regexp /tests/1/result pass
        for attempt in 0 1; do
            test_crosscheck_message 0 "I> agreement captured $workers test thread snapshots across 2 CPUs" 1 "$attempt"
            test_crosscheck_message 0 "I> agreement input generation $((attempt + 1))" 1 "$attempt"
        done
        crosscheck_no_mismatch
        [[ "$output" != *"snapshots survived"* ]]
    done
}

@test "crosscheck internal placement fixtures require serialized workers" {
    declare -A yamldump
    vote_run 1 -O selftest_crosscheck_votes.cpu_case=3
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result skip
    test_yaml_expr /tests/0/skip-reason = 'CPU submission fixture requires sequential test threads'
    crosscheck_no_mismatch
    vote_no_deferred
}

@test "crosscheck reschedule preserves test thread snapshots with all modes" {
    ((MAX_PROC >= 2)) || skip "Need at least 2 logical processors to run this test"
    local mode thread message text cpu
    for mode in none queue random barrier; do
        declare -A yamldump
        vote_run 2 --no-slicing --reschedule="$mode" --timeout=10s \
            -O selftest_crosscheck_votes.cpu_case=15
        if [[ "$status" -eq 0 && "$output" = *"Cannot pin cross-check fixture"* ]]; then
            skip "Cannot pin cross-check fixture to the required CPUs"
        fi
        [[ "$status" -eq 0 ]]
        test_yaml_regexp /tests/0/result pass
        test_crosscheck_message 0 'I> reschedule retained 2 test thread snapshots and completion devices'
        [[ "$output" != *"one test thread submitted; no deferred comparison"* ]]
        crosscheck_no_mismatch
        for thread in 0 1; do
            cpu=
            for ((message=0; message<${yamldump[/tests/0/threads/$((thread + 1))/messages@len]:-0}; ++message)); do
                text=${yamldump[/tests/0/threads/$((thread + 1))/messages/$message/text]:-}
                if [[ "$text" = "I> reschedule test thread $thread finished on CPU "* ]]; then
                    cpu=${text##* }
                fi
            done
            [[ -n "$cpu" ]]
            test_crosscheck_message 0 "I> reschedule test thread $thread completion CPU $cpu"
        done
    done
}

@test "crosscheck outside-slice completion aborts even in release with OS errors ignored" {
    ((MAX_PROC >= 2)) || skip "Requires two available CPUs"
    declare -A yamldump
    vote_run 2 -O selftest_crosscheck_votes.shape=5
    [[ "$status" -eq 0 ]]
    local outside=${yamldump[/cpu-info/1/logical]}
    if $is_windows; then
        outside=$((outside + 64 * ${yamldump[/cpu-info/1/logical-group]}))
    fi
    cpu_run 1 8 --ignore-os-errors \
        -O "selftest_crosscheck_votes_sequential.outside_cpu=$outside"
    if [[ "$status" -eq 0 && "$output" = *"Cannot pin cross-check fixture"* ]]; then
        skip "Cannot pin to an available CPU outside the selected slice"
    fi
    [[ "$status" -eq 1 ]]
    test_yaml_regexp /tests/0/result crash
    test_crosscheck_message 1 'E> Cross-check invalid execution: completion or mismatch CPU is outside the selected slice'
    crosscheck_no_mismatch
    test_crosscheck_message 0 'I> vote cleanup retained snapshots' 0
}

@test "crosscheck retries and repeated no-fork executions capture fresh state" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    vote_run 3 -fno --no-slicing --retest-on-failure=1 -O selftest_crosscheck_votes.values=1 \
        --total-retest-on-failure=1 -O selftest_crosscheck_votes.retry=1
    check_passing_retry
    sandstone_selftest -vvv -fno -n3 --no-slicing -e selftest_crosscheck_output_retry \
        --retest-on-failure=1 --total-retest-on-failure=1
    check_passing_retry
    local attempt
    for attempt in 0 1; do
        test_crosscheck_message 0 "I> output init generation $((attempt + 1))" 1 "$attempt"
    done
    sandstone_selftest -vvv -fno -n3 --no-slicing \
        -e selftest_crosscheck_votes -e selftest_crosscheck_votes
    [[ "$status" -eq 0 ]]
    test_yaml_numeric /tests@len 'value == 2'
    test_yaml_regexp /tests/0/result pass
    test_yaml_regexp /tests/1/result pass
    [[ "$output" != *"snapshots survived"* ]]
}

@test "crosscheck containers wrappers and meaningful representation comparisons" {
    declare -A yamldump
    local suffix
    for suffix in containers_pass wrapper_pass nan_pass padding_pass; do
        sandstone_selftest -vvv -e "selftest_crosscheck_output_$suffix" --max-test-loop-count=2
        [[ "$status" -eq 0 ]]
        crosscheck_no_mismatch
    done
    for suffix in bad_later nan_fail zero_fail padding_fail; do
        sandstone_selftest -vvv -e "selftest_crosscheck_output_$suffix"
        if [[ "$suffix" = padding_fail && "$status" -eq 0 ]]; then
            test_yaml_regexp /tests/0/result skip
        else
            [[ "$status" -eq 1 ]]
            local path mismatches=0
            for path in "${!yamldump[@]}"; do
                if [[ "$path" = /tests/0/threads/*/messages/*/data-miscompare/description ]]; then
                    test_yaml_expr "$path" = 'Cross-check output mismatch'
                    ((++mismatches))
                fi
            done
            ((mismatches > 0))
        fi
    done
}

@test "crosscheck API misuse aborts and cannot be waived" {
    declare -A yamldump
    local suffix thread reason
    for suffix in invalid_pointer invalid_count worker_invalid_pointer worker_invalid_count \
                  init_snapshot_count wrapper_conflict later_count; do
        sandstone_selftest -vvv -n1 --ignore-os-errors -e "selftest_crosscheck_output_$suffix"
        [[ "$status" -eq 1 ]]
        test_yaml_regexp /tests/0/result crash
        thread=1
        case "$suffix" in
            invalid_pointer|invalid_count) thread=0 ;;
        esac
        case "$suffix" in
            invalid_pointer|worker_invalid_pointer) reason='null data pointer with nonzero count' ;;
            invalid_count|worker_invalid_count) reason='data extent overflows' ;;
            init_snapshot_count|later_count) reason='later output submission count mismatch' ;;
            wrapper_conflict) reason='output element type mismatch' ;;
        esac
        test_crosscheck_message "$thread" "E> Cross-check invalid execution: $reason"
        crosscheck_no_mismatch
    done
}

@test "crosscheck cleanup submission violates the debug phase invariant" {
    $is_debug || skip "Phase assertions require a debug build"
    declare -A yamldump
    sandstone_selftest -vvv -n1 --ignore-os-errors -e selftest_crosscheck_output_submit_cleanup
    [[ "$status" -eq 1 ]]
    test_yaml_regexp /tests/0/result crash
    crosscheck_no_mismatch
}

@test "crosscheck parent flags reject every API under debug isolation" {
    $is_debug || skip "Parent-isolation checks require a debug build"
    local test api
    for test in selftest_crosscheck_parent selftest_crosscheck_init_parent; do
        for api in 0 1 2; do
            # The actual parent aborts, so there is no completed child-result YAML.
            run $SANDSTONE --selftests -Y -o - -n1 --retest-on-failure=0 \
                --ignore-os-errors -e "$test" -O "$test.api=$api"
            [[ "$status" -ne 0 ]]
            [[ "$output" = *"cross-check APIs require process-local test execution"* ]]
            [[ "$output" != *"result: crash"* ]]
            [[ "$output" != *data-miscompare* ]]
        done
    done
}

@test "crosscheck parent flags permit valid no-fork use" {
    declare -A yamldump
    local test
    for test in selftest_crosscheck_parent selftest_crosscheck_init_parent; do
        sandstone_selftest -fno -n1 -e "$test"
        [[ "$status" -eq 0 ]]
        if [[ "$test" = selftest_crosscheck_init_parent ]]; then
            test_yaml_regexp /tests/0/result skip
        else
            test_yaml_regexp /tests/0/result pass
        fi
    done
}

@test "crosscheck seven test threads with a unique plurality have no strict majority" {
    declare -A yamldump
    local MAX_PROC=7
    require_cpus "$MAX_PROC"
    vote_run 7 --no-slicing -O selftest_crosscheck_votes.values=10560
    vote_failure 0 1 2 3 4 5 6
    local worker
    for ((worker=1; worker<=7; ++worker)); do
        test_yaml_regexp "/tests/0/threads/$worker/state" failed
        local crosscheck_mismatch
        find_crosscheck_mismatch "$worker" vote_a "$((worker - 1))"
        test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'no strict majority; conflicting peer'
    done
}

@test "crosscheck preexisting worker failures stop all deferred comparisons" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    local after log_failure
    for after in 0 1; do
        for log_failure in 0 1; do
            vote_run 3 -O selftest_crosscheck_votes.failures=1 \
                -O selftest_crosscheck_votes.values=16 -O "selftest_crosscheck_votes.after=$after" \
                -O "selftest_crosscheck_votes.log_failure=$log_failure"
            [[ "$status" -eq 1 ]]
            test_yaml_regexp /tests/0/threads/1/state failed
            test_yaml_absent /tests/0/threads/2/state
            test_yaml_absent /tests/0/threads/3/state
            crosscheck_no_mismatch
            test_crosscheck_message 0 'I> vote cleanup retained snapshots'
            test_yaml_absent /tests/0/fail/crosscheck-no-majority
            [[ "$output" != *"one test thread submitted; no deferred comparison"* ]]
        done
    done
}

@test "crosscheck init snapshot compares with another successful test thread" {
    ((MAX_PROC >= 2)) || skip "Requires two workers"
    declare -A yamldump
    vote_run 2 -O selftest_crosscheck_votes.skips=1 -O selftest_crosscheck_votes.init=0
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result pass
    vote_run 2 -O selftest_crosscheck_votes.skips=1 -O selftest_crosscheck_votes.init=1
    vote_failure 0 1
    test_yaml_expr /tests/0/fail/crosscheck-no-majority = True
    test_crosscheck_message 0 'I> vote worker 0 final state -2'
    test_yaml_regexp /tests/0/threads/2/state failed
    local crosscheck_mismatch
    find_crosscheck_mismatch 0 vote_a 0
    test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'no strict majority; conflicting peer'
    find_crosscheck_mismatch 2 vote_a 1
    test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'no strict majority; conflicting peer'
}

@test "crosscheck init output shares test thread zero's snapshot despite alternate host CPU placement" {
    ((MAX_PROC >= 2)) || skip "Requires two selected CPUs"
    declare -A yamldump
    vote_run 2 -O selftest_crosscheck_votes.init=1 -O selftest_crosscheck_votes.init_cpu=1 \
        -O selftest_crosscheck_votes.skips=2
    vote_failure 0
    local crosscheck_mismatch
    find_crosscheck_mismatch 1 vote_a 0
    test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'later submission vs first submission'
    test_yaml_expr "$crosscheck_mismatch/details/first_description" = 'CPU computation in init'
    check_crosscheck_device_description "$crosscheck_mismatch/details/reference_device_description" 0
    local init_cpu=${yamldump[/cpu-info/1/logical]}
    if $is_windows; then
        init_cpu=$((init_cpu + 64 * ${yamldump[/cpu-info/1/logical-group]}))
    fi
    test_yaml_numeric "$crosscheck_mismatch/details/reference_host_cpu" "value == $init_cpu"
    test_crosscheck_message 0 "I> vote init submission CPU $init_cpu"
    test_crosscheck_message 0 'I> vote worker 1 final state -2'
    test_yaml_regexp /tests/0/threads/1/state failed
    test_yaml_absent /tests/0/threads/2/state
    vote_no_deferred
}

@test "crosscheck globally skipped independent output stays skip but cannot hide a local mismatch" {
    declare -A yamldump
    sandstone_selftest -vvv -n1 -e selftest_crosscheck_output_bad_first_skip_flag
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result skip
    test_crosscheck_message 1 'original output skip flag after independent submission'
    test_crosscheck_message 0 'I> output test cleanup retained storage'
    crosscheck_no_mismatch
    sandstone_selftest -vvv -n1 -e selftest_crosscheck_output_mixed_bad_first_skip_flag
    [[ "$status" -eq 1 ]]
    test_yaml_regexp /tests/0/result fail
    vote_expect_mask 0
    local crosscheck_mismatch
    find_crosscheck_mismatch 1 output_words 0
    test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'later submission vs first submission'
    test_crosscheck_message 1 'original output skip flag after wrong first submission' 0
    test_crosscheck_message 0 'I> output test cleanup retained storage'
    vote_no_deferred
}

@test "crosscheck additional worker names and zero-length outputs are valid" {
    declare -A yamldump
    sandstone_selftest -vvv -n1 -e selftest_crosscheck_output_additional_worker_output
    [[ "$status" -eq 0 ]]
    crosscheck_no_mismatch
    ((MAX_PROC >= 2)) || return 0
    sandstone_selftest -vvv -n2 -e selftest_crosscheck_output_consensus_zero_length
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result pass
}

@test "crosscheck captures are verified independently in each execution slice" {
    ((MAX_PROC >= 4)) || skip "Requires four workers"
    declare -A yamldump
    sandstone_selftest -vvv -n4 --max-cores-per-slice=1 --disable='*'
    [[ "$status" -eq 0 ]]
    ((${yamldump[/test-plans/heuristic@len]} >= 2)) || skip "Requires at least two execution slices"
    sandstone_selftest -vvv -n4 --max-cores-per-slice=1 \
        -e selftest_crosscheck_output_consensus_only_slice
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result pass
    crosscheck_no_mismatch
}

@test "crosscheck init outputs share local test thread zero's snapshot in nonfirst execution slices" {
    ((MAX_PROC >= 4)) || skip "Requires four workers"
    declare -A yamldump
    sandstone_selftest -vvv -n4 --max-cores-per-slice=1 --disable='*'
    [[ "$status" -eq 0 ]]
    ((${yamldump[/test-plans/heuristic@len]} >= 2)) || skip "Requires at least two execution slices"
    sandstone_selftest -vvv -n4 --max-cores-per-slice=1 \
        -e selftest_crosscheck_votes -O selftest_crosscheck_votes.init=0
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result pass
    crosscheck_no_mismatch
    local thread message text prefix='I> vote worker 0 submission CPU '
    local -A first_devices=()
    for ((thread=0; thread<${yamldump[/tests/0/threads@len]}; ++thread)); do
        for ((message=0; message<${yamldump[/tests/0/threads/$thread/messages@len]:-0}; ++message)); do
            text=${yamldump[/tests/0/threads/$thread/messages/$message/text]:-}
            if [[ "$text" = "$prefix"* ]]; then
                first_devices[${text#"$prefix"}]=1
            fi
        done
    done
    ((${#first_devices[@]} >= 2))
}

@test "crosscheck diagnostics count submitted test thread snapshots after skips and optional names" {
    ((MAX_PROC >= 2)) || skip "Requires two workers"
    declare -A yamldump
    local after
    for after in 0 1; do
        vote_run 2 -O selftest_crosscheck_votes.skips=1 -O "selftest_crosscheck_votes.after=$after"
        [[ "$status" -eq 0 ]]
        test_yaml_regexp /tests/0/result pass
        local singleton=1
        [[ "$after" = 0 ]] || singleton=0
        test_crosscheck_message 0 "I> Cross-check output 'vote_a': one test thread submitted; no deferred comparison" "$singleton"
    done
    vote_run 2 -O selftest_crosscheck_votes.shape=4
    [[ "$status" -eq 0 ]]
    test_crosscheck_message 0 "I> Cross-check output 'worker_0': one test thread submitted; no deferred comparison"
    test_crosscheck_message 0 "I> Cross-check output 'worker_1': one test thread submitted; no deferred comparison"
    local suffix
    for suffix in consensus_empty consensus_input_only; do
        sandstone_selftest -vvv -n1 -e "selftest_crosscheck_output_$suffix"
        [[ "$status" -eq 0 ]]
        crosscheck_no_mismatch
        [[ "$output" != *"one test thread submitted; no deferred comparison"* ]]
    done
}

@test "crosscheck no-majority summary survives isolation quiet output and message limits" {
    ((MAX_PROC >= 2)) || skip "Requires two workers"
    declare -A yamldump
    local budget
    for budget in 0 1; do
        sandstone_selftest -q -n2 --no-slicing --max-messages="$budget" \
            -e selftest_crosscheck_votes -O selftest_crosscheck_votes.values=4
        [[ "$status" -eq 1 ]]
        test_yaml_regexp /tests/0/result fail
        test_yaml_expr /tests/0/fail/crosscheck-no-majority = True
        vote_expect_mask 0 1
        # The harness captures the full log, which retains verbose analysis even with -q.
        [[ "$output" = *"Topology analysis shows observed implicated-device patterns"* ]]
    done
}

@test "crosscheck mixed names retain majority evidence and qualify no-majority attribution" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    vote_run 3 -O selftest_crosscheck_votes.values=36 -O selftest_crosscheck_votes.two_names=1 \
        -O selftest_crosscheck_votes.cleanup_failure=1
    vote_failure 0 1 2
    test_yaml_expr /tests/0/fail/crosscheck-no-majority = True
    local crosscheck_mismatch
    find_crosscheck_mismatch 1 vote_a 0
    test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'no strict majority; conflicting peer'
    find_crosscheck_mismatch 2 vote_z 1
    test_yaml_expr "$crosscheck_mismatch/details/comparison_description" = 'strict majority baseline (not proven correct)'
    test_crosscheck_message 0 'E> original vote cleanup error'
    [[ "$output" = *"Topology analysis shows observed implicated-device patterns"* ]]
    [[ "$output" = *"# Topology analysis:"* ]]
}

@test "crosscheck quiet stdout retains no-majority summary but leaves topology qualification in the full log" {
    ((MAX_PROC >= 2)) || skip "Requires two workers"
    local logfile=$(mktempfile crosscheck-quiet-XXXXXX.yaml)
    run $SANDSTONE --selftests -Y -q -o "$logfile" -n2 --no-slicing \
        --retest-on-failure=0 --max-messages=1 --disable @postexec \
        -e selftest_crosscheck_votes -O selftest_crosscheck_votes.values=4
    local full_log=$(<"$logfile")
    rm -f -- "$logfile"
    [[ "$status" -eq 1 ]]
    [[ "$output" = *"result: fail"* ]]
    [[ "$output" = *"crosscheck-no-majority: true"* ]]
    [[ "$output" != *"Topology analysis shows observed implicated-device patterns"* ]]
    [[ "$full_log" = *"Topology analysis shows observed implicated-device patterns"* ]]
}

@test "crosscheck no-majority flag resets on retries but still qualifies accumulated topology" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    vote_run 3 --no-slicing --retest-on-failure=1 --total-retest-on-failure=1 \
        -O selftest_crosscheck_votes.values=36 -O selftest_crosscheck_votes.retry=1 \
        -O selftest_crosscheck_votes.two_names=1
    [[ "$status" -eq 1 ]]
    test_yaml_numeric /tests@len 'value == 2'
    test_yaml_regexp /tests/0/result fail
    test_yaml_regexp /tests/1/result fail
    test_yaml_expr /tests/1/state/retry = True
    test_yaml_expr /tests/0/fail/crosscheck-no-majority = True
    test_yaml_absent /tests/1/fail/crosscheck-no-majority
    [[ "$output" = *"Topology analysis shows observed implicated-device patterns"* ]]
    sandstone_selftest -vvv -fno -n3 --no-slicing -e selftest_crosscheck_votes \
        -e selftest_crosscheck_votes_sequential -O selftest_crosscheck_votes.values=36 \
        -O selftest_crosscheck_votes_sequential.values=1
    [[ "$status" -eq 1 ]]
    test_yaml_numeric /tests@len 'value == 2'
    test_yaml_expr /tests/0/fail/crosscheck-no-majority = True
    test_yaml_regexp /tests/1/result fail
    test_yaml_absent /tests/1/fail/crosscheck-no-majority
}

@test "crosscheck no-majority summary aggregates a nonfirst slice and resets unused slices" {
    ((MAX_PROC >= 4)) || skip "Requires four workers"
    declare -A yamldump
    vote_run 4 --no-slicing -O selftest_crosscheck_votes.shape=5
    [[ "$status" -eq 0 ]]
    local first=${yamldump[/cpu-info/0/package]}:${yamldump[/cpu-info/0/core]} device key
    local -A counts=()
    for device in 0 1 2 3; do
        key=${yamldump[/cpu-info/$device/package]}:${yamldump[/cpu-info/$device/core]}
        counts[$key]=$(( ${counts[$key]:-0} + 1 ))
    done
    local eligible=false
    for key in "${!counts[@]}"; do
        if [[ "$key" != "$first" ]] && ((${counts[$key]} >= 2)); then
            eligible=true
        fi
    done
    $eligible || skip "Requires a nonfirst core with at least two selected CPUs"
    sandstone_selftest -vvv -n4 --max-cores-per-slice=1 \
        -e selftest_crosscheck_votes -e selftest_crosscheck_votes_sequential \
        -O selftest_crosscheck_votes.values=4 -O selftest_crosscheck_votes.nonfirst_slice=1 \
        -O selftest_crosscheck_votes_sequential.values=1
    [[ "$status" -eq 1 ]]
    test_yaml_numeric /tests@len 'value == 2'
    test_yaml_regexp /tests/0/result fail
    test_yaml_expr /tests/0/fail/crosscheck-no-majority = True
    test_yaml_regexp /tests/1/result fail
    test_yaml_absent /tests/1/fail/crosscheck-no-majority
    [[ "$output" = *"Topology analysis shows observed implicated-device patterns"* ]]
    local qualifier='Cross-check had no strict majority:'
    local remainder=${output#*"$qualifier"}
    [[ "$remainder" != *"$qualifier"* ]]
}

@test "crosscheck text formats qualify no-majority failure masks independently of message budgets" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    local format
    for format in tap key-value; do
        run $SANDSTONE --selftests --output-format="$format" -o - -q -n3 --no-slicing \
            --retest-on-failure=0 --max-messages=1 -e selftest_crosscheck_votes \
            -O selftest_crosscheck_votes.values=36
        [[ "$status" -eq 1 ]]
        [[ "$output" = *"Cross-check no strict majority: conflicting devices are suspects; failure mask includes inconclusive attribution."* ]]
        run $SANDSTONE --selftests --output-format="$format" -o - -q -n3 --no-slicing \
            --retest-on-failure=0 --max-messages=1 -e selftest_crosscheck_votes \
            -O selftest_crosscheck_votes.values=1
        [[ "$status" -eq 1 ]]
        [[ "$output" != *"failure mask includes inconclusive attribution"* ]]
    done
}
