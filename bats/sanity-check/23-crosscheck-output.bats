#!/usr/bin/bats
# Copyright 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
load ../testenv
load helpers

vote_run() {
    local workers=$1
    shift
    sandstone_selftest -vvv --max-messages=100 -n"$workers" -e selftest_crosscheck_votes "$@"
}

vote_failure() {
    [[ "$status" -eq 1 ]]
    test_yaml_regexp /tests/0/result fail
    test_yaml_regexp /exit fail
    test_yaml_regexp /tests/0/fail/cpu-mask '[._:X1-9a-f]*[X1-9a-f][._:X1-9a-f]*'
    [[ "$output" = *data-miscompare* ]]
    [[ "$output" = *"vote cleanup retained snapshots"* ]]
    [[ "$output" != *"operating system error"* ]]
}

@test "crosscheck golden and consensus agreement need no mode declaration" {
    declare -A yamldump
    vote_run 1 -O selftest_crosscheck_votes.init=0
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result pass
    ((MAX_PROC >= 2)) || return 0
    vote_run 2
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result pass
}

@test "crosscheck a wrong golden implicates init but not agreeing workers" {
    ((MAX_PROC >= 2)) || skip "Requires two workers"
    declare -A yamldump
    local mode
    for mode in no yes exec; do
        $is_windows && [[ "$mode" = yes ]] && continue
        vote_run 2 -f"$mode" -O selftest_crosscheck_votes.init=1
        vote_failure
        [[ "$output" = *"golden computation in init"* ]]
        test_yaml_absent /tests/0/threads/1/state
        test_yaml_absent /tests/0/threads/2/state
        [[ "$output" = *"first submission vs strict majority"* ]]
        [[ "$output" != *"output failure callback fired"* ]]
    done
}

@test "crosscheck worker zero can be the majority outlier" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    vote_run 3 -O selftest_crosscheck_votes.values=1
    vote_failure
    test_yaml_regexp /tests/0/threads/1/state failed
    test_yaml_absent /tests/0/threads/2/state
    test_yaml_absent /tests/0/threads/3/state
    [[ "$output" = *"output failure callback fired"* ]]
}

@test "crosscheck golden repetition does not multiply its vote" {
    ((MAX_PROC >= 2)) || skip "Requires two workers"
    declare -A yamldump
    vote_run 2 -O selftest_crosscheck_votes.init=0 -O selftest_crosscheck_votes.values=5
    vote_failure
    [[ "$output" = *"golden computation in init"* ]]
    test_yaml_absent /tests/0/threads/1/state
    test_yaml_absent /tests/0/threads/2/state
}

@test "crosscheck golden versus one worker disagreement implicates both producers" {
    declare -A yamldump
    vote_run 1 -O selftest_crosscheck_votes.init=1
    vote_failure
    [[ "$output" = *"golden computation in init"* ]]
    test_yaml_regexp /tests/0/threads/1/state failed
    [[ "$output" = *"no strict majority"* ]]
}

@test "crosscheck ties and distinct values implicate every conflicting worker" {
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
        for ((worker=1; worker<=workers; ++worker)); do
            test_yaml_regexp "/tests/0/threads/$worker/state" failed
        done
        [[ "$output" = *"no strict majority"* ]]
    done
}

@test "crosscheck exclusion of skipped workers is independent of their submissions" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    local after
    for after in 0 1; do
        vote_run 3 -O selftest_crosscheck_votes.skips=1 \
            -O selftest_crosscheck_votes.values=1 -O "selftest_crosscheck_votes.after=$after"
        [[ "$status" -eq 0 ]]
        test_yaml_regexp /tests/0/result pass
        [[ "$output" = *"vote worker 0 final state -2"* ]]
        [[ "$output" = *"original vote worker skip"* ]]
        [[ "$output" != *data-miscompare* ]]
    done
}

@test "crosscheck losing worker zero does not suppress remaining disagreement" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    vote_run 3 -O selftest_crosscheck_votes.skips=1 -O selftest_crosscheck_votes.values=16
    vote_failure
    [[ "$output" = *"vote worker 0 final state -2"* ]]
    test_yaml_regexp /tests/0/threads/2/state failed
    test_yaml_regexp /tests/0/threads/3/state failed
}

@test "crosscheck insufficient coverage and all worker skips still clean up" {
    declare -A yamldump
    vote_run 1
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result skip
    [[ "$output" = *"at least two successful participants"* ]]
    [[ "$output" = *"vote cleanup retained snapshots"* ]]
    vote_run 1 -O selftest_crosscheck_votes.init=0 -O selftest_crosscheck_votes.skips=1
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result skip
    [[ "$output" = *"vote cleanup retained snapshots"* ]]
    [[ "$output" != *data-miscompare* ]]
}

@test "crosscheck per-name eligibility does not change after an earlier mismatch" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    vote_run 3 -O selftest_crosscheck_votes.values=1 -O selftest_crosscheck_votes.two_names=1
    vote_failure
    test_yaml_regexp /tests/0/threads/1/state failed
    test_yaml_regexp /tests/0/threads/2/state failed
    test_yaml_absent /tests/0/threads/3/state
    [[ "$output" = *vote_a* && "$output" = *vote_z* ]]
}

@test "crosscheck missing outputs and type or count errors do not blame CPUs" {
    ((MAX_PROC >= 2)) || skip "Requires two workers"
    declare -A yamldump
    local shape
    for shape in 1 2 3; do
        vote_run 2 -O "selftest_crosscheck_votes.shape=$shape"
        [[ "$status" -eq 2 ]]
        test_yaml_regexp /tests/0/result 'operating system error'
        [[ "$output" != *data-miscompare* ]]
        [[ "$output" != *"output failure callback fired"* ]]
        [[ "$output" = *"vote cleanup retained snapshots"* ]]
    done
}

@test "crosscheck data failure survives structural errors cleanup skip and OS-error waiver" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    vote_run 3 --ignore-os-errors -O selftest_crosscheck_votes.shape=1 \
        -O selftest_crosscheck_votes.two_names=1 -O selftest_crosscheck_votes.cleanup_skip=1
    vote_failure
    [[ "$output" = *vote_z* ]]
}

@test "crosscheck later submission mismatch fails without a second voter" {
    declare -A yamldump
    vote_run 1 -O selftest_crosscheck_votes.later=0
    vote_failure
    [[ "$output" = *"later submission vs first submission"* ]]
}

@test "crosscheck init mismatch and init skip do not start workers" {
    declare -A yamldump
    vote_run 1 -O selftest_crosscheck_votes.init=0 -O selftest_crosscheck_votes.later=-2
    [[ "$status" -eq 1 ]]
    [[ "$output" = *data-miscompare* ]]
    [[ "$output" != *"vote cleanup retained snapshots"* ]]
    vote_run 1 -O selftest_crosscheck_votes.init=0 -O selftest_crosscheck_votes.init_skip=1
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result skip
    [[ "$output" != *"vote cleanup retained snapshots"* ]]
}

@test "crosscheck sequential rescheduling uses submission CPU provenance" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    sandstone_selftest -vvv --max-messages=100 -n3 -e selftest_crosscheck_votes_sequential \
        -O selftest_crosscheck_votes_sequential.values=1 \
        -O selftest_crosscheck_votes_sequential.reschedule=1
    vote_failure
    test_yaml_regexp /tests/0/threads/1/state failed
    local cpu=${yamldump[/tests/0/threads/1/id/logical]}
    [[ "$output" = *"vote worker 0 submission CPU $cpu"* ]]
}

@test "crosscheck retries and repeated no-fork executions capture fresh state" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    vote_run 3 -fno --retest-on-failure=1 -O selftest_crosscheck_votes.values=1 \
        -O selftest_crosscheck_votes.retry=1
    [[ "$status" -eq 1 ]]
    [[ "$output" != *"snapshots survived"* ]]
    sandstone_selftest -vvv -fno -n3 -e selftest_crosscheck_votes -e selftest_crosscheck_votes
    [[ "$status" -eq 0 ]]
    [[ "$output" != *"snapshots survived"* ]]
}

@test "crosscheck C C++ containers wrappers and meaningful representation comparisons" {
    declare -A yamldump
    local suffix
    for suffix in containers_pass c_pass c_golden_pass wrapper_pass nan_pass padding_pass fracture_pass; do
        sandstone_selftest -vvv -e "selftest_crosscheck_output_$suffix" --max-test-loop-count=2
        [[ "$status" -eq 0 ]]
        [[ "$output" != *data-miscompare* ]]
    done
    for suffix in c_bad_later bad_later nan_fail zero_fail padding_fail; do
        sandstone_selftest -vvv -e "selftest_crosscheck_output_$suffix"
        if [[ "$suffix" = padding_fail && "$status" -eq 0 ]]; then
            test_yaml_regexp /tests/0/result skip
        else
            [[ "$status" -eq 1 ]]
            [[ "$output" = *data-miscompare* ]]
        fi
    done
}

@test "crosscheck API misuse remains invalid" {
    declare -A yamldump
    local suffix
    for suffix in invalid_pointer invalid_count worker_invalid_pointer worker_invalid_count \
                  later_count c_later_count submit_cleanup; do
        sandstone_selftest -vvv -e "selftest_crosscheck_output_$suffix"
        [[ "$status" -eq 2 ]]
        [[ "$output" = *"Cross-check invalid execution"* ]]
        [[ "$output" != *data-miscompare* ]]
    done
}

@test "crosscheck a plurality with golden participation is not a strict majority" {
    ((MAX_PROC >= 4)) || skip "Requires four workers"
    declare -A yamldump
    vote_run 4 -O selftest_crosscheck_votes.init=2 -O selftest_crosscheck_votes.values=80
    vote_failure
    local worker
    for ((worker=1; worker<=4; ++worker)); do
        test_yaml_regexp "/tests/0/threads/$worker/state" failed
    done
    [[ "$output" = *"no strict majority"* ]]
    [[ "$output" = *"init on logical processor"* ]]
}

@test "crosscheck failed participants do not supply votes before or after submission" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    local after
    for after in 0 1; do
        vote_run 3 -O selftest_crosscheck_votes.failures=1 \
            -O selftest_crosscheck_votes.values=1 -O "selftest_crosscheck_votes.after=$after"
        [[ "$status" -eq 1 ]]
        test_yaml_regexp /tests/0/threads/1/state failed
        test_yaml_absent /tests/0/threads/2/state
        test_yaml_absent /tests/0/threads/3/state
        [[ "$output" != *data-miscompare* ]]
        [[ "$output" = *"vote cleanup retained snapshots"* ]]
    done
}

@test "crosscheck golden can compare with the single remaining successful worker" {
    ((MAX_PROC >= 2)) || skip "Requires two workers"
    declare -A yamldump
    vote_run 2 -O selftest_crosscheck_votes.skips=1 -O selftest_crosscheck_votes.init=0
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result pass
    vote_run 2 -O selftest_crosscheck_votes.skips=1 -O selftest_crosscheck_votes.init=1
    vote_failure
    [[ "$output" = *"vote worker 0 final state -2"* ]]
    test_yaml_regexp /tests/0/threads/2/state failed
}

@test "crosscheck empty outputs input-only captures and additional worker names are valid" {
    declare -A yamldump
    local suffix
    for suffix in consensus_empty consensus_input_only missing_golden duplicate; do
        sandstone_selftest -vvv -n1 -e "selftest_crosscheck_output_$suffix"
        [[ "$status" -eq 0 ]]
        [[ "$output" != *data-miscompare* ]]
    done
    ((MAX_PROC >= 2)) || return 0
    sandstone_selftest -vvv -n2 -e selftest_crosscheck_output_consensus_zero_length
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result pass
}

@test "crosscheck captures are verified independently in each execution slice" {
    ((MAX_PROC >= 4)) || skip "Requires four workers"
    declare -A yamldump
    sandstone_selftest -vvv -n4 --max-cores-per-slice=1 \
        -e selftest_crosscheck_output_consensus_only_slice
    [[ "$status" -eq 0 ]]
    test_yaml_regexp /tests/0/result pass
    [[ "$output" != *data-miscompare* ]]
}
