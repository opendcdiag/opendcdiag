#!/usr/bin/bats
# Copyright 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
load ../testenv
load helpers

@test "selftest_crosscheck_output C C++ wrapper and representation passes" {
    declare -A yamldump
    local suffix
    for suffix in containers_pass c_pass c_golden_pass wrapper_pass \
            nan_pass padding_pass missing_golden; do
        sandstone_selftest -vvv -e "selftest_crosscheck_output_$suffix"
        [[ "$status" -eq 0 ]]
        test_yaml_regexp "/exit" pass
        if [[ "$suffix" = padding_pass && "${yamldump[/tests/0/result]}" = skip ]]; then
            test_yaml_regexp "/tests/0/skip-reason" 'Requires trailing long double padding'
        else
            test_yaml_regexp "/tests/0/result" pass
            [[ "$output" = *"output test cleanup retained storage"* ]]
            [[ "$output" = *"output callback cleanup released storage"* ]]
            [[ "$output" != *"output failure callback fired"* ]]
        fi
    done
}

crosscheck_output_mismatch() {
    local suffix=$1 boundary=$2 actual_bits=$3 expected_bits=$4
    sandstone_selftest -vvv -e "selftest_crosscheck_output_$suffix"
    [[ "$status" -eq 1 ]]
    crosscheck_output_verify_mismatch "$boundary" "$actual_bits" "$expected_bits"
    [[ "$output" != *"ignored worker words"* ]]
    [[ "$output" = *"output failure callback fired"* ]]
    [[ "$output" = *"output test cleanup retained storage"* ]]
    [[ "$output" = *"output callback cleanup released storage"* ]]
}

crosscheck_output_verify_mismatch() {
    local boundary=$1 actual_bits=$2 expected_bits=$3
    test_yaml_regexp "/tests/0/result" fail
    local i j found path
    for ((i = 1; i <= MAX_PROC; ++i)); do
        found=0
        for ((j = 0; j < ${yamldump[/tests/0/threads/$i/messages@len]}; ++j)); do
            path="/tests/0/threads/$i/messages/$j/data-miscompare"
            [[ -n "${yamldump[$path/description]}" ]] || continue
            found=1
            test_yaml_regexp "$path/description" \
                "Cross-check output 'output_words' \(authoritative golden words\), $boundary"
            test_yaml_regexp "$path/actual" "0x0*$actual_bits( .*)?"
            test_yaml_regexp "$path/expected" "0x0*$expected_bits( .*)?"
        done
        ((found))
    done
}

@test "selftest_crosscheck_output wrong identical first results fail only after workers finish" {
    declare -A yamldump
    local suffix
    for suffix in bad_first c_bad_first; do
        crosscheck_output_mismatch "$suffix" 'first submission vs golden output' 7 6
        [[ "$output" = *"output post-capture sentinel"* ]]
    done
}

@test "selftest_crosscheck_output sequential golden failures verify every finalized worker once" {
    ((MAX_PROC > 1)) || skip "Requires multiple workers"
    declare -A yamldump
    sandstone_selftest -vvv --max-messages=20 --reschedule=queue \
        -e selftest_crosscheck_output_sequential_bad_first
    [[ "$status" -eq 1 ]]
    crosscheck_output_verify_mismatch 'first submission vs golden output' 7 6
    local i j text cpu callbacks mismatches sentinels
    for ((i = 1; i <= MAX_PROC; ++i)); do
        callbacks=0 mismatches=0 sentinels=0 cpu=-1
        test_yaml_regexp "/tests/0/threads/$i/state" failed
        for ((j = 0; j < ${yamldump[/tests/0/threads/$i/messages@len]}; ++j)); do
            text=${yamldump[/tests/0/threads/$i/messages/$j/text]}
            if [[ "$text" =~ output\ completion\ CPU\ ([0-9]+) ]]; then
                cpu=${BASH_REMATCH[1]}
            fi
            [[ "$text" != *"output failure callback fired"* ]] || ((++callbacks))
            [[ "$text" != *"output post-capture sentinel"* ]] || ((++sentinels))
            [[ -z "${yamldump[/tests/0/threads/$i/messages/$j/data-miscompare/description]}" ]] || ((++mismatches))
        done
        ((callbacks == 1 && mismatches == 1 && sentinels == 1 && cpu >= 0))
        if ! $is_windows; then
            test_yaml_numeric "/tests/0/threads/$i/id/logical" "value == $cpu"
        fi
    done
    [[ "$output" = *"output test cleanup retained storage"* ]]
    [[ "$output" = *"output callback cleanup released storage"* ]]
}

@test "selftest_crosscheck_output later mismatch fails immediately with correct orientation" {
    declare -A yamldump
    local suffix
    for suffix in bad_later c_bad_later; do
        crosscheck_output_mismatch "$suffix" 'later submission vs first submission' 6 5
        [[ "$output" != *"output post-capture sentinel"* ]]
    done
}

@test "selftest_crosscheck_output counts fail at both boundaries" {
    declare -A yamldump
    local suffix boundary
    for suffix in golden_count later_count c_golden_count c_later_count; do
        boundary='first submission vs golden output'
        [[ "$suffix" != *later_count ]] || boundary='later submission vs first submission'
        sandstone_selftest -vvv -e "selftest_crosscheck_output_$suffix"
        [[ "$status" -eq 1 ]]
        test_yaml_regexp "/tests/0/result" fail
        local i j found path
        for ((i = 1; i <= MAX_PROC; ++i)); do
            found=0
            for ((j = 0; j < ${yamldump[/tests/0/threads/$i/messages@len]}; ++j)); do
                path="/tests/0/threads/$i/messages/$j"
                [[ "${yamldump[$path/text]}" = *"count mismatch"* ]] || continue
                found=1
                local description="Cross-check output 'output_words' \(authoritative golden words\)"
                test_yaml_regexp "$path/text" \
                    ".*$description, $boundary: count mismatch: actual 1 vs expected 2"
            done
            ((found))
        done
        [[ "$output" != *"data-miscompare"* ]]
        if [[ "$suffix" = *later_count ]]; then
            [[ "$output" != *"output post-capture sentinel"* ]]
        else
            [[ "$output" = *"output post-capture sentinel"* ]]
        fi
    done
}

@test "selftest_crosscheck_output NaN signed zero and multi-element meaningful bytes fail" {
    declare -A yamldump
    local suffix
    for suffix in nan_fail zero_fail padding_fail; do
        sandstone_selftest -vvv -e "selftest_crosscheck_output_$suffix"
        if [[ "$suffix" = padding_fail && "${yamldump[/tests/0/result]}" = skip ]]; then
            [[ "$status" -eq 0 ]]
            test_yaml_regexp "/tests/0/skip-reason" 'Requires trailing long double padding'
            continue
        fi
        [[ "$status" -eq 1 ]]
        test_yaml_regexp "/tests/0/result" fail
        [[ "$output" = *"later submission vs first submission"* ]]
        [[ "$output" != *"output post-capture sentinel"* ]]
        local i j path found expected_offset
        if [[ "$suffix" = padding_fail ]]; then
            [[ "$output" =~ "output padded mismatch byte offset "([0-9]+) ]]
            expected_offset=${BASH_REMATCH[1]}
        fi
        for ((i = 1; i <= MAX_PROC; ++i)); do
            found=0
            for ((j = 0; j < ${yamldump[/tests/0/threads/$i/messages@len]}; ++j)); do
                path="/tests/0/threads/$i/messages/$j/data-miscompare"
                [[ -n "${yamldump[$path/description]}" ]] || continue
                found=1
                [[ "${yamldump[$path/actual]}" != "${yamldump[$path/expected]}" ]]
                if [[ "$suffix" = padding_fail ]]; then
                    test_yaml_regexp "$path/description" ".*output_long_double.*golden padded array.*"
                    test_yaml_numeric "$path/offset/0" "value == $expected_offset"
                    test_yaml_numeric "$path/offset/1" 'value == 0'
                else
                    test_yaml_regexp "$path/description" ".*output_float.*golden floating bits.*"
                    if [[ "$suffix" = nan_fail ]]; then
                        test_yaml_regexp "$path/actual" '0x7fc12344 \(nan\)'
                        test_yaml_regexp "$path/expected" '0x7fc12345 \(nan\)'
                    else
                        test_yaml_regexp "$path/actual" '0x80000000.*'
                        test_yaml_regexp "$path/expected" '0x00000000.*'
                    fi
                fi
            done
            ((found))
        done
    done
}

@test "selftest_crosscheck_output asserts on invalid output capture" {
    if ! $is_debug; then
        skip "Cross-check output programmer misuse requires debug assertions"
    fi
    local suffix
    for suffix in duplicate capture_cleanup invalid_pointer invalid_count \
            worker_invalid_pointer worker_invalid_count; do
        selftest_crash_common "selftest_crosscheck_output_$suffix" SIGABRT \
            '0xC0000602 || value == 0xC0000409' \
            "Aborted|Program self-triggered abnormal termination"
    done
}

@test "selftest_crosscheck_output reports missing worker submissions and element type mismatches" {
    declare -A yamldump
    local suffix
    for suffix in missing_all missing_partial c_conflict wrapper_conflict; do
        sandstone_selftest -vvv -e "selftest_crosscheck_output_$suffix"
        [[ "$status" -eq 1 ]]
        test_yaml_regexp "/tests/0/result" fail
        [[ "$output" = *"worker did not submit"* || "$output" = *"worker never submitted"* \
            || "$output" = *"element type mismatch"* ]]
        [[ "$output" != *"data-miscompare"* ]]
        local i j callbacks text
        for ((i = 1; i <= MAX_PROC; ++i)); do
            callbacks=0
            test_yaml_regexp "/tests/0/threads/$i/state" failed
            for ((j = 0; j < ${yamldump[/tests/0/threads/$i/messages@len]}; ++j)); do
                text=${yamldump[/tests/0/threads/$i/messages/$j/text]}
                [[ "$text" != *"output failure callback fired"* ]] || ((++callbacks))
            done
            ((callbacks == 1))
        done
    done
}

@test "selftest_crosscheck_output consensus unanimous sequential and pass resets" {
    declare -A yamldump
    sandstone_selftest -fno -vvv -e selftest_crosscheck_output_consensus_pass \
        -e selftest_crosscheck_output_consensus_sequential -e selftest_crosscheck_output_containers_pass \
        -e selftest_crosscheck_output_consensus_pass
    [[ "$status" -eq 0 ]]
    local i
    for i in 0 1 2 3; do
        test_yaml_regexp "/tests/$i/result" pass
    done
    [[ "$output" != *"survived"* ]]
    [[ "$output" != *"output failure callback fired"* ]]
}

@test "selftest_crosscheck_output consensus-only passes with one and multiple workers" {
    declare -A yamldump
    local workers
    for workers in 1 "$MAX_PROC"; do
        sandstone_selftest -vvv -n"$workers" -e selftest_crosscheck_output_consensus_only_pass
        [[ "$status" -eq 0 ]]
        test_yaml_regexp "/tests/0/result" pass
        test_yaml_numeric "/tests/0/threads@len" "value == $((workers + 1))"
        [[ "$output" != *"output failure callback fired"* ]]
        [[ "$output" = *"output callback cleanup released storage"* ]]
    done
    ((MAX_PROC > 1)) || return 0
    sandstone_selftest -vvv -e selftest_crosscheck_output_consensus_only_single
    [[ "$status" -eq 1 ]]
    test_yaml_regexp "/tests/0/result" fail
    [[ "$output" = *"first submission vs worker 0's first submission"* ]]
    [[ "$output" != *"first submission vs golden output"* ]]
}

@test "selftest_crosscheck_output consensus-only reference exits never select a fallback" {
    ((MAX_PROC > 1)) || skip "Requires multiple workers"
    declare -A yamldump
    local suffix
    for suffix in skip error noreturn; do
        sandstone_selftest -vvv -e "selftest_crosscheck_output_consensus_only_reference_$suffix"
        if [[ "$suffix" = skip ]]; then
            [[ "$status" -eq 0 ]]
            test_yaml_regexp "/tests/0/result" skip
            [[ "$output" = *"Cross-check consensus incomplete"* ]]
            [[ "$output" != *"output failure callback fired"* ]]
        else
            [[ "$status" -eq 1 ]]
            test_yaml_regexp "/tests/0/result" fail
            test_yaml_regexp "/tests/0/threads/1/state" failed
            [[ "$output" = *"original consensus worker"* ]]
            [[ "$output" = *"output failure callback fired"* ]]
        fi
        [[ "$output" != *"first submission vs worker 0"* ]]
        [[ "$output" != *"data-miscompare"* ]]
        [[ "$output" = *"output callback cleanup released storage"* ]]
    done
}

@test "selftest_crosscheck_output consensus reference is local to each execution slice" {
    [[ "$SANDSTONE_DEVICE_TYPE" = CPU ]] || skip "Requires CPU slicing"
    $is_debug || skip "Requires Debug topology mocking"
    ((MAX_PROC >= 4)) || skip "Requires four workers"
    export SANDSTONE_MOCK_TOPOLOGY='c0 c1 c2 c3'
    declare -A yamldump references
    sandstone_selftest -vvv -n4 --max-cores-per-slice=2 -e selftest_crosscheck_output_consensus_only_slice
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/tests/0/result" pass
    test_yaml_numeric "/test-plans/heuristic@len" 'value == 2'
    local i j text reference mains=0
    for ((i = 0; i < ${yamldump[/tests/0/threads@len]}; ++i)); do
        [[ "${yamldump[/tests/0/threads/$i/thread]}" != main* ]] || ((++mains))
        for ((j = 0; j < ${yamldump[/tests/0/threads/$i/messages@len]}; ++j)); do
            text=${yamldump[/tests/0/threads/$i/messages/$j/text]}
            [[ "$text" =~ consensus\ slice\ reference\ ([0-9]+) ]] || continue
            reference=${BASH_REMATCH[1]}
            references[$reference]=$(( ${references[$reference]:-0} + 1 ))
        done
    done
    ((mains == 2 && ${#references[@]} == 2))
    for reference in "${!references[@]}"; do
        [[ "${references[$reference]}" -eq 2 ]]
    done
}

@test "selftest_crosscheck_output consensus data and structural failures honor ud-on-failure" {
    ((MAX_PROC > 1)) || skip "Requires multiple workers"
    [[ "$(uname -m)" = x86_64 ]] || skip "UD trap signal is architecture dependent"
    local SANDSTONE="$SANDSTONE --ud-on-failure"
    local suffix
    for suffix in only_single missing; do
        selftest_crash_common "selftest_crosscheck_output_consensus_$suffix" \
            SIGILL 0xC000001D "Illegal instruction"
    done
}

@test "selftest_crosscheck_output incomplete slice prevents pass in either slice order" {
    [[ "$SANDSTONE_DEVICE_TYPE" = CPU ]] || skip "Requires CPU slicing"
    $is_debug || skip "Requires Debug topology mocking"
    ((MAX_PROC >= 4)) || skip "Requires four workers"
    export SANDSTONE_MOCK_TOPOLOGY='c0 c1 c2 c3'
    declare -A yamldump
    local slice mode
    for mode in yes exec; do
        if $is_windows && [[ "$mode" = yes ]]; then
            continue
        fi
        for slice in 0 1; do
            sandstone_selftest -f"$mode" -vvv -n4 --max-cores-per-slice=2 \
                -e selftest_crosscheck_output_consensus_mixed_slice \
                -O "selftest_crosscheck_output_consensus_mixed_slice.incomplete_slice=$slice"
            [[ "$status" -eq 0 ]]
            test_yaml_regexp "/tests/0/result" skip
            test_yaml_regexp "/tests/0/skip-category" Runtime
            test_yaml_regexp "/tests/0/skip-reason" \
                'Cross-check consensus incomplete: not all workers completed successfully'
            test_yaml_numeric "/test-plans/heuristic@len" 'value == 2'
            [[ "$output" != *"SKIP requested in cleanup"* ]]
            [[ "$output" != *"output failure callback fired"* ]]
        done
    done
}

@test "selftest_crosscheck_output incomplete slices never hide deferred golden failures" {
    [[ "$SANDSTONE_DEVICE_TYPE" = CPU ]] || skip "Requires CPU slicing"
    $is_debug || skip "Requires Debug topology mocking"
    ((MAX_PROC >= 4)) || skip "Requires four workers"
    export SANDSTONE_MOCK_TOPOLOGY='c0 c1 c2 c3'
    declare -A yamldump
    local incomplete_slice failed_slice thread_index j callbacks text path
    for incomplete_slice in 0 1; do
        for failed_slice in 0 1; do
            sandstone_selftest -vvv --max-messages=20 -n4 --max-cores-per-slice=2 \
                -e selftest_crosscheck_output_consensus_mixed_slice \
                -O "selftest_crosscheck_output_consensus_mixed_slice.incomplete_slice=$incomplete_slice" \
                -O "selftest_crosscheck_output_consensus_mixed_slice.fail_slice=$failed_slice"
            [[ "$status" -eq 1 ]]
            test_yaml_regexp "/tests/0/result" fail
            test_yaml_absent "/tests/0/skip-reason"
            [[ "$output" = *"first submission vs golden output"* ]]
            [[ "$output" = *"output failure callback fired"* ]]
            thread_index=$((2 + 2 * failed_slice))
            path="/tests/0/threads/$thread_index"
            test_yaml_regexp "$path/state" failed
            callbacks=0
            for ((j = 0; j < ${yamldump[$path/messages@len]}; ++j)); do
                text=${yamldump[$path/messages/$j/text]}
                [[ "$text" != *"output failure callback fired"* ]] || ((++callbacks))
            done
            ((callbacks == 1))
            [[ "$output" != *"Cross-check consensus incomplete"* ]]
            [[ "$output" != *"SKIP requested in cleanup"* ]]
        done
    done
}

@test "selftest_crosscheck_output incomplete consensus resets before following no-fork passes" {
    ((MAX_PROC > 1)) || skip "Requires multiple workers"
    declare -A yamldump
    sandstone_selftest -fno -vvv -e selftest_crosscheck_output_consensus_skip \
        -e selftest_crosscheck_output_consensus_pass -e selftest_crosscheck_output_containers_pass
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/tests/0/result" skip
    test_yaml_regexp "/tests/0/skip-category" Runtime
    test_yaml_regexp "/tests/1/result" pass
    test_yaml_regexp "/tests/2/result" pass
    [[ "$output" != *"SKIP requested in cleanup"* ]]
    [[ "$output" != *"survived"* ]]
}

@test "selftest_crosscheck_output incomplete consensus reason reaches TAP and key-value loggers" {
    ((MAX_PROC > 1)) || skip "Requires multiple workers"
    local format
    for format in tap key-value; do
        run $SANDSTONE --selftests --retest-on-failure=0 -n"$MAX_PROC" -vvv -o - \
            --output-format="$format" -e selftest_crosscheck_output_consensus_skip
        [[ "$status" -eq 0 ]]
        [[ "$output" = *"Runtime"* ]]
        [[ "$output" = *"Cross-check consensus incomplete: not all workers completed successfully"* ]]
        [[ "$output" != *"SKIP requested in cleanup"* ]]
    done
}

@test "selftest_crosscheck_output reports each worker that differs from logical worker 0" {
    ((MAX_PROC > 1)) || skip "Requires multiple workers"
    declare -A yamldump
    local suffix worker i j path description expected actual count cpu text
    for suffix in zero_outlier single multiple distinct; do
        local -a extra=()
        [[ "$suffix" != distinct ]] || extra=(--reschedule=queue)
        sandstone_selftest -vvv -e "selftest_crosscheck_output_consensus_$suffix" "${extra[@]}"
        [[ "$status" -eq 1 ]]
        test_yaml_regexp "/tests/0/result" fail
        for ((worker = 0; worker < MAX_PROC; ++worker)); do
            i=$((worker + 1))
            count=0
            for ((j = 0; j < ${yamldump[/tests/0/threads/$i/messages@len]}; ++j)); do
                path="/tests/0/threads/$i/messages/$j"
                if [[ "${yamldump[$path/text]}" =~ consensus\ completion\ CPU\ ([0-9]+) ]]; then
                    cpu=${BASH_REMATCH[1]}
                fi
                description=${yamldump[$path/data-miscompare/description]}
                [[ "$description" = *"first submission vs worker 0's first submission"* ]] || continue
                if ((count == 0)); then
                    [[ "$description" = *"consensus_a' (worker a metadata)"* ]]
                else
                    [[ "$description" = *"consensus_z' (worker z metadata)"* ]]
                fi
                ((++count))
                expected=11
                actual=12
                [[ "$suffix" != zero_outlier ]] || { expected=12; actual=11; }
                [[ "$suffix" != distinct ]] || printf -v actual '%x' "$((17 + worker))"
                test_yaml_regexp "$path/data-miscompare/actual" "0x0*$actual( .*)?"
                test_yaml_regexp "$path/data-miscompare/expected" "0x0*$expected( .*)?"
            done
            if ((worker == 0)) || [[ "$suffix" = single && "$worker" != 1 ]]; then
                ((count == 0))
                [[ "${yamldump[/tests/0/threads/$i/state]}" != failed ]]
            else
                ((count == 2))
                test_yaml_regexp "/tests/0/threads/$i/state" failed
                if ! $is_windows; then
                    test_yaml_numeric "/tests/0/threads/$i/id/logical" "value == $cpu"
                fi
                local callbacks=0
                for ((j = 0; j < ${yamldump[/tests/0/threads/$i/messages@len]}; ++j)); do
                    text=${yamldump[/tests/0/threads/$i/messages/$j/text]}
                    [[ "$text" != *"output failure callback fired"* ]] || ((++callbacks))
                done
                ((callbacks == 1))
            fi
        done
        [[ "$output" != *"first submission vs golden output"* ]]
        [[ "$output" = *"output callback cleanup released storage"* ]]
    done
}

@test "selftest_crosscheck_output consensus missing count type and later errors" {
    ((MAX_PROC > 1)) || skip "Requires multiple workers"
    declare -A yamldump
    local suffix
    for suffix in missing reference_missing count type later; do
        sandstone_selftest -vvv -e "selftest_crosscheck_output_consensus_$suffix"
        [[ "$status" -eq 1 ]]
        test_yaml_regexp "/tests/0/result" fail
        case "$suffix" in
            missing) [[ "$output" = *"worker did not submit output"* ]] ;;
            reference_missing)
                test_yaml_regexp "/tests/0/threads/1/messages/1/text" \
                    "E> Cross-check output 'consensus_a': worker 0 did not submit output"
                [[ "$output" != *"first submission vs worker 0"* ]]
                ;;
            count) [[ "$output" = *"count mismatch: actual 1 vs expected 2"* ]] ;;
            type) [[ "$output" = *"element type mismatch"* ]] ;;
            later)
                [[ "$output" = *"later submission vs first submission"* ]]
                [[ "$output" = *"worker a metadata"* ]]
                ;;
        esac
        [[ "$output" != *"first submission vs golden output"* ]]
    done
}

@test "selftest_crosscheck_output consensus incomplete preserves skip error and early sequential exit" {
    ((MAX_PROC > 1)) || skip "Requires multiple workers"
    declare -A yamldump
    local suffix
    for suffix in skip error noreturn sequential_exit; do
        sandstone_selftest -vvv -e "selftest_crosscheck_output_consensus_$suffix"
        if [[ "$suffix" = skip ]]; then
            [[ "$status" -eq 0 ]]
            test_yaml_regexp "/tests/0/result" skip
            [[ "${yamldump[/tests/0/threads/2/state]}" != failed ]]
            [[ "$output" = *"Cross-check consensus incomplete"* ]]
        else
            [[ "$status" -eq 1 ]]
            test_yaml_regexp "/tests/0/result" fail
            [[ "$output" = *"original consensus worker"* ]]
        fi
        [[ "$output" != *"first submission vs worker 0"* ]]
        [[ "$output" != *"data-miscompare"* ]]
    done
}

@test "selftest_crosscheck_output failure skip and noreturn preserve original completion" {
    declare -A yamldump
    local suffix
    for suffix in fail_return fail_flag noreturn skip_return negative_return skip_flag \
            bad_first_fail_flag bad_first_skip_flag; do
        sandstone_selftest -vvv -e "selftest_crosscheck_output_$suffix"
        case "$suffix" in
            skip_*|negative_return|bad_first_skip_flag)
                [[ "$status" -eq 0 ]]
                test_yaml_regexp "/tests/0/result" skip
                [[ "$output" != *"output failure callback fired"* ]]
                ;;
            *)
                [[ "$status" -eq 1 ]]
                test_yaml_regexp "/tests/0/result" fail
                [[ "$output" = *"output failure callback fired"* ]]
                ;;
        esac
        if [[ "$suffix" = negative_return ]]; then
            [[ "$output" = *"original output negative return"* ]]
        fi
        [[ "$output" != *"first submission vs golden output"* ]]
        [[ "$output" != *"later submission vs first submission"* ]]
        [[ "$output" != *"data-miscompare"* ]]
        [[ "$output" != *"count mismatch"* ]]
        [[ "$output" != *"worker never submitted"* ]]
        [[ "$output" != *"worker did not submit"* ]]
        [[ "$output" = *"output test cleanup retained storage"* ]]
        [[ "$output" = *"output callback cleanup released storage"* ]]
    done
}

@test "selftest_crosscheck_output changed golden and init exits reset no-fork state" {
    declare -A yamldump
    sandstone_selftest -fno -vvv -e selftest_crosscheck_output_containers_pass \
        -e selftest_crosscheck_output_skip_init -e selftest_crosscheck_output_c_pass \
        -e selftest_crosscheck_output_error_init -e selftest_crosscheck_output_containers_pass
    [[ "$status" -eq 1 ]]
    test_yaml_numeric "/tests@len" 'value == 5'
    test_yaml_regexp "/tests/0/result" pass
    test_yaml_regexp "/tests/1/result" skip
    test_yaml_regexp "/tests/2/result" pass
    test_yaml_regexp "/tests/3/result" fail
    test_yaml_regexp "/tests/4/result" pass
    [[ "$output" = *"output init generation 5"* ]]
    [[ "$output" != *"survived"* ]]
}

@test "selftest_crosscheck_output parent init skip releases storage before the next no-fork pass" {
    declare -A yamldump
    sandstone_selftest -fno -vvv -e selftest_crosscheck_output_parent_skip_init \
        -e selftest_crosscheck_output_containers_pass
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/tests/0/result" skip
    test_yaml_regexp "/tests/1/result" pass
    [[ "$output" != *"survived"* ]]
}

@test "selftest_crosscheck_output retries get fresh golden outputs and first submissions" {
    declare -A yamldump
    sandstone_selftest -fno -vvv --retest-on-failure=1 -e selftest_crosscheck_output_retry
    [[ "$status" -eq 1 ]]
    # A single initial failure allows twice the requested retry count.
    test_yaml_numeric "/tests@len" 'value == 3'
    crosscheck_output_verify_mismatch 'first submission vs golden output' 7 6
    local i
    for i in 1 2; do
        test_yaml_regexp "/tests/$i/result" pass
        test_yaml_regexp "/tests/$i/state/retry" True
    done
    [[ "$output" = *"output init generation 3"* ]]
    [[ "$output" != *"survived"* ]]
}

@test "selftest_crosscheck_output fracture passes reset no-fork capture state" {
    declare -A yamldump
    sandstone_selftest -fno -vvv -e selftest_crosscheck_output_fracture_pass -t 490
    [[ "$status" -eq 0 ]]
    test_yaml_numeric "/tests@len" 'value >= 2'
    local i
    for ((i = 0; i < yamldump[/tests@len]; ++i)); do
        test_yaml_regexp "/tests/$i/result" pass
        test_yaml_numeric "/tests/$i/state/iteration" "value == $i"
    done
    [[ "$output" = *"output init generation 2"* ]]
    [[ "$output" != *"survived"* ]]
}
