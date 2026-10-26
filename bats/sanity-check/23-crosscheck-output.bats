#!/usr/bin/bats
# Copyright 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
load ../testenv
load helpers

@test "selftest_crosscheck_output C C++ wrapper and representation passes" {
    declare -A yamldump
    local suffix
    for suffix in containers_pass c_pass c_golden_pass wrapper_pass \
            nan_pass padding_pass; do
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

@test "selftest_crosscheck_policy none rejects all API families in init workers and parent init" {
    local phase operation mode fixture
    for mode in no yes exec; do
        if $is_windows && [[ "$mode" = yes ]]; then
            continue
        fi
        for phase in init run parent; do
            fixture="selftest_crosscheck_none_$phase"
            for operation in 0 1 2; do
                run $SANDSTONE --selftests --timeout=20s --retest-on-failure=0 -Y -o - \
                    -n"$MAX_PROC" -f"$mode" -vvv --ud-on-failure -e "$fixture" \
                    -O "$fixture.operation=$operation"
                if [[ "$status" -ne 2 ]]; then
                    printf 'mode=%s fixture=%s operation=%s status=%s\n%s\n' \
                        "$mode" "$fixture" "$operation" "$status" "$output"
                fi
                [[ "$status" -eq 2 ]]
                [[ "$output" = *"cross-check APIs require an enabled .crosscheck policy"* ]]
                [[ "$output" != *"failure callback fired"* ]]
                [[ "$output" != *"data-miscompare"* ]]
            done
        done
        run $SANDSTONE --selftests --timeout=20s --retest-on-failure=0 -Y -o - \
            -n"$MAX_PROC" -f"$mode" -vvv --ud-on-failure --ignore-os-error \
            -e selftest_crosscheck_none_run
        if [[ "$mode" = no ]]; then
            [[ "$status" -eq 2 ]]
        else
            # Existing child OS-error handling permits this explicit waiver.
            [[ "$status" -eq 0 ]]
        fi
        [[ "$output" = *"cross-check APIs require an enabled .crosscheck policy"* ]]
        [[ "$output" != *"failure callback fired"* ]]
        [[ "$output" != *"state: failed"* ]]
    done
}

@test "selftest_crosscheck_policy declaration controls output authority" {
    local fixture
    for fixture in selftest_crosscheck_consensus_init_output selftest_crosscheck_golden_no_outputs \
            selftest_crosscheck_invalid_policy; do
        run $SANDSTONE --selftests --timeout=20s --retest-on-failure=0 -Y -o - \
            -n"$MAX_PROC" -vvv --ud-on-failure -e "$fixture"
        [[ "$status" -eq 2 ]]
        [[ "$output" = *"Cross-check invalid execution"* ]]
        [[ "$output" != *"output failure callback fired"* ]]
        [[ "$output" != *"data-miscompare"* ]]
    done
}

@test "selftest_crosscheck_output unknown golden name precedes pointer and extent validation" {
    declare -A yamldump
    local pointer count fixture=selftest_crosscheck_output_missing_golden
    for pointer in 0 1; do
        for count in 0 1; do
            sandstone_selftest -vvv --ud-on-failure -e "$fixture" \
                -O "$fixture.invalid_pointer=$pointer" -O "$fixture.invalid_count=$count"
            [[ "$status" -eq 2 ]]
            [[ "$output" = *"actual output has no golden reference"* ]]
            [[ "$output" != *"null data pointer"* ]]
            [[ "$output" != *"data extent overflows"* ]]
            [[ "$output" != *"output failure callback fired"* ]]
            [[ "$output" != *"data-miscompare"* ]]
        done
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

crosscheck_output_skip_message() {
    local owner=$1 reason=$2 i j path count=0
    for ((i = 0; i < ${yamldump[/tests/0/threads@len]}; ++i)); do
        for ((j = 0; j < ${yamldump[/tests/0/threads/$i/messages@len]:-0}; ++j)); do
            path="/tests/0/threads/$i/messages/$j"
            [[ "${yamldump[$path/text]}" = "$reason" ]] || continue
            ((++count))
            [[ "$i" -eq "$owner" ]]
            test_yaml_regexp "$path/level" skip
        done
    done
    ((count == 1))
    [[ "${yamldump[/tests/0/threads/$owner/state]}" != failed ]]
    for ((j = 0; j < ${yamldump[/tests/0/threads/$owner/messages@len]:-0}; ++j)); do
        path="/tests/0/threads/$owner/messages/$j"
        test_yaml_absent "$path/data-miscompare/description"
        [[ "${yamldump[$path/text]}" != *"output failure callback fired"* ]]
    done
}

@test "selftest_crosscheck_output explicit consensus skips preserve worker diagnostics" {
    ((MAX_PROC > 1)) || skip "Requires multiple workers"
    declare -A yamldump
    local worker after return_skip fatal
    local fixture=selftest_crosscheck_output_consensus_only_skip_diagnostic
    for worker in 0 1; do
        for after in 0 1; do
            return_skip=$((worker != after))
            for fatal in 0 1; do
                local -a extra=()
                ((fatal == 0)) || extra=(--fatal-skips)
                sandstone_selftest -vvv -n2 -e "$fixture" "${extra[@]}" \
                    -O "$fixture.skip_worker=$worker" -O "$fixture.after_submission=$after" \
                    -O "$fixture.return_skip=$return_skip"
                [[ "$status" -eq 2 ]]
                test_yaml_regexp "/tests/0/result" 'operating system error'
                test_yaml_regexp "/exit" invalid
                test_yaml_absent "/tests/0/skip-reason"
                crosscheck_output_skip_message "$((worker + 1))" 'original consensus worker explicit skip'
                [[ "$output" != *"data-miscompare"* ]]
                [[ "$output" != *"worker did not submit"* ]]
                [[ "$output" != *"output failure callback fired"* ]]
            done
        done
    done
}

@test "selftest_crosscheck_output explicit skip and peer disagreement are invalid without attribution" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    local fixture=selftest_crosscheck_output_consensus_only_skip_diagnostic
    sandstone_selftest -vvv -n3 -e "$fixture" -O "$fixture.after_submission=1" \
        -O "$fixture.return_skip=0" -O "$fixture.mismatch=1"
    [[ "$status" -eq 2 ]]
    test_yaml_regexp "/tests/0/result" 'operating system error'
    test_yaml_absent "/tests/0/skip-reason"
    crosscheck_output_skip_message 2 'original consensus worker explicit skip'
    [[ "${yamldump[/tests/0/threads/3/state]}" != failed ]]
    [[ "$output" = *"first submission vs worker 0"* ]]
    [[ "$output" != *"output failure callback fired"* ]]
    [[ "$output" = *"Cross-check consensus incomplete"* ]]
    [[ "$output" != *"data-miscompare"* ]]
}

crosscheck_output_consensus_fixture() {
    local workers=$1 mask=$2 after=$3 outlier=$4 return_skip=$5
    local fixture=selftest_crosscheck_output_consensus_only_states
    sandstone_selftest -vvv --max-messages=30 -n"$workers" -e "$fixture" \
        -O "$fixture.skip_mask=$mask" -O "$fixture.after_submission=$after" \
        -O "$fixture.outlier_worker=$outlier" -O "$fixture.return_skip=$return_skip"
    # Check fixture setup, not the incomplete-consensus outcome policy.
    [[ "$status" -eq 0 || "$status" -eq 2 ]]
    test_yaml_numeric "/tests/0/threads@len" "value == $((workers + 1))"
    local worker skipped submitted value i j path found
    for ((worker = 0; worker < workers; ++worker)); do
        skipped=$(((mask >> worker) & 1))
        submitted=$((!skipped || after))
        [[ "$output" = *"consensus fixture worker $worker: submitted=$submitted skipped=$skipped"* ]]
        value=$((17 + (worker == outlier)))
        if ((submitted)); then
            [[ "$output" = *"consensus fixture worker $worker submitted $value,23"* ]]
        else
            [[ "$output" != *"consensus fixture worker $worker submitted "* ]]
        fi
        i=$((worker + 1)) found=0
        for ((j = 0; j < ${yamldump[/tests/0/threads/$i/messages@len]:-0}; ++j)); do
            path="/tests/0/threads/$i/messages/$j"
            [[ "${yamldump[$path/text]}" = 'synthetic consensus worker resource unavailable' ]] || continue
            test_yaml_regexp "$path/level" skip
            ((++found))
        done
        ((found == skipped))
    done
    [[ "$output" != *"unexpected completion or submission state"* ]]
    [[ "$output" = *"output test cleanup retained storage"* ]]
    [[ "$output" = *"output callback cleanup released storage"* ]]
}

@test "selftest_crosscheck_output configurable complete consensus output shapes" {
    ((MAX_PROC >= 2)) || skip "Requires two workers"
    declare -A yamldump
    local workers outlier
    for workers in 2 3; do
        ((MAX_PROC >= workers)) || continue
        for outlier in -1 1; do
            crosscheck_output_consensus_fixture "$workers" 0 0 "$outlier" 1
            if ((outlier < 0)); then
                [[ "$status" -eq 0 ]]
                test_yaml_regexp "/tests/0/result" pass
            else
                [[ "$status" -eq 2 ]]
                test_yaml_regexp "/tests/0/result" 'operating system error'
            fi
        done
    done
}

@test "selftest_crosscheck_output unavailable reference fixture covers zero one and two survivors" {
    ((MAX_PROC >= 2)) || skip "Requires two workers"
    declare -A yamldump
    local scenario workers mask outlier after return_skip
    for scenario in '2 3 -1' '2 1 -1' '3 1 -1' '3 1 2' '3 1 0'; do
        read -r workers mask outlier <<< "$scenario"
        ((MAX_PROC >= workers)) || continue
        for after in 0 1; do
            [[ "$scenario" != '3 1 0' || "$after" != 0 ]] || continue
            for return_skip in 0 1; do
                crosscheck_output_consensus_fixture "$workers" "$mask" "$after" "$outlier" "$return_skip"
                [[ "$status" -eq 2 ]]
                [[ "$output" != *"data-miscompare"* ]]
                [[ "$output" != *"output failure callback fired"* ]]
            done
        done
    done
}

@test "selftest_crosscheck_output unavailable nonreference fixture submits an excluded outlier" {
    ((MAX_PROC >= 2)) || skip "Requires two workers"
    declare -A yamldump
    local workers after
    for workers in 2 3; do
        ((MAX_PROC >= workers)) || continue
        for after in 0 1; do
            crosscheck_output_consensus_fixture "$workers" 2 "$after" 1 "$after"
            [[ "$status" -eq 2 ]]
            [[ "$output" != *"data-miscompare"* ]]
            [[ "$output" != *"output failure callback fired"* ]]
        done
    done
}

@test "selftest_crosscheck_output ordered consensus merge preserves sorted diagnostics and deduplicates extras" {
    ((MAX_PROC >= 3)) || skip "Requires three workers"
    declare -A yamldump
    local fixture=selftest_crosscheck_output_consensus_only_states
    sandstone_selftest -vvv --max-messages=30 -n3 -e "$fixture" \
        -O "$fixture.skip_mask=0" -O "$fixture.ordered_merge=1"
    [[ "$status" -eq 2 ]]
    test_yaml_regexp "/tests/0/result" 'operating system error'
    local i j text name names
    for i in 1 2 3; do
        names=
        for ((j = 0; j < ${yamldump[/tests/0/threads/$i/messages@len]:-0}; ++j)); do
            text=${yamldump[/tests/0/threads/$i/messages/$j/text]}
            [[ "$text" = "E> Cross-check output '"* ]] || continue
            name=${text#*\'}
            names+=" ${name%%\'*}"
            if ((i == 1)); then
                [[ "$text" = *": worker 0 did not submit output" ]]
            elif [[ "$text" = *"_ref'"* ]]; then
                [[ "$text" = *": worker did not submit output" ]]
            else
                [[ "$text" = *": disagreement without independent attribution" ]]
            fi
        done
        if ((i == 1)); then
            [[ "$names" = ' a_extra c_extra e_extra k_extra' ]]
        else
            [[ "$names" = ' b_ref d_shared f_ref h_shared j_ref' ]]
        fi
        [[ "${yamldump[/tests/0/threads/$i/state]}" != failed ]]
    done
    [[ "$output" != *"data-miscompare"* ]]
    [[ "$output" != *"output failure callback fired"* ]]
}

@test "selftest_crosscheck_output ordered consensus merge finds skipped peer extras but never substitutes for worker zero" {
    ((MAX_PROC >= 2)) || skip "Requires two workers"
    declare -A yamldump
    local fixture=selftest_crosscheck_output_consensus_only_states
    local mask i j text name extras incomplete
    for mask in 2 1; do
        sandstone_selftest -vvv --max-messages=30 -n2 -e "$fixture" \
            -O "$fixture.skip_mask=$mask" -O "$fixture.after_submission=1" \
            -O "$fixture.ordered_merge=1"
        [[ "$status" -eq 2 ]]
        test_yaml_regexp "/tests/0/result" 'operating system error'
        extras= incomplete=0
        for i in 1 2; do
            for ((j = 0; j < ${yamldump[/tests/0/threads/$i/messages@len]:-0}; ++j)); do
                text=${yamldump[/tests/0/threads/$i/messages/$j/text]}
                if [[ "$text" = "E> Cross-check consensus incomplete: worker did not complete successfully" ]]; then
                    ((++incomplete))
                    ((i == (mask == 1 ? 1 : 2)))
                fi
                [[ "$text" = "E> Cross-check output '"* ]] || continue
                ((mask == 2 && i == 1))
                [[ "$text" = *": worker 0 did not submit output" ]]
                name=${text#*\'}
                extras+=" ${name%%\'*}"
            done
        done
        ((incomplete == 1))
        if ((mask == 2)); then
            [[ "$extras" = ' a_extra c_extra e_extra g_skipped_extra k_extra' ]]
        else
            [[ -z "$extras" ]]
        fi
        [[ "$output" != *"first submission vs worker 0"* ]]
        [[ "$output" != *"data-miscompare"* ]]
        [[ "$output" != *"output failure callback fired"* ]]
    done
}

@test "selftest_crosscheck_output wrong identical first results fail only after workers finish" {
    declare -A yamldump
    local suffix
    for suffix in bad_first c_bad_first; do
        crosscheck_output_mismatch "$suffix" 'first submission vs golden output' 7 6
        [[ "$output" = *"output post-submit sentinel"* ]]
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
            [[ "$text" != *"output post-submit sentinel"* ]] || ((++sentinels))
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
        [[ "$output" != *"output post-submit sentinel"* ]]
    done
}

@test "selftest_crosscheck_output counts are invalid at both boundaries" {
    declare -A yamldump
    local suffix boundary
    for suffix in golden_count later_count c_golden_count c_later_count; do
        boundary='first submission vs golden output'
        [[ "$suffix" != *later_count ]] || boundary='later submission vs first submission'
        sandstone_selftest -vvv -e "selftest_crosscheck_output_$suffix"
        [[ "$status" -eq 2 ]]
        test_yaml_regexp "/tests/0/result" 'operating system error'
        [[ "$output" = *"count mismatch"* ]]
        [[ "$output" != *"output failure callback fired"* ]]
        [[ "$output" != *"data-miscompare"* ]]
        if [[ "$suffix" = *later_count ]]; then
            [[ "$output" != *"output post-submit sentinel"* ]]
        else
            [[ "$output" = *"output post-submit sentinel"* ]]
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
        [[ "$output" != *"output post-submit sentinel"* ]]
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

@test "selftest_crosscheck_output invalid output submission is rejected in every build" {
    declare -A yamldump
    local suffix
    for suffix in duplicate submit_cleanup invalid_pointer invalid_count \
            worker_invalid_pointer worker_invalid_count; do
        sandstone_selftest -vvv --ud-on-failure -e "selftest_crosscheck_output_$suffix"
        [[ "$status" -eq 2 ]]
        [[ "$output" = *"Cross-check invalid execution"* ]]
        [[ "$output" != *"output failure callback fired"* ]]
        [[ "$output" != *"data-miscompare"* ]]
    done
}

@test "selftest_crosscheck_output reports missing worker submissions and element type mismatches" {
    declare -A yamldump
    local suffix
    for suffix in missing_all missing_partial c_conflict wrapper_conflict; do
        sandstone_selftest -vvv -e "selftest_crosscheck_output_$suffix"
        [[ "$status" -eq 2 ]]
        test_yaml_regexp "/tests/0/result" 'operating system error'
        [[ "$output" = *"worker did not submit"* || "$output" = *"worker never submitted"* \
            || "$output" = *"element type mismatch"* ]]
        [[ "$output" != *"data-miscompare"* ]]
        local i j callbacks text
        for ((i = 1; i <= MAX_PROC; ++i)); do
            callbacks=0
            [[ "${yamldump[/tests/0/threads/$i/state]}" != failed ]]
            for ((j = 0; j < ${yamldump[/tests/0/threads/$i/messages@len]}; ++j)); do
                text=${yamldump[/tests/0/threads/$i/messages/$j/text]}
                [[ "$text" != *"output failure callback fired"* ]] || ((++callbacks))
            done
            ((callbacks == 0))
        done
    done
}

@test "selftest_crosscheck_output consensus unanimous sequential and pass resets" {
    ((MAX_PROC > 1)) || skip "Requires multiple workers"
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

@test "selftest_crosscheck_output consensus-only requires multiple workers" {
    declare -A yamldump
    local workers
    for workers in 1 "$MAX_PROC"; do
        sandstone_selftest -vvv -n"$workers" -e selftest_crosscheck_output_consensus_pass
        [[ "$status" -eq 0 ]]
        if ((workers == 1)); then
            test_yaml_regexp "/tests/0/result" skip
            test_yaml_regexp "/tests/0/skip-category" TestResourceIssue
            [[ "$output" = *"requires at least two workers per slice"* ]]
            [[ "$output" != *"consensus completion CPU"* ]]
        else
            test_yaml_regexp "/tests/0/result" pass
        fi
        test_yaml_numeric "/tests/0/threads@len" "value == $((workers + 1))"
        [[ "$output" != *"output failure callback fired"* ]]
        [[ "$output" = *"output callback cleanup released storage"* ]]
        ((MAX_PROC > 1)) || break
    done
    ((MAX_PROC > 1)) || return 0
    sandstone_selftest -vvv -e selftest_crosscheck_output_consensus_single
    [[ "$status" -eq 2 ]]
    test_yaml_regexp "/tests/0/result" 'operating system error'
    [[ "$output" = *"first submission vs worker 0"* ]]
    [[ "$output" != *"first submission vs golden output"* ]]
}

@test "selftest_crosscheck_output consensus-only reference exits never select a fallback" {
    ((MAX_PROC > 1)) || skip "Requires multiple workers"
    declare -A yamldump
    local suffix
    for suffix in skip error noreturn; do
        sandstone_selftest -vvv -e "selftest_crosscheck_output_consensus_only_reference_$suffix"
        [[ "$status" -eq 2 ]]
        test_yaml_regexp "/tests/0/result" 'operating system error'
        if [[ "$suffix" = skip ]]; then
            [[ "$output" = *"Cross-check consensus incomplete"* ]]
            [[ "$output" != *"output failure callback fired"* ]]
        else
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

@test "selftest_crosscheck_output consensus disagreements and structural errors never trigger ud-on-failure" {
    ((MAX_PROC > 1)) || skip "Requires multiple workers"
    [[ "$(uname -m)" = x86_64 ]] || skip "UD trap signal is architecture dependent"
    declare -A yamldump
    local suffix
    for suffix in single missing; do
        sandstone_selftest --ud-on-failure -vvv -e "selftest_crosscheck_output_consensus_$suffix"
        [[ "$status" -eq 2 ]]
        [[ "$output" != *"output failure callback fired"* ]]
        [[ "$output" != *"data-miscompare"* ]]
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
            [[ "$status" -eq 2 ]]
            test_yaml_regexp "/tests/0/result" 'operating system error'
            test_yaml_absent "/tests/0/skip-reason"
            test_yaml_numeric "/test-plans/heuristic@len" 'value == 2'
            crosscheck_output_skip_message "$((3 + 2 * slice))" 'original consensus slice worker skip'
            [[ "$output" != *"SKIP requested in cleanup"* ]]
            [[ "$output" != *"output failure callback fired"* ]]
        done
    done
}

@test "selftest_crosscheck_output incomplete slices never hide independently attributed invariance failures" {
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
            [[ "$status" -eq 2 ]]
            test_yaml_regexp "/tests/0/result" 'operating system error'
            test_yaml_absent "/tests/0/skip-reason"
            crosscheck_output_skip_message "$((3 + 2 * incomplete_slice))" 'original consensus slice worker skip'
            [[ "$output" = *"later submission vs first submission"* ]]
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
            [[ "$output" = *"Cross-check consensus incomplete"* ]]
            [[ "$output" != *"SKIP requested in cleanup"* ]]
        done
    done
}

@test "selftest_crosscheck_output incomplete consensus stops no-fork execution unless OS errors are explicitly ignored" {
    ((MAX_PROC > 1)) || skip "Requires multiple workers"
    declare -A yamldump
    sandstone_selftest -fno -vvv -e selftest_crosscheck_output_consensus_skip \
        -e selftest_crosscheck_output_consensus_pass -e selftest_crosscheck_output_containers_pass
    [[ "$status" -eq 2 ]]
    test_yaml_regexp "/tests/0/result" 'operating system error'
    test_yaml_numeric "/tests@len" 'value == 1'
    run $SANDSTONE --selftests --timeout=20s --retest-on-failure=0 -Y -o - \
        -n"$MAX_PROC" -fno -vvv --ignore-os-error -e selftest_crosscheck_output_consensus_skip \
        -e selftest_crosscheck_output_consensus_pass -e selftest_crosscheck_output_containers_pass
    [[ "$status" -eq 0 ]]
    [[ "$output" = *"result: operating system error"* ]]
    [[ "$output" = *"test: selftest_crosscheck_output_consensus_pass"* ]]
    [[ "$output" = *"test: selftest_crosscheck_output_containers_pass"* ]]
    [[ "$output" = *"result: pass"* ]]
    [[ "$output" != *"SKIP requested in cleanup"* ]]
    [[ "$output" != *"survived"* ]]
}

@test "selftest_crosscheck_output incomplete consensus reason reaches TAP and key-value loggers" {
    ((MAX_PROC > 1)) || skip "Requires multiple workers"
    local format fatal
    local fixture=selftest_crosscheck_output_consensus_only_skip_diagnostic
    for format in tap key-value; do
        for fatal in 0 1; do
            local -a extra=()
            ((fatal == 0)) || extra=(--fatal-skips)
            run $SANDSTONE --selftests --retest-on-failure=0 -n2 -vvv -o - \
                --output-format="$format" -e "$fixture" -O "$fixture.after_submission=1" \
                -O "$fixture.return_skip=0" "${extra[@]}"
            [[ "$status" -eq 2 ]]
            [[ "$output" = *"Cross-check consensus incomplete: worker did not complete successfully"* ]]
            [[ "$output" = *"original consensus worker explicit skip"* ]]
            if [[ "$format" = tap ]]; then
                [[ "$output" = *"not ok "*"$fixture"* ]]
            else
                [[ "$output" = *"${fixture}_result = fail"* ]]
            fi
            [[ "$output" != *"SKIP requested in cleanup"* ]]
            [[ "$output" != *"output failure callback fired"* ]]
        done
    done
}

@test "selftest_crosscheck_output reports disagreement with fixed worker 0 without peer blame" {
    ((MAX_PROC > 1)) || skip "Requires multiple workers"
    declare -A yamldump
    local suffix worker i j path description count
    for suffix in zero_outlier single distinct; do
        local -a extra=()
        [[ "$suffix" != distinct ]] || extra=(--reschedule=queue)
        sandstone_selftest -vvv -e "selftest_crosscheck_output_consensus_$suffix" "${extra[@]}"
        [[ "$status" -eq 2 ]]
        test_yaml_regexp "/tests/0/result" 'operating system error'
        for ((worker = 0; worker < MAX_PROC; ++worker)); do
            i=$((worker + 1))
            count=0
            for ((j = 0; j < ${yamldump[/tests/0/threads/$i/messages@len]}; ++j)); do
                path="/tests/0/threads/$i/messages/$j"
                description=${yamldump[$path/text]}
                [[ "$description" = *"first submission vs worker 0's first submission"* ]] || continue
                if ((count == 0)); then
                    [[ "$description" = *"consensus_a' (worker a metadata)"* ]]
                else
                    [[ "$description" = *"consensus_z' (worker z metadata)"* ]]
                fi
                ((++count))
            done
            if ((worker == 0)) || [[ "$suffix" = single && "$worker" != 1 ]]; then
                ((count == 0))
                [[ "${yamldump[/tests/0/threads/$i/state]}" != failed ]]
            else
                ((count == 2))
                [[ "${yamldump[/tests/0/threads/$i/state]}" != failed ]]
            fi
        done
        [[ "$output" != *"first submission vs golden output"* ]]
        [[ "$output" != *"data-miscompare"* ]]
        [[ "$output" != *"output failure callback fired"* ]]
        [[ "$output" = *"output callback cleanup released storage"* ]]
    done
}

@test "selftest_crosscheck_output consensus missing count type and later errors" {
    ((MAX_PROC > 1)) || skip "Requires multiple workers"
    declare -A yamldump
    local suffix
    for suffix in missing reference_missing count type later; do
        sandstone_selftest -vvv -e "selftest_crosscheck_output_consensus_$suffix"
        [[ "$status" -eq 2 ]]
        test_yaml_regexp "/tests/0/result" 'operating system error'
        case "$suffix" in
            missing) [[ "$output" = *"worker did not submit output"* ]] ;;
            reference_missing)
                [[ "$output" = *"worker 0 did not submit output"* ]]
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
        if [[ "$suffix" != later ]]; then
            [[ "$output" != *"data-miscompare"* ]]
            [[ "$output" != *"output failure callback fired"* ]]
        else
            [[ "$output" = *"data-miscompare"* ]]
            [[ "$output" = *"output failure callback fired"* ]]
        fi
    done
}

@test "selftest_crosscheck_output consensus incomplete preserves skip error and early sequential exit" {
    ((MAX_PROC > 1)) || skip "Requires multiple workers"
    declare -A yamldump
    local suffix
    for suffix in skip error noreturn sequential_exit; do
        sandstone_selftest -vvv -e "selftest_crosscheck_output_consensus_$suffix"
        [[ "$status" -eq 2 ]]
        test_yaml_regexp "/tests/0/result" 'operating system error'
        if [[ "$suffix" = skip ]]; then
            [[ "${yamldump[/tests/0/threads/2/state]}" != failed ]]
            [[ "$output" = *"Cross-check consensus incomplete"* ]]
        else
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
        if [[ "$suffix" = skip_flag || "$suffix" = bad_first_skip_flag ]]; then
            local i reason='original output skip flag'
            [[ "$suffix" != bad_first_skip_flag ]] || reason+=' after wrong first submission'
            # Each worker owns a separate copy of the same original reason.
            for ((i = 1; i <= MAX_PROC; ++i)); do
                local j found=0
                for ((j = 0; j < ${yamldump[/tests/0/threads/$i/messages@len]}; ++j)); do
                    [[ "${yamldump[/tests/0/threads/$i/messages/$j/text]}" != "$reason" ]] || {
                        test_yaml_regexp "/tests/0/threads/$i/messages/$j/level" skip
                        ((++found))
                    }
                done
                ((found == 1))
            done
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

@test "selftest_crosscheck_output golden failure wins without verifying a skipped bad submission" {
    ((MAX_PROC > 1)) || skip "Requires multiple workers"
    declare -A yamldump
    sandstone_selftest -vvv -n2 -e selftest_crosscheck_output_mixed_bad_first_skip_flag
    [[ "$status" -eq 1 ]]
    test_yaml_regexp "/tests/0/result" fail
    crosscheck_output_skip_message 1 'original output skip flag after wrong first submission'
    test_yaml_regexp "/tests/0/threads/2/state" failed
    [[ "$output" = *"first submission vs golden output"* ]]
    [[ "$output" = *"output failure callback fired"* ]]
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

@test "selftest_crosscheck_output enabled empty and input-only consensus are invalid but named zero length is present" {
    ((MAX_PROC > 1)) || skip "Requires two workers"
    declare -A yamldump
    local suffix
    for suffix in empty input_only; do
        sandstone_selftest -vvv -n2 --ud-on-failure -e "selftest_crosscheck_output_consensus_$suffix"
        [[ "$status" -eq 2 ]]
        [[ "$output" = *"consensus registered no outputs"* ]]
        [[ "$output" != *"output failure callback fired"* ]]
        [[ "$output" != *"data-miscompare"* ]]
        [[ "$output" = *"output test cleanup retained storage"* ]]
        [[ "$output" = *"output callback cleanup released storage"* ]]
    done
    sandstone_selftest -vvv -n2 -e selftest_crosscheck_output_consensus_zero_length
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/tests/0/result" pass
}

@test "selftest_crosscheck_output consensus init skip does not activate verification" {
    declare -A yamldump
    sandstone_selftest -vvv -e selftest_crosscheck_output_consensus_only_skip_init
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/tests/0/result" skip
    [[ "$output" = *"Consensus init opted out before verification activation"* ]]
    [[ "$output" != *"Cross-check invalid"* ]]
}

@test "selftest_crosscheck_output deferred structural errors retain golden byte evidence in every process mode" {
    declare -A yamldump
    local mode
    for mode in no yes exec; do
        if $is_windows && [[ "$mode" = yes ]]; then
            continue
        fi
        sandstone_selftest -f"$mode" -vvv --max-messages=30 -e selftest_crosscheck_output_mixed_structural
        [[ "$status" -eq 2 ]]
        test_yaml_regexp "/tests/0/result" 'operating system error'
        [[ "$output" = *"worker did not submit"* ]]
        [[ "$output" = *"first submission vs golden output"* ]]
        [[ "$output" = *"data-miscompare"* ]]
        [[ "$output" = *"output failure callback fired"* ]]
        [[ "$output" = *"output test cleanup retained storage"* ]]
        [[ "$output" = *"output callback cleanup released storage"* ]]
    done
}

@test "selftest_crosscheck_output deferred invalidity during retries stops further attempts" {
    declare -A yamldump
    sandstone_selftest -fno -vvv --retest-on-failure=2 -e selftest_crosscheck_output_retry_invalid
    [[ "$status" -eq 2 ]]
    test_yaml_numeric "/tests@len" 'value == 2'
    test_yaml_regexp "/tests/0/result" fail
    test_yaml_regexp "/tests/1/result" 'operating system error'
    test_yaml_regexp "/tests/1/state/retry" True
    [[ "$output" = *"worker did not submit"* ]]
}

@test "selftest_crosscheck_output ordered golden merge skips extras and retains all diagnostics" {
    declare -A yamldump
    sandstone_selftest -vvv --max-messages=30 -e selftest_crosscheck_output_mixed_structural \
        -O selftest_crosscheck_output_mixed_structural.ordered_merge=1
    [[ "$status" -eq 2 ]]
    local i j path description names
    for ((i = 1; i <= MAX_PROC; ++i)); do
        names=
        for ((j = 0; j < ${yamldump[/tests/0/threads/$i/messages@len]}; ++j)); do
            path="/tests/0/threads/$i/messages/$j"
            description=${yamldump[$path/data-miscompare/description]:-${yamldump[$path/text]}}
            case "$description" in
                *"Cross-check output 'output_flags': worker did not submit"*) names+=" flags" ;;
                *"Cross-check output 'output_words'"*) names+=" words" ;;
                *"Cross-check output 'output_z'"*) names+=" z" ;;
                *"Cross-check output 'output_zz': worker did not submit"*) names+=" zz" ;;
            esac
        done
        [[ "$names" = ' flags words z zz' ]]
    done
    [[ "$output" = *"output failure callback fired"* ]]
    [[ "$output" != *"Cross-check output 'a_extra'"* ]]
    [[ "$output" != *"Cross-check output 'output_middle_extra'"* ]]
    [[ "$output" != *"Cross-check output 'zz_extra'"* ]]
}
