#!/usr/bin/bats
# -*- mode: sh -*-
# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
load ../testenv
load helpers

function setup_file() {
    run $SANDSTONE --selftests --list-group-members @kvm
    export kvm_tests=$output
    if [[ $status -ne 0 ]]; then
        skip "No KVM tests in this build"
    fi

    # Intersect the @kvm and @positive groups
    kvm_tests_positive=$($SANDSTONE --selftests --list-group-members @positive | \
                         grep -Fxf <(echo "${kvm_tests}"))

    kvm_tests_negative=$(grep -Fxvf <(echo "${kvm_tests_positive}") <(echo "${kvm_tests}"))
    export kvm_tests_positive=$(echo "${kvm_tests_positive}" | xargs)
    export kvm_tests_negative=$(echo "${kvm_tests_negative}" | xargs)
#    echo \# a: $kvm_tests >&3
#    echo \# +: $kvm_tests_positive >&3
#    echo \# -: $kvm_tests_negative >&3
}

function run_kvm_selftests() {
    # KVM tests may skip, pass, or fail, but mustn't crash or anything else
    declare -A yamldump
    local expectation=$1
    shift
    local args=()
    while [[ "$1" = -* ]]; do
        args+=($1)
        shift
    done
    args+=(`printf -- '-e%s ' $@`)

    sandstone_selftest --retest-on-failure=0 --quick "${args[@]}"

    local exit=pass
    local i=0
    for ((i = 0; i < ${yamldump[/tests@len]}; ++i)); do
        #printf '# %s\n' ${yamldump[/tests/$i/test]} >&3
        test_yaml_regexp "/tests/$i/result" "skip|$expectation"
        if [[ "${yamldump[/tests/$i/result]}" = fail ]]; then
            exit=fail
        fi
    done
    test_yaml_expr "/exit" = "$exit"
}

@test "kvm_positive -fyes" {
    ! $is_windows || skip "Not supported on Windows"
    run_kvm_selftests pass -fyes $kvm_tests_positive
}

@test "kvm_positive -fno" {
    run_kvm_selftests pass -fno $kvm_tests_positive
}

@test "kvm_positive -fexec" {
    run_kvm_selftests pass -fexec $kvm_tests_positive
}

@test "kvm_negative -fyes" {
    ! $is_windows || skip "Not supported on Windows"
    run_kvm_selftests fail -fyes $kvm_tests_negative
}

@test "kvm_negative -fno" {
    run_kvm_selftests fail -fno $kvm_tests_negative
}

@test "kvm_negative -fexec" {
    run_kvm_selftests fail -fexec $kvm_tests_negative
}
