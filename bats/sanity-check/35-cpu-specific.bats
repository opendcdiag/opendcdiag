#!/usr/bin/bats
# -*- mode: sh -*-
# Copyright 2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
load ../testenv
load helpers

function setup_cpu_features_tests() {
    run $SANDSTONE --selftests --list-group-members @test_hw_features
    export cpu_features_tests=$output
    if [[ $status -ne 0 ]]; then
        skip "No tests for specific CPU type in this build"
    fi
}

function setup_file() {
    setup_cpu_features_tests
}

function run_min_cpu_test() {
    local test=$1

    declare -A yamldump
    sandstone_selftest -e $test

    [[ "$status" -eq 0 ]]

    if [[ "${yamldump[/tests/0/result]}" = skip ]]; then
        skip "Test skipped due to matching 'skip' result"
    fi
}

@test "selftest_test_hsw_min_cpu" {
    run_min_cpu_test selftest_test_hsw_min_cpu
}

@test "selftest_test_bdw_min_cpu" {
    run_min_cpu_test selftest_test_bdw_min_cpu
}

@test "selftest_test_skl_min_cpu" {
    run_min_cpu_test selftest_test_skl_min_cpu
}

@test "selftest_test_skx_min_cpu" {
    run_min_cpu_test selftest_test_skx_min_cpu
}

@test "selftest_test_icx_min_cpu" {
    run_min_cpu_test selftest_test_icx_min_cpu
}

@test "selftest_test_spr_min_cpu" {
    run_min_cpu_test selftest_test_spr_min_cpu
}

@test "selftest_test_srf_min_cpu" {
    run_min_cpu_test selftest_test_srf_min_cpu
}

@test "selftest_test_gnr_min_cpu" {
    run_min_cpu_test selftest_test_gnr_min_cpu
}

@test "selftest_test_dmr_min_cpu" {
    run_min_cpu_test selftest_test_dmr_min_cpu
}
