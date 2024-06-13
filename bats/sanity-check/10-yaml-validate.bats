#!/usr/bin/bats
# -*- mode: sh -*-
# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

load ../testenv

@test "Verify that the python yaml module can import regular output" {
    run_sandstone_yaml --retest-on-failure=0 --selftest --timeout=60s --quick -e @positive
}

@test "Verify that the python yaml module can import regular, indented output" {
    run_sandstone_yaml --retest-on-failure=0 --selftest --timeout=60s --quick -Y10 -e @positive
}

@test "Verify that the python yaml module can import failure output" {
    for test in selftest_failinit selftest_fail selftest_freeze selftest_sigill; do
        run $SANDSTONE --no-triage --retest-on-failure=1 --on-crash=kill --on-hang=kill --timeout=2s --selftest -o output-${test}.yaml -Y2 -e $test
        if [[ "$status" = 0 ]]; then
            printf "%s: status is 0\n" $test
            exit 1
        fi

        python3 $BATS_TEST_COMMONDIR/yamltest.py output-${test}.yaml
    done
}
