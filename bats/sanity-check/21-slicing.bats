#!/usr/bin/bats
# -*- mode: sh -*-
# Copyright 2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
load ../testenv
load helpers

@test "crash backtrace multi-slice" {
    # We need GDB and at least two cores
    check_gdb_usable
    export SANDSTONE_MOCK_TOPOLOGY='0 1'
    run $SANDSTONE --cpuset=t0 --dump-cpu-info
    if [[ "$output" != *$'\n1\t'* ]]; then
        skip "Test only works with multiple cores or a debug build"
    fi

    declare -A yamldump
    selftest_crash_context_common --cpuset=t0 -n2 --timeout=5m -e selftest_sigsegv --on-crash=backtrace --max-cores-per-slice=1

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

