#!/bin/bash
# Copyright 2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

sandstone_selftest() {
    VALIDATION=dump
    run_sandstone_yaml -n$MAX_PROC --disable=mce_check --selftests --timeout=20s --retest-on-failure=0 -Y2 "$@"
}

extract_from_yaml() {
    if [[ "${yamldump[$1]-unset}" = unset ]]; then
        printf 'Query not found in structure: %s\n' "$1"
        printf ' %s\n' "${!yamldump[@]}" | sort
        return 1
    fi
    local query=$1
    value=${yamldump[$1]}
}

test_yaml_absent() {
    local query=$1
    local isset=${yamldump[$1]:+1}
    if [[ -z "$isset" ]]; then
        return 0
    fi

    printf "Key is not absent:\\n"
    printf "query:      %s\n" "$query"
    printf "value =     %s\n" "${yamldump[$query]}"
    return 1
}

test_yaml_numeric() {
    local query=$1
    local value
    extract_from_yaml "$query"
    shift
    if [[ -n "$value" ]]; then
        if awk -v value="$value" "BEGIN{exit(!($*))}" /dev/null; then
            return 0
        fi
    fi
    printf "Numeric test failed:\n"
    printf "query:      %s\n" "$query"
    printf "value =     %s\n" "$value"
    printf "expression: %s\n" "$*"
    return 1
}

test_yaml_regexp() {
    local value
    extract_from_yaml "$1"
    if printf "%s" "$value" | grep --line-regexp -Eq -e "$2"; then
        return 0
    fi
    printf "Regexp match failed:\n"
    printf "query:      %s\n" "$1"
    printf "value =     %s\n" "$value"
    printf "regex =     %s\n" "$2"
    return 1
}

check_gdb_usable() {
    if [[ "$SANDSTONE" != "$SANDSTONE_BIN" ]] &&
       [[ "$SANDSTONE" != "$SANDSTONE_BIN "* ]]; then
        skip "Not executing directly (executing '$SANDSTONE')"
    fi

    # Check that we have gdb
    if ! gdb -batch -ex 'python 1' 2>/dev/null; then
        skip "No GDB in this installation."
    fi

    # Check that gdb can attach to running processes
    sleep 120 &
    pid=$!
    if ! gdb -batch -pid $pid -ex kill >/dev/null 2>/dev/null; then
        kill $pid
        ps h $pid ||:
        skip "GDB can't attach to running processes"
    fi
    wait $pid ||:
}

selftest_crash_context_common() {
    if $is_asan; then
        skip "Crashing tests skipped with ASAN"
    fi
    if [[ `uname -r` = *-azure ]]; then
        skip "GitHub Hosted Actions somehow make this impossible"
    fi

    sandstone_selftest "$@"
    [[ "$status" -eq 1 ]]
    test_yaml_regexp "/exit" fail
    test_yaml_regexp "/tests/0/result" "crash"
    test_yaml_regexp "/tests/0/result-details/crashed" True

    local threadidx=$((yamldump[/tests/0/threads@len] - 1))
    test_yaml_regexp "/tests/0/threads/$threadidx/state" "failed"
    test_yaml_regexp "/tests/0/threads/$threadidx/messages/0/level" "error"
    if $is_windows; then
        test_yaml_regexp "/tests/0/threads/$threadidx/messages/0/text" ".*Received exception 0xc0000005 \(Access violation\), RIP = 0x.*"
    else
        local signum=`kill -l SEGV`
        test_yaml_regexp "/tests/0/threads/$threadidx/messages/0/text" ".*Received signal $signum \((Segmentation fault|Access violation)\) code=[0-9]+.* RIP = 0x.*"
    fi

    if [[ `uname -m` = x86_64 ]]; then
        # OpenDCDiag's built-in register dumper is only implemented for x86-64
        msgidx=$((yamldump[/tests/0/threads/$threadidx/messages@len] - 1))
        test_yaml_regexp "/tests/0/threads/$threadidx/messages/$msgidx/level" "info"
        test_yaml_regexp "/tests/0/threads/$threadidx/messages/$msgidx/text" "Registers:"
        test_yaml_regexp "/tests/0/threads/$threadidx/messages/$msgidx/text" " rax += 0x[0-9a-f]{16}.*"
    fi
}
