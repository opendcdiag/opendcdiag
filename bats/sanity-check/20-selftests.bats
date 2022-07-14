#!/usr/bin/bats
# -*- mode: sh -*-
# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
load ../testenv

sandstone_selftest() {
    VALIDATION=dump
    run_sandstone_yaml -n$MAX_PROC --disable=mce_check --no-triage --selftests --timeout=20s --retest-on-failure=0 -Y2 "$@"
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
}

test_yaml_numeric() {
    local query=$1
    local value
    extract_from_yaml "$query"
    shift
    if [[ -n "$value" ]]; then
        if awk -v value="$value" "BEGIN{exit(!($@))}" /dev/null; then
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
    if printf "%s" "$value" | grep --line-regexp -Pq -e "$2"; then
        return 0;
    fi
    printf "Regexp match failed:\n"
    printf "query:      %s\n" "$1"
    printf "value =     %s\n" "$value"
    printf "regex =     %s\n" "$2"
    return 1
}

@test "TAP output @positive" {
    local tests=`$SANDSTONE --selftests --list-group-members @positive | sed 's,\r$,,'`
    run $SANDSTONE --output-format=tap --selftests --timeout=15s --disable=mce_check -e @positive
    [[ "$status" -eq 0 ]]
    while read line; do
        printf "# %s\n" "$line"
        case "$line" in
            \#* | " "*)
                continue
                ;;
            "not ok"*)
                return 1
                ;;
            ok*)
                test=`echo "$line" | sed -E 's/^ok +([0-9]+ )?//;s/#.*//;s/ .*//'`
                echo "$tests" | grep -qxF -e $test
                ;;
            "exit: pass")
                ;;
            "exit: *")
                return 1
                ;;
        esac
    done <<<"$output"
}

@test "TAP output @negative" {
    # not all tests
    for test in selftest_failinit selftest_fail; do
        bash -c "$SANDSTONE --output-format=tap --no-triage --selftests --retest-on-failure=4 -e $test -o -; [[ $? -eq 1 ]]" | \
            sed 's,\r$,,' | tee output.tap
        egrep -qx "\[[ 0-9.]+\] exit: fail" output.tap
        not_oks=`grep -E 'not ok +([0-9] )'$test output.tap`
        [[ `echo "$not_oks" | wc -l` -eq 5 ]]
    done
}

@test "YAML header output" {
    declare -A yamldump
    local args="-e selftest_pass -Y4 -e selftest_skip -t 1234 --timeout=12345"
    sandstone_selftest $args    # yes, no quotes
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/command-line" ".* $args"
    test_yaml_regexp "/version" '([a-z-]+-)?(v[0-9.]+ \([0-9a-f]{40}\)|[0-9]+-[0-9]+-g[0-9a-f]+|[0-9a-f]{12}|[0-9a-f]{40})(-.*)?'

    local os=`uname -sr`
    if [[ "$SANDSTONE" = "wine "* ]]; then
        os=`wine cmd /c ver | sed -n "s/\r$//;s/.*Windows /Windows v/p"`
    fi
    test_yaml_regexp "/os" "\\Q$os\\E\\b.*"
    test_yaml_numeric "/timing/duration" 'value == 1234'
    test_yaml_numeric "/timing/timeout" 'value == 12345'

    # just verify these exist
    for ((i = 0; i < MAX_PROC; ++i)); do
        test_yaml_numeric "/cpu-info/$i/logical" 'value >= 0'
        test_yaml_numeric "/cpu-info/$i/package" 'value >= 0'
        test_yaml_numeric "/cpu-info/$i/core" 'value >= 0'
        test_yaml_numeric "/cpu-info/$i/thread" 'value >= 0'
        test_yaml_numeric "/cpu-info/$i/family" 'value >= 0'
        test_yaml_numeric "/cpu-info/$i/model" 'value >= 0'
        test_yaml_numeric "/cpu-info/$i/stepping" 'value >= 0'
        test_yaml_regexp "/cpu-info/$i/microcode" '(None|[0-9]+)'
        test_yaml_regexp "/cpu-info/$i/ppin" '(None|[0-9a-f]{16})'
    done
}

@test "obey taskset single" {
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
    run_sandstone_yaml -vvv --max-test-loop-count=1 --selftests -e selftest_timedpass

    test_yaml_numeric "/tests/0/threads@len" "value == $nproc / 2 + 1"
    for ((i = 0; i < nproc/2; ++i)); do
        test_yaml_numeric "/cpu-info/$i/logical" "value == $i * 2"
    done
}

@test "selftest_timedpass_maxthreads1 --timeout 100ms" {
    if [[ "$SANDSTONE" = "wine "* ]] && [[ "$HOME" = /github/* ]]; then
        skip "This test runs too slowly on GitHub runners"
    fi
    VALIDATION=dump
    declare -A yamldump
    sandstone_selftest -e selftest_timedpass_maxthreads1 --timeout 100ms
    [[ "$status" -eq 0 ]]
    test_yaml_numeric "/tests/0/test-runtime" 'value > 100'
}

@test "selftest_pass" {
    declare -A yamldump
    sandstone_selftest -e selftest_pass
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_pass
    test_yaml_regexp "/tests/0/details/quality" beta
    test_yaml_regexp "/tests/0/details/description" 'Just pass'
    test_yaml_regexp "/tests/0/state/seed" '\w+:\w+'
    test_yaml_numeric "/tests/0/state/iteration" 'value == 0'
    test_yaml_regexp "/tests/0/state/retry" False
    test_yaml_regexp "/tests/0/result" pass
    test_yaml_numeric "/tests/0/time-at-start/elapsed" 'value >= 0'
    test_yaml_numeric "/tests/0/time-at-end/elapsed" 'value >= 0'
    test_yaml_numeric "/tests/0/test-runtime" 'value >= 0'
}

@test "selftest_skip" {
    declare -A yamldump
    sandstone_selftest -e selftest_skip
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_skip
    test_yaml_regexp "/tests/0/result" skip
    test_yaml_regexp "/tests/0/threads/0/messages/0/level" info
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" '.*skip.*'
    i=$((-1 + yamldump[/tests/0/threads/0/messages@len]))
    test_yaml_regexp "/tests/0/threads/0/messages/$i/level" info
    test_yaml_regexp "/tests/0/threads/0/messages/$i/text" '.*requested skip.*'
}

@test "selftest_skip --fatal-skips" {
    declare -A yamldump
    sandstone_selftest -e selftest_skip --fatal-skips
    [[ "$status" -eq 1 ]]
    test_yaml_regexp "/exit" fail
    test_yaml_regexp "/tests/0/test" selftest_skip
    test_yaml_regexp "/tests/0/result" skip
    # There can't be other tests
    test_yaml_numeric "/tests@len" "value == 1"
}

@test "selftest_timedpass -t 250" {
    declare -A yamldump
    sandstone_selftest -e selftest_timedpass -t 250
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/result" pass
    test_yaml_numeric "/tests/0/test-runtime" 'value >= 250'
}

@test "selftest_timedpass -t 1150" {
    # With over 800 ms, we should see fracturing
    declare -A yamldump
    sandstone_selftest -e selftest_timedpass -t 1150
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass

    last_seed="Wontmatch"
    for ((i = 0; i < yamldump[/tests@len]; ++i)); do
        test_yaml_regexp "/tests/$i/test" selftest_timedpass
        test_yaml_regexp "/tests/$i/state/seed" '\w+:\w+'
        test_yaml_regexp "/tests/$i/state/retry" False
        test_yaml_numeric "/tests/$i/state/iteration" "value == $i"
        test_yaml_regexp "/tests/$i/result" pass

        # verify that the random generator seed is changing
        # (using pcre syntax to invert the match)
        test_yaml_regexp "/tests/$i/state/seed" "^((?!\\Q$last_seed\\E).)*\$"
        last_seed=${yamldump[/tests/$i/state/seed]}

        if ((i == yamldump[/tests@len] - 1)); then
            test_yaml_numeric "/tests/1/test-runtime" 'value >= 10'
        else
            test_yaml_numeric "/tests/0/test-runtime" 'value >= 400 && value <= 1000'
        fi
    done
}

@test "selftest_timedpass --max-test-loop-count=1" {
    # With just one loop, this should have very predictable timing
    declare -A yamldump
    sandstone_selftest -e selftest_timedpass --max-test-loop-count=1 -vvv
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/result" pass
    # FIXME: how to ensure this in a slow CI runner?
    #test_yaml_numeric "/tests/0/test-runtime" 'value < 20'
    for ((i = 1; i <= MAX_PROC; ++i)); do
        test_yaml_numeric "/tests/0/threads/$i/loop-count" 'value == 1'
    done
}

@test "selftest_logs" {
    declare -A yamldump
    sandstone_selftest -e selftest_logs
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/result" pass
    test_yaml_regexp "/tests/0/threads/0/thread" main
    test_yaml_regexp "/tests/0/threads/0/messages" '.*init function.*'
    for ((i = 1; i <= MAX_PROC; ++i)); do
        test_yaml_numeric "/tests/0/threads/$i/thread" "value == $i - 1"
        test_yaml_regexp "/tests/0/threads/$i/id" '\{.*\}'
        test_yaml_numeric "/tests/0/threads/$i/loop-count" 'value == 0'
        test_yaml_regexp "/tests/0/threads/$i/messages/0/level" '(debug|info|warning|error)'
        test_yaml_regexp "/tests/0/threads/$i/messages/0/text" '.> .+'

        # Confirm some aspects of the messages
        test_yaml_regexp "/tests/0/threads/$i/messages" '.*W> This is a .*warning.*'
        test_yaml_regexp "/tests/0/threads/$i/messages" '.*I> This is a .*info.*'
        if $SANDSTONE --is-debug >/dev/null 2>/dev/null; then
            test_yaml_regexp "/tests/0/threads/$i/messages" '.*d> This is a .*debug.*'
        fi
    done

    if ! $is_asan; then
        # ASAN builds don't catch stderr
        test_yaml_regexp "/tests/0/stderr messages" '.* stderr .*'
    fi

    i=2
    [[ MAX_PROC -gt 1 ]] || i=1
    test_yaml_regexp "/tests/0/threads/$i/messages" '.*message from cpu '$((i - 1))'.*'
}

@test "selftest_logdata" {
    declare -A yamldump
    sandstone_selftest -vvv -e selftest_logdata
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/result" pass
    for ((i = 1; i <= MAX_PROC; ++i)); do
        test_yaml_regexp "/tests/0/threads/$i/messages/0/level" info
        test_yaml_regexp "/tests/0/threads/$i/messages/0/text" '.*'
        test_yaml_regexp "/tests/0/threads/$i/messages/0/data" '[0-9a-f ]+'
    done
}

@test "selftest_logs_options" {
    declare -A yamldump
    sandstone_selftest -vvv -e selftest_logs_options
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/result" pass

    # with no -O, there should be no test-options
    test_yaml_absent "/tests/0/test-options"

    # but there should be if we set something
    sandstone_selftest -vvv -e selftest_logs_options -O dummy=dummy
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/result" pass
    test_yaml_regexp "/tests/0/test-options/selftest_logs_options.StringValue" 'DefaultValue'
    test_yaml_regexp "/tests/0/test-options/selftest_logs_options.NullStringValue" None
    test_yaml_numeric "/tests/0/test-options/selftest_logs_options.UIntValue" 'value == 0'
    test_yaml_numeric "/tests/0/test-options/selftest_logs_options.IntValue" 'value == -1'
    test_yaml_numeric "/tests/0/threads/0/messages@len" "value == 1"
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" '.*StringValue = DefaultValue'

    sandstone_selftest -vvv -e selftest_logs_options \
                       -O selftest_logs_options.NullStringValue=0x1 \
                       -O selftest_logs_options.UIntValue=0x1 \
                       -O selftest_logs_options.IntValue=0x1001
    test_yaml_regexp "/tests/0/test-options/selftest_logs_options.StringValue" 'DefaultValue'
    test_yaml_regexp "/tests/0/test-options/selftest_logs_options.NullStringValue" "0x1"
    test_yaml_numeric "/tests/0/test-options/selftest_logs_options.UIntValue" 'value == 1'
    test_yaml_numeric "/tests/0/test-options/selftest_logs_options.IntValue" 'value == 4097'
    test_yaml_numeric "/tests/0/threads/0/messages@len" "value == 3"
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" '.*StringValue = DefaultValue'
    test_yaml_regexp "/tests/0/threads/0/messages/1/text" '.*NullStringValue = 0x1'
    test_yaml_regexp "/tests/0/threads/0/messages/2/text" '.*Numbers: 1 4097'
}

test_list_file() {
    local -a list=("$@")
    local -i count=${#list[@]}
    declare -A yamldump
    sandstone_selftest --test-list-file <(printf '%s\n' "${list[@]}")
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass

    # confirm each test
    local -i i=0
    local entry
    for entry in "${list[@]}"; do
        if [[ "$entry" = "" ]] || [[ "$entry" = "#"* ]]; then
            continue;
        fi

        test_yaml_regexp "/tests/$i/result" "pass"
        test_yaml_regexp "/tests/$i/test" "${entry%:*}"

        # was there a duration?
        local -i duration=${entry#*:}
        if (( duration > 0 )); then
            test_yaml_numeric "/tests/$i/test-runtime" "value >= $duration"
            test_yaml_numeric "/tests/$i/test-runtime" "value <= 2 * $duration"
        fi

        i=$((i + 1))
    done
    test_yaml_numeric "/tests@len" "value = $i"
}

@test "--test-list-file with 1 test" {
    test_list_file selftest_pass
}

@test "--test-list-file with 3 tests" {
    test_list_file selftest_pass selftest_logs selftest_pass
}

@test "--test-list-file with duration" {
    test_list_file selftest_pass:default selftest_timedpass:50
}

@test "--test-list-file with comments and empty lines" {
    test_list_file '# a file list' '' selftest_pass '' '# the end!'
}

@test "--test-list-file with unknown test name" {
    # This doesn't produce valid YAML output, so run directly
    local name=`mktemp -u selftest_XXXXXX`
    run $SANDSTONE -Y -o - --selftests --test-list-file <(echo "$name")
    echo "$output"
    [[ $status -eq 64 ]]        # exit(EX_USAGE)
    grep -qwF "$name" <<<"$output"
}

# -- negative tests --

@test "selftest_failinit" {
    declare -A yamldump
    sandstone_selftest -e selftest_failinit
    [[ "$status" -eq 1 ]]
    test_yaml_regexp "/exit" fail
    test_yaml_regexp "/tests/0/result" fail
    test_yaml_regexp "/tests/0/fail/cpu-mask" None
    test_yaml_regexp "/tests/0/fail/time-to-fail" None
    test_yaml_regexp "/tests/0/fail/seed" '\w+:\w+'
    i=$((-1 + yamldump[/tests/0/threads/0/messages@len]))
    test_yaml_regexp "/tests/0/threads/0/messages/$i/level" error
    test_yaml_regexp "/tests/0/threads/0/messages/$i/text" 'E> Init function failed.*'
}

fail_common() {
    [[ "$status" -eq 1 ]]
    test_yaml_regexp "/exit" fail
    test_yaml_regexp "/tests/0/result" fail
    test_yaml_regexp "/tests/0/fail/cpu-mask" '[X_.:]+'
    test_yaml_regexp "/tests/0/state/seed" '\w+:\w+'
    test_yaml_regexp "/tests/0/fail/seed" "\\Q${yamldump[/tests/0/state/seed]}\\E"
    test_yaml_numeric "/tests/0/fail/time-to-fail" 'value > 0'

    ttf=${yamldump[/tests/0/fail/time-to-fail]}
    for ((i = 1; i <= MAX_PROC; ++i)); do
        test_yaml_regexp "/tests/0/threads/$i/state" failed
        test_yaml_numeric "/tests/0/threads/$i/time-to-fail" "value >= $ttf"
    done
}

@test "selftest_fail" {
    declare -A yamldump
    sandstone_selftest -vvv -e selftest_fail
    fail_common
}

@test "selftest_fail --retest-on-failure=3" {
    # with --total-retest-on-failure=5, we should see:
    # 1x selftest_fail, retry = false
    # 3x selftest_fail, retry = true
    # 1x selftest_fail, retry = false
    # 2x selftest_fail, retry = true
    # for a total of 7 runs

    declare -A yamldump
    sandstone_selftest -vvv -e selftest_fail -e selftest_fail --retest-on-failure=3 --total-retest-on-failure=5
    fail_common

    # confirm it retested - first selftest_fail
    for ((i = 1; i <= 3; ++i)); do
        # same test
        test_yaml_regexp "/tests/$i/test" selftest_fail
        # with the same RNG seed
        test_yaml_regexp "/tests/$i/state/seed" "\\Q${yamldump[/tests/0/fail/seed]}\\E"
        # reporting correctly
        test_yaml_regexp "/tests/$i/state/retry" True
        test_yaml_numeric "/tests/$i/state/iteration" "value == $i"
    done
    grep -e '# Test failed 4 out of 4' output.yaml

    # confirm it retested - second selftest_fail
    for ((i = 5; i <= 6; ++i)); do
        # same test
        test_yaml_regexp "/tests/$i/test" selftest_fail
        # with the same RNG seed
        test_yaml_regexp "/tests/$i/state/seed" "\\Q${yamldump[/tests/4/fail/seed]}\\E"
        # reporting correctly
        test_yaml_regexp "/tests/$i/state/retry" True
        test_yaml_numeric "/tests/$i/state/iteration" "value == $i - 4"
    done
    grep -e '# Test failed 3 out of 3' output.yaml
}

function selftest_logerror_common() {
    declare -A yamldump
    sandstone_selftest -vvv -e $1
    pattern=$2
    set -e
    fail_common
    for ((i = 1; i <= MAX_PROC; ++i)); do
        test_yaml_regexp "/tests/0/threads/$i/messages/0/level" error
        test_yaml_regexp "/tests/0/threads/$i/messages/0/text" 'E> '"${pattern/@CPU@/$((i - 1))}"
    done
}

@test "selftest_logerror" {
    selftest_logerror_common selftest_logerror "This is an error.*CPU @CPU@"
}

@test "selftest_reportfail" {
    selftest_logerror_common selftest_reportfail 'Failed at .*selftest\.cpp:[0-9]+'
}
@test "selftest_reportfailmsg" {
    selftest_logerror_common selftest_reportfailmsg 'Failed at .*selftest\.cpp:[0-9]+: Failure message from thread @CPU@'
}

@test "selftest_cxxthrow" {
    selftest_logerror_common selftest_cxxthrow 'Caught C\+\+ exception: .*'
}

@test "selftest_datacompare" {
    declare -A yamldump
    local dataregexp='0x[0-9a-f]+( \(([-0-9]+|[-+0-9a-fpx.]+)\))?'
    for test in `$SANDSTONE --selftests --list-tests | sed -n '/^selftest_datacomparefail/s/\r$//p'`; do
        type=${test#selftest_datacomparefail_}
        case "$type" in
            Float16)            type=_Float16;;
            long_double)        type=_Float64x;;
        esac
        sandstone_selftest -vvv -e $test
        set -e
        fail_common
        for ((i = 1; i <= MAX_PROC; ++i)); do
            test_yaml_regexp "/tests/0/threads/$i/messages/0/level" error
            test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/type" $type
            test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/offset" '\[.*\]'
            test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/address" '0x[0-9a-f]+'
            test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/actual" "$dataregexp"
            test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/expected" "$dataregexp"
            test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/mask" '0x[0-9a-f]+'
            test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/actual data" '[0-9a-f ]+'
            test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/expected data" '[0-9a-f ]+'
        done
    done
}

@test "selftest_freeze" {
    declare -A yamldump
    sandstone_selftest -vvv --on-crash=kill --on-hang=kill -e selftest_freeze --timeout=1s
    [[ "$status" -eq 2 ]]
    test_yaml_regexp "/exit" invalid
    test_yaml_regexp "/tests/0/result" 'timed out'
    test_yaml_numeric "/tests/0/test-runtime" 'value >= 1000'
    for ((i = 1; i <= MAX_PROC; ++i)); do
        test_yaml_regexp "/tests/0/threads/$i/state" failed
        n=$((-1 + yamldump[/tests/0/threads/$i/messages@len]))
        test_yaml_regexp "/tests/0/threads/$i/messages/$n/text" '.*Thread is stuck'
    done
}

@test "selftest_freeze --ignore-timeout" {
    declare -A yamldump
    sandstone_selftest -vvv --on-crash=kill --on-hang=kill -e selftest_freeze --timeout=500 --ignore-timeout
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/result" 'timed out'
}

selftest_crash_common() {
    if $is_asan; then
        skip "Crashing tests skipped with ASAN"
    fi
    if ! declare -p yamldump >/dev/null 2>/dev/null; then
        declare -A yamldump
    fi
    sandstone_selftest --on-crash=kill -vvv -e $1
    [[ "$status" -eq 1 ]]
    test_yaml_regexp "/exit" fail
    test_yaml_regexp "/tests/0/result/crashed" True
    test_yaml_regexp "/tests/0/result/core-dump" '(True|False)'
    if $is_windows; then
        shift 2
    fi
    test_yaml_numeric "/tests/0/result/code" 'value > 0 && value == '$2
    test_yaml_regexp "/tests/0/result/reason" "$3"
}

@test "selftest_abortinit" {
    selftest_crash_common selftest_abortinit 6 "Aborted" 0xC0000602 "Aborted"
}

@test "selftest_abort" {
    selftest_crash_common selftest_abort 6 "Aborted" 0xC0000602 "Aborted"
}

@test "selftest_sigill" {
    selftest_crash_common selftest_sigill 4 "Illegal instruction" 0xC000001D "Illegal instruction"
}

@test "selftest_sigfpe" {
    selftest_crash_common selftest_sigfpe 8 "Floating point exception" 0xC0000094 'Integer division by zero'
}

@test "selftest_sigbus" {
    selftest_crash_common selftest_sigbus 7 "Bus error" 0xC0000005 'Access violation'
}

@test "selftest_sigsegv_init" {
    selftest_crash_common selftest_sigsegv 11 "Segmentation fault" 0xC0000005 'Access violation'
}

@test "selftest_sigsegv" {
    selftest_crash_common selftest_sigsegv 11 "Segmentation fault" 0xC0000005 'Access violation'
}

@test "selftest_sigsegv_cleanup" {
    selftest_crash_common selftest_sigsegv 11 "Segmentation fault" 0xC0000005 'Access violation'
}

@test "selftest_sigsegv_instruction" {
    selftest_crash_common selftest_sigsegv_instruction 11 "Segmentation fault" 0xC0000005 'Access violation'
}

@test "selftest_fastfail" {
    if ! $is_windows; then
        skip "Windows-only test"
    fi
    if [[ "$SANDSTONE" = "wine "* ]]; then
        # WINE doesn't handle __fastfail very well / at all
        selftest_crash_common selftest_fastfail x x 0xC0000005 'Access violation'
    else
        # I don't know *why* we get this error, but we do
        selftest_crash_common selftest_fastfail x x 0xC0000409 "Stack buffer overrun"
    fi
}

@test "selftest_sigkill" {
    if $is_windows; then
        skip "Unix-only test"
    fi
    declare -A yamldump
    sandstone_selftest -vvv -e selftest_sigkill
    [[ "$status" -eq 2 ]]
    test_yaml_regexp "/exit" invalid    # interpreted as OOM killer
    test_yaml_regexp "/tests/0/result/crashed" True
    test_yaml_regexp "/tests/0/result/core-dump" '(True|False)'
    test_yaml_numeric "/tests/0/result/code" 'value > 0 && value == 9'
    test_yaml_regexp "/tests/0/result/reason" Killed
}

@test "selftest_sigkill --ignore-os-error" {
    if $is_windows; then
        skip "Unix-only test"
    fi
    declare -A yamldump
    sandstone_selftest -vvv -e selftest_sigkill --ignore-os-error
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/result/crashed" True
    test_yaml_regexp "/tests/0/result/reason" Killed
}

@test "selftest_malloc_fail" {
    declare -A yamldump
    selftest_crash_common selftest_malloc_fail 6 "Aborted" 0xC0000017 "Out of memory condition"
    test_yaml_regexp "/tests/0/stderr messages" 'Out of memory condition'
}

@test "backtrace" {
    if $is_asan; then
        skip "Crashing tests skipped with ASAN"
    fi
    if ! type -p gdb > /dev/null; then
        skip "GDB not installed"
    fi
    if [[ "$SANDSTONE" != "$SANDSTONE_BIN" ]] &&
       [[ "$SANDSTONE" != "$SANDSTONE_BIN "* ]]; then
        skip "Not executing directly (executing '$SANDSTONE')"
    fi
    declare -A yamldump
    sandstone_selftest --on-crash=backtrace -n1 -vvv -e selftest_sigsegv
    [[ "$status" -eq 1 ]]
    test_yaml_regexp "/exit" fail
    test_yaml_regexp "/tests/0/result/crashed" True
    test_yaml_regexp "/tests/0/threads/0/messages/0/level" "info"
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" "Backtrace:.*"
    test_yaml_regexp "/tests/0/threads/1/state" "failed"
    test_yaml_regexp "/tests/0/threads/1/messages/0/level" "error"
    test_yaml_regexp "/tests/0/threads/1/messages/0/text" ".*\((Segmentation fault|Access violation)\).*"
    if ! $is_windows &&
            gdb -batch -ex 'python 1' 2>/dev/null; then
        test_yaml_regexp "/tests/0/threads/1/messages/1/level" "warning"
        test_yaml_regexp "/tests/0/threads/1/messages/1/text" ".*\bmov\b.*"
        test_yaml_regexp "/tests/0/threads/1/messages/2/level" "info"
        test_yaml_regexp "/tests/0/threads/1/messages/2/text" "Registers:"
        test_yaml_regexp "/tests/0/threads/1/messages/2/text" " rax += 0x[0-9a-f]{16}.*"
    fi
}

@test "triage" {
    if ! $is_debug; then
        skip "Test only works with Debug builds (to mock the topology)"
    fi
    if (( MAX_PROC < 4 )); then
        skip "Need at least 4 logical processors to run this test"
    fi
    declare -A yamldump
    export SANDSTONE_MOCK_TOPOLOGY='0 1 2 3'

    # can't use sandstone_selftest because of --no-triage
    VALIDATION=dump
    run_sandstone_yaml -n$MAX_PROC --disable=mce_check --selftests --timeout=20s --retest-on-failure=0 -Y -e selftest_fail_socket1

    # confirm the topology took effect
    for ((i = 0; i < 4; ++i)); do
        test_yaml_numeric "/cpu-info/$i/logical" "value == $i"
        test_yaml_numeric "/cpu-info/$i/package" "value == $i"
        test_yaml_numeric "/cpu-info/$i/core" 'value == 0'
        test_yaml_numeric "/cpu-info/$i/thread" 'value == 0'
    done

    # now confirm it exited properly
    [[ "$status" -eq 1 ]]
    test_yaml_regexp "/exit" fail

    # and test it did triage properly
    test_yaml_numeric "/triage-results@len" 'value == 1'
    test_yaml_numeric "/triage-results/0" 'value == 1'
}
