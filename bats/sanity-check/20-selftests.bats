#!/usr/bin/bats
# -*- mode: sh -*-
# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
load ../testenv

mktempfile() {
    # find a temporary directory for us
    local tmpdir=$BATS_TEST_TMPDIR
    tmpdir=${tmpdir-$BATS_TMPDIR}
    tmpdir=${tmpdir-$TMPDIR}
    tmpdir=${tmpdir-/tmp}
    TMPDIR=$tmpdir mktemp --tmpdir "$@"
}

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
    if printf "%s" "$value" | grep --line-regexp -Eq -e "$2"; then
        return 0
    fi
    printf "Regexp match failed:\n"
    printf "query:      %s\n" "$1"
    printf "value =     %s\n" "$value"
    printf "regex =     %s\n" "$2"
    return 1
}

test_fail_socket1() {
    if $is_debug; then
        if (( MAX_PROC < 4 )); then
            skip "Need at least 4 logical processors to run this test"
        fi
        SANDSTONE_MOCK_TOPOLOGY="0 1 0:1 1:1" "$@"
    else
        # Maybe we're running on a real multi-socket system
        run $SANDSTONE --cpuset=p1 --dump-cpu-info
        if (( status != 0 )); then
            skip "Test only works with Debug builds (to mock the topology) or multi-socket systems"
        fi
        "$@" --cpuset=c0t0,c1t0
    fi

    # only one socket should have had problems
    test_yaml_regexp "/tests/0/fail/cpu-mask" 'None|\.+:\.*X[.X]*(:.+)?'
}

@test "time parse negative" {
    # positive parsing with the YAML header below
    run $SANDSTONE -t xyzzy
    ((status == 64))
    [[ "$output" = *": invalid time \"xyzzy\": could not parse"* ]]

    run $SANDSTONE -t 1yr
    ((status == 64))
    [[ "$output" = *": invalid time \"1yr\": unknown time unit"* ]]

    run $SANDSTONE -t 1d
    ((status == 64))
    [[ "$output" = *": invalid time \"1d\": unknown time unit"* ]]

    run $SANDSTONE -t 1000us
    ((status == 64))
    [[ "$output" = *": invalid time \"1000us\": unknown time unit"* ]]

    out_of_range() {
        local t=$1
        run $SANDSTONE -t $t
        ((status == 64))
        [[ "$output" = *": invalid time \"$t\": time out of range"* ]]
    }
    out_of_range 597h
    out_of_range 35792min
    out_of_range 21474837s
    out_of_range 2147483648ms
    out_of_range 2147483648
}

@test "TAP output @positive" {
    # make an associative array:
    #  tests=([selftest_pass]=1 [selftest_logs]=1 ...)
    eval local -A tests=\( \
         $($SANDSTONE --selftests --list-group-members @positive | \
               sed -E 's/^/[/; s/\r?$/]=1/') \
         \)

    # Run without the timeedpass tests to run more quickly
    run $SANDSTONE -n$MAX_PROC --output-format=tap --selftests --quick --timeout=15s --disable=mce_check --disable='*timedpass*' -e @positive
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
                if [[ "$line" =~ 'ok '[\ 0-9]+\ ([^#\ ]+)\ *#' (beta test)'? ]]; then
                    test=${BASH_REMATCH[1]}
                    if [[ "${tests[$test]}" != 1 ]]; then
                        echo Unexpected test: "$test" >&2
                        return 1
                    fi
                else
                    echo "bad line: $line" >&2
                    return 1
                fi
                ;;
            "exit: pass")
                ;;
            "exit: *")
                return 1
                ;;
        esac
    done <<<"$output"
}

tap_negative_check() {
    local line
    local test=$1
    local suffix=$2
    local exit_line=${3-"exit: fail"}
    notok=0
    while read line; do
        case "$line" in
            \#* | \
                "$exit_line" | \
                "THIS IS AN UNOPTIMIZED BUILD"*)
                # acceptable line
                ;;
            "not ok"*)
                # inspect a little more
                if ! [[ "$line" =~ 'not ok '[\ 0-9]+\ ([^#\ ]+)\ *#' (beta test)'?$suffix ]] ||
                        ! [[ "${BASH_REMATCH[1]}" = "$test" ]]; then
                    echo "bad line: $line" >&2
                    return 1
                fi
                notok=$((notok + 1))
                ;;
            "---")
                # beginning of YAML output, scan until its end
                while read line; do
                    if [[ "$line" = --- ]]; then
                        break
                    fi
                done
                ;;
            *)
                echo "bad line: $line" >&2
                return 1
                ;;
        esac
    done
}

@test "TAP output fails" {
    # not all tests
    for test in selftest_failinit selftest_fail; do
        local notok
        run $SANDSTONE --output-format=tap --no-triage --selftests --retest-on-failure=4 --on-crash=kill -e $test -o /dev/null -v
        [[ $status -eq 1 ]]
        sed 's/\r$//' <<<"$output" | {
            tap_negative_check "$test" ''
            [[ $notok -eq 5 ]]
        }
    done
}

@test "TAP output crash" {
    if $is_asan; then
        skip "Crashing tests skipped with ASAN"
    fi

    # not all tests
    local -a crashtests=(selftest_abortinit selftest_abort selftest_sigsegv)
    if $is_windows; then
        crashtests+=(selftest_fastfail)
    fi
    ulimit -Sc 0                # disable core dumps
    for test in ${crashtests[@]}; do
        run $SANDSTONE --output-format=tap --no-triage --selftests --retest-on-failure=0 --on-crash=kill -e $test -o /dev/null -v
        [[ $status -eq 1 ]]
        sed 's/\r$//; /^wine: Unhandled/d' <<<"$output" | \
            tap_negative_check "$test" ' (Killed|Core Dumped):.*'
    done
}

@test "TAP output OS error" {
    run $SANDSTONE --output-format=tap --no-triage --selftests --retest-on-failure=0 --on-crash=kill -e selftest_oserror -o /dev/null -v
    [[ $status -eq 2 ]]
    sed 's/\r$//' <<<"$output" | \
        tap_negative_check selftest_oserror ' Operating system error:.*' "exit: invalid"
}

@test "TAP silent output" {
    opts="--output-format=tap --quick --selftests --quiet --disable=mce_check -e @positive"
    $SANDSTONE $opts > $BATS_TEST_TMPDIR/output.tap

    sed -i -e 's/\r$//' $BATS_TEST_TMPDIR/output.tap
    {
        read line
        echo line 1: $line
        [[ "$line" = "# ${SANDSTONE##*/} $opts" ]]

        read line
        echo line 2: $line
        [[ "$line" = "Ran "*" tests without error"* ]]

        read line
        echo line 3: $line
        [[ "$line" = "exit: pass" ]]

        # There's no line 4
        ! read line
    } < $BATS_TEST_TMPDIR/output.tap
}

@test "YAML silent output" {
    opts="-Y --quick --selftests --quiet --disable=mce_check -e @positive"
    $SANDSTONE $opts > $BATS_TEST_TMPDIR/output.yaml

    sed -i -e 's/\r$//' $BATS_TEST_TMPDIR/output.yaml
    {
        read line
        echo line 1: $line
        [[ "$line" = "command-line: '${SANDSTONE##*/} $opts'" ]]

        read line
        echo line 2: $line
        [[ "$line" = "version: "* ]]

        read line
        echo line 3: $line

        [[ "$line" = "exit: pass" ]]

        # There's no line 4
        ! read line
    } < $BATS_TEST_TMPDIR/output.yaml
}

@test "YAML header output" {
    declare -A yamldump
    local args="-e selftest_pass -Y4 -e selftest_skip -t 1234 --timeout=12345"
    sandstone_selftest $args    # yes, no quotes
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/command-line" ".* $args"
    test_yaml_regexp "/version" '.*'

    local os=`uname -sr`
    if [[ "$SANDSTONE" = "wine "* ]] || [[ "$os" = MINGW* ]]; then
        os=`wine cmd /c ver | sed -n "s/\r$//;s/.*Windows /Windows v/p"`
    fi
    [[ "${yamldump[/os]}" = "$os"* ]]
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

    # check some more timing parse
    sandstone_selftest -e selftest_pass -t 12ms --timeout 20s
    [[ "$status" -eq 0 ]]
    test_yaml_numeric "/timing/duration" 'value == 12'
    test_yaml_numeric "/timing/timeout" 'value == 20000'

    sandstone_selftest -e selftest_pass -t 1min --timeout 5h
    [[ "$status" -eq 0 ]]
    test_yaml_numeric "/timing/duration" 'value == 60000'
    test_yaml_numeric "/timing/timeout" 'value == 5*60*60*1000'
}

@test "obey taskset single" {
    if $is_windows; then
        skip "taskset does not apply to Windows"
    fi
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
    if $is_windows; then
        skip "taskset does not apply to Windows"
    fi
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
    run_sandstone_yaml -vvv --max-test-loop-count=1 --no-slicing --selftests -e selftest_timedpass

    test_yaml_numeric "/tests/0/threads@len" "value == $nproc / 2 + 1"
    for ((i = 0; i < nproc/2; ++i)); do
        test_yaml_numeric "/cpu-info/$i/logical" "(value % 2) == 0"
    done

    # Verify there are no more CPUs:
    [[ "${yamldump[/cpu-info/$i/logical]-unset}" = unset ]]
}

selftest_pass() {
    declare -A yamldump
    sandstone_selftest "$@"
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

@test "selftest_pass" {
    selftest_pass -e selftest_pass
}

@test "selftest_pass wildcard" {
    # This should NOT run selftest_pass_low_quality
    declare -A yamldump
    selftest_pass -e 'selftest_pass*'
    [[ ${yamldump[/tests]} != *selftest_pass_low_quality* ]]
}

@test "selftest_pass_low_quality" {
    # This should NOT run selftest_pass_low_quality
    declare -A yamldump
    selftest_pass -e 'selftest_pass_low_quality' -e selftest_pass
    [[ ${yamldump[/tests]} != *selftest_pass_low_quality* ]]
}

@test "selftest_skip" {
    declare -A yamldump
    sandstone_selftest -e selftest_skip
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_skip
    test_yaml_regexp "/tests/0/result" skip
    i=$((-1 + yamldump[/tests/0/threads/0/messages@len]))
    test_yaml_regexp "/tests/0/threads/0/messages/$i/level" info
    test_yaml_regexp "/tests/0/threads/0/messages/$i/text" '.*skip.*'
}

@test "selftest_log_skip_init" {
    declare -A yamldump
    sandstone_selftest -e selftest_log_skip_init
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_log_skip_init
    test_yaml_regexp "/tests/0/result" skip
    test_yaml_regexp "/tests/0/skip-category" SelftestSkipCategory
    test_yaml_regexp "/tests/0/skip-reason" '.*skip.*'
}

@test "selftest_log_skip_run_all_threads" {
    declare -A yamldump
    sandstone_selftest -e selftest_log_skip_run_all_threads
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_log_skip_run_all_threads
    test_yaml_regexp "/tests/0/result" skip
    test_yaml_regexp "/tests/0/skip-category" RuntimeSkipCategory
    test_yaml_regexp "/tests/0/skip-reason" '.*test_run().*'
    for ((i = 0; i < yamldump[/tests/0/threads@len]; ++i)); do
        test_yaml_regexp "/tests/0/threads/$i/messages/0/level" skip
        test_yaml_regexp "/tests/0/threads/$i/messages/0/text" '.*Skipping.*'
    done
}

@test "selftest_log_skip_run_even_threads" {
    declare -A yamldump
    sandstone_selftest -e selftest_log_skip_run_even_threads
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_log_skip_run_even_threads
    test_yaml_regexp "/tests/0/result" pass
    for ((i = 0; i < yamldump[/tests/0/threads@len]; ++i)); do
        test_yaml_regexp "/tests/0/threads/$i/messages/0/level" skip
        test_yaml_regexp "/tests/0/threads/$i/messages/0/text" '.*Skipping.*'
    done
}

@test "selftest_log_skip_newline" {
    declare -A yamldump
    sandstone_selftest -e selftest_log_skip_newline
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_log_skip_newline
    test_yaml_regexp "/tests/0/result" skip
    test_yaml_regexp "/tests/0/skip-category" SelftestSkipCategory
    test_yaml_regexp "/tests/0/skip-reason" $'.*\n.*\n.*'
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
        extract_from_yaml "/tests/$i/state/seed"
        [[ "$value" != "$last_seed" ]]
        last_seed=$value

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
    # Run the test twice to ensure one run doesn't clobber the next
    declare -A yamldump
    sandstone_selftest -e selftest_logs -e selftest_logs
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    check_test() {
        local testnr=$1
        test_yaml_regexp "/tests/$testnr/result" pass
        test_yaml_regexp "/tests/$testnr/threads/0/thread" main
        test_yaml_regexp "/tests/$testnr/threads/0/messages" '.*init function.*'
        for ((i = 1; i <= MAX_PROC; ++i)); do
            test_yaml_numeric "/tests/$testnr/threads/$i/thread" "value == $i - 1"
            test_yaml_regexp "/tests/$testnr/threads/$i/id" '\{.*\}'
            test_yaml_numeric "/tests/$testnr/threads/$i/loop-count" 'value == 0'
            test_yaml_regexp "/tests/$testnr/threads/$i/messages/0/level" '(debug|info|warning|error)'
            test_yaml_regexp "/tests/$testnr/threads/$i/messages/0/text" '.> .+'

            # Confirm some aspects of the messages
            test_yaml_regexp "/tests/$testnr/threads/$i/messages" '.*W> This is a .*warning.*'
            test_yaml_regexp "/tests/$testnr/threads/$i/messages" '.*I> This is a .*info.*'
            if $SANDSTONE --is-debug >/dev/null 2>/dev/null; then
                test_yaml_regexp "/tests/$testnr/threads/$i/messages" '.*d> This is a .*debug.*'
            fi
        done

        if ! $is_asan; then
            # ASAN builds don't catch stderr
            test_yaml_regexp "/tests/$testnr/stderr messages" '.* stderr .*'
        fi

        i=2
        [[ MAX_PROC -gt 1 ]] || i=1
        test_yaml_regexp "/tests/$testnr/threads/$i/messages" '.*message from cpu '$((i - 1))'.*'
    }
    check_test 0
    check_test 1
}

@test "selftest_logdata" {
    declare -A yamldump
    sandstone_selftest -e selftest_logdata
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/result" pass
    for ((i = 0; i < MAX_PROC; ++i)); do
        test_yaml_regexp "/tests/0/threads/$i/messages/0/level" info
        test_yaml_regexp "/tests/0/threads/$i/messages/0/text" '.*'
        test_yaml_regexp "/tests/0/threads/$i/messages/0/data" '[0-9a-f ]+'
    done
}

@test "selftest_logs_options" {
    run $SANDSTONE -n1 --selftests -e selftest_logs_options -O dummy=dummy
    if [[ $status == 64 ]]; then
       skip "Not supported"
    fi
    declare -A yamldump
    sandstone_selftest -vvv --max-messages=0 -e selftest_logs_options
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/result" pass

    # with no -O, there should be no test-options
    test_yaml_absent "/tests/0/test-options"

    # but there should be if we set something
    sandstone_selftest -vvv --max-messages=0 -e selftest_logs_options -O dummy=dummy
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/result" pass
    test_yaml_regexp "/tests/0/test-options/selftest_logs_options.StringValue" 'DefaultValue'
    test_yaml_regexp "/tests/0/test-options/selftest_logs_options.NullStringValue" None
    test_yaml_numeric "/tests/0/test-options/selftest_logs_options.UIntValue" 'value == 0'
    test_yaml_numeric "/tests/0/test-options/selftest_logs_options.IntValue" 'value == -1'
    test_yaml_numeric "/tests/0/test-options/selftest_logs_options.DoubleValue" 'value == 2.5'
    test_yaml_numeric "/tests/0/threads/0/messages@len" "value == 1"
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" '.*StringValue = DefaultValue'

    sandstone_selftest -vvv --max-messages=0 -e selftest_logs_options \
                       -O selftest_logs_options.NullStringValue=0x1 \
                       -O selftest_logs_options.UIntValue=0x1 \
                       -O selftest_logs_options.IntValue=0x1001 \
		       -O selftest_logs_options.DoubleValue=-8.125
    test_yaml_regexp "/tests/0/test-options/selftest_logs_options.StringValue" 'DefaultValue'
    test_yaml_regexp "/tests/0/test-options/selftest_logs_options.NullStringValue" "0x1"
    test_yaml_numeric "/tests/0/test-options/selftest_logs_options.UIntValue" 'value == 1'
    test_yaml_numeric "/tests/0/test-options/selftest_logs_options.IntValue" 'value == 4097'
    test_yaml_numeric "/tests/0/test-options/selftest_logs_options.DoubleValue" 'value == -8.125'
    test_yaml_numeric "/tests/0/threads/0/messages@len" "value == 4"
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" '.*StringValue = DefaultValue'
    test_yaml_regexp "/tests/0/threads/0/messages/1/text" '.*NullStringValue = 0x1'
    test_yaml_regexp "/tests/0/threads/0/messages/2/text" '.*Numbers: 1 4097'
    test_yaml_regexp "/tests/0/threads/0/messages/3/text" '.*Double: -8.125'
}

@test "selftest_logs_random_init" {
    declare -A yamldump
    sandstone_selftest -e selftest_logs_random_init -s Constant:1234
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" "I> 1234 1234 1234 1234"

    sandstone_selftest -e selftest_logs_random_init -s LCG:1348219713
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" "I> 421843888 386376794 2046232626 184745881"

    sandstone_selftest -e selftest_logs_random_init -s AES:87608d752b11fb972c8f0b4c19cdecf7789f728ad4ee0468d370f4b3e6321308
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" "I> 1242137224 1378217084 1525375882 474233533"
}

test_random() {
    if ! $is_debug; then
        skip "Test only works with Debug builds (to mock the topology)"
    fi
    local results=()
    local cpus=()
    seed=$1
    shift
    for cpu; do
        r=${random_results[$cpu]}
        [[ -n "$r" ]]
        results+=("$r")
        cpus+=($cpu)
    done

    declare -A yamldump
    SANDSTONE_MOCK_TOPOLOGY="${cpus[*]}" sandstone_selftest -e selftest_logs_random -s $seed
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    #test_yaml_regexp "/tests/0/result" pass
    #test_yaml_regexp "/tests/0/threads/0/messages/0/text" "I> [0-9]+ [0-9]+ [0-9]+ [0-9]+"

    # Compare the printed numbers to what was expected
    for ((i = 0; i < yamldump[/tests/0/threads@len]; ++i)); do
        numbers=${yamldump[/tests/0/threads/$i/messages/0/text]}
        numbers=${numbers#I> }
        if [[ "$numbers" != "${results[$i]}" ]]; then
            echo "Random numbers for CPU ${cpus[$i]} ($numbers) don't match expected (${results[$i]})" >&2
            false
        fi
    done
}

@test "selftest_logs_random_lcg" {
    local -Ar random_results=(
        [0:0:0]="2008263207 1313955870 34286625 1487267185"
        [0:0:1]="1704585366 1204267381 955907608 1782506326"
        [0:1:0]="1719058115 1886149085 1585783823 316322718"
        [0:1:1]="151737293 1591634133 1396278971 1007948046"
        [0:2:0]="1775100370 1272444970 2011359023 428234716"
        [0:3:0]="1929298235 1379265883 107930352 110693770"
        [1:0:0]="1694270094 1491978773 1295765691 296967739"
        [2:0:0]="566941671 1457287120 1732228388 1973237556"
        [3:0:0]="235862816 1523178389 1946393080 1930808430"
    )

    # Mocking 4 sockets of 1 core each
    test_random LCG:1348219713 0:0:0 1:0:0 2:0:0 3:0:0

    # Mocking 1 socket of 4 single-thread cores
    test_random LCG:1348219713 0:0:0 0:1:0 0:2:0 0:3:0

    # Mocking 1 socket of 4 hyperthreaded cores
    test_random LCG:1348219713 0:0:0 0:0:1 0:1:0 0:1:1
}

@test "selftest_logs_random_aes" {
    local -r SEED=AES:87608d752b11fb972c8f0b4c19cdecf7789f728ad4ee0468d370f4b3e6321308
    local -Ar random_results=(
        [0:0:0]="1442152966 848034066 1178242204 1152613460"
        [0:0:1]="801863574 1764783886 468436526 1150421294"
        [0:1:0]="1318899296 1591921602 1551294054 1334527618"
        [0:1:1]="517627017 379261874 2001880952 937361294"
        [0:2:0]="1041439551 1150890517 375859362 2139318920"
        [0:3:0]="563921477 676951712 16315069 1235380647"
        [1:0:0]="672773493 1071973933 867607355 1164627367"
        [2:0:0]="65707667 538845702 2142028653 158189198"
        [3:0:0]="647518054 617961218 490776568 784171714"
    )

    # Mocking 4 sockets of 1 core each
    test_random $SEED 0:0:0 1:0:0 2:0:0 3:0:0

    # Mocking 1 socket of 4 single-thread cores
    test_random $SEED 0:0:0 0:1:0 0:2:0 0:3:0

    # Mocking 1 socket of 4 hyperthreaded cores
    test_random $SEED 0:0:0 0:0:1 0:1:0 0:1:1
}

test_list_file() {
    local -a list=("$@")
    local -i count=${#list[@]}
    declare -A yamldump

    local testlistfile=`mktempfile list.XXXXXX`
    echo "=== test list ==="
    printf '%s\n' "${list[@]}" | tee "$testlistfile"
    echo "=== ==="

    sandstone_selftest --test-list-file "$testlistfile"
    rm -f -- "$testlistfile"
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
            if (( 2 * duration < yamldump[/timing/duration] )); then
               test_yaml_numeric "/tests/$i/test-runtime" "value <= "${yamldump[/timing/duration]}
            fi
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

test_list_randomize() {
    declare -A yamldump
    local -a list=(
        # These tests should run instantly
        selftest_pass
        selftest_logs
        selftest_logdata
        selftest_log_platform
        selftest_logs_options
        selftest_skip
    )
    list+=(${list[@]})          # 2x
    list+=(${list[@]})          # 4x

    local testmode=$1
    shift
    if [[ "$testmode" = "--test-list-file" ]]; then
        local testlistfile=`mktempfile list.XXXXXX`
        echo "=== test list ==="
        printf '%s\n' ${list[@]} | tee "$testlistfile"
        echo "=== ==="

        sandstone_selftest --test-list-file "$testlistfile" "$@"
        rm -f -- "$testlistfile"
    elif [[ "$testmode" = "-e" ]]; then
        local cmdline=`printf -- '-e %s ' ${list[@]}`
        sandstone_selftest $cmdline "$@"
    else
        echo >&2 "Don't know what to do with argument: $testmode"
        false
    fi

    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass

    # confirm all tests ran
    test_yaml_numeric "/tests@len" ${#list[@]}

    # collect test names that ran
    local -a executedlist=()
    for ((i = 0; i < yamldump[/tests@len]; ++i)); do
        executedlist+=${yamldump[/tests/$i/test]}
    done

    # confirm we didn't run in the original order
    # (in theory, randomness could produce that, but it's unlikely)
    echo "Executed list: ${executedlist[*]}"
    [[ "${list[*]}" != "${executedlist[*]}" ]]
}

@test "--test-list-file --test-list-randomize" {
    test_list_randomize --test-list-file
}

test_list_file_ignores_beta() {
    declare -A yamldump
    local -a list=(selftest_pass selftest_pass_low_quality
                   selftest_skip selftest_pass selftest_logs)

    local testlistfile=`mktempfile list.XXXXXX`
    echo "=== test list ==="
    printf '%s\n' ${list[@]} | tee "$testlistfile"
    echo "=== ==="

    sandstone_selftest --test-list-file "$testlistfile" "$@"
    rm -f -- "$testlistfile"
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass

    # confirm all but one of these tests ran
    test_yaml_numeric "/tests@len" "${#list[@]} - 1"

    # and that none of them is the low_quality one
    for ((i = 0; i < yamldump[/tests@len]; ++i)); do
        [[ ${yamldump[/tests/test]} != "selftest_pass_low_quality" ]]
    done
}

@test "--test-list-file ignores beta test" {
    test_list_file_ignores_beta
}

@test "--test-list-file --test-list-randomize ignores beta test" {
    test_list_file_ignores_beta --test-list-randomize
}

@test "--test-list-file with unknown test name" {
    # This doesn't produce valid YAML output, so run directly
    local name=`mktemp -u selftest_XXXXXX`
    local testlistfile=`mktempfile list.XXXXXX`

    echo "$name" > $testlistfile
    run $SANDSTONE -Y -o - --selftests --test-list-file "$testlistfile"
    rm -f -- "$testlistfile"

    echo "$output"
    [[ $status -eq 64 ]]        # exit(EX_USAGE)
    grep -qwF "$name" <<<"$output"
}

@test "--test-list-randomize" {
    test_list_randomize -e
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

@test "selftest_failinit_socket1 --max-cores-per-slice" {
    declare -A yamldump
    test_fail_socket1 sandstone_selftest -e selftest_failinit_socket1 --max-cores-per-slice=2
    [[ "$status" -eq 1 ]]
    test_yaml_regexp "/exit" fail
    test_yaml_regexp "/tests/0/result" fail
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
    [[ "${yamldump[/tests/0/fail/seed]}" = "${yamldump[/tests/0/state/seed]}" ]]
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
        extract_from_yaml "/tests/$i/state/seed"
        [[ "$value" = "${yamldump[/tests/0/fail/seed]}" ]]
        # reporting correctly
        test_yaml_regexp "/tests/$i/state/retry" True
        test_yaml_numeric "/tests/$i/state/iteration" "value == $i"
    done
    grep -e '# Test failed 4 out of 4' /tmp/output.yaml

    # confirm it retested - second selftest_fail
    for ((i = 5; i <= 6; ++i)); do
        # same test
        test_yaml_regexp "/tests/$i/test" selftest_fail
        # with the same RNG seed
        extract_from_yaml "/tests/$i/state/seed"
        [[ "$value" = "${yamldump[/tests/4/fail/seed]}" ]]
        # reporting correctly
        test_yaml_regexp "/tests/$i/state/retry" True
        test_yaml_numeric "/tests/$i/state/iteration" "value == $i - 4"
    done
    grep -e '# Test failed 3 out of 3' /tmp/output.yaml
}

selftest_fail_socket1_common() {
    declare -A yamldump
    test_fail_socket1 sandstone_selftest -e selftest_fail_socket1 "$@"
    [[ "$status" -eq 1 ]]
    test_yaml_regexp "/exit" fail
    test_yaml_regexp "/tests/0/result" fail

    # only one socket should have failed
    test_yaml_regexp "/tests/0/threads/0/id/package" 1
    test_yaml_regexp "/tests/0/threads/0/state" "failed"
    test_yaml_regexp "/tests/0/threads/0/thread" 2
}

@test "selftest_fail_socket1" {
    selftest_fail_socket1_common
}
@test "selftest_fail_socket1 --max-cores-per-slice" {
    selftest_fail_socket1_common --max-cores-per-slice=2
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
            test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/address" '(0x)?[0-9a-f]+'
            test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/actual" "$dataregexp"
            test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/expected" "$dataregexp"
            test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/mask" '0x[0-9a-f]+'
            test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/actual data" '[0-9a-f ]+'
            test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/expected data" '[0-9a-f ]+'
        done
    done
}

@test "selftest_datacompare_nodifference" {
    declare -A yamldump
    sandstone_selftest -vvv -e selftest_datacompare_nodifference
    fail_common
    for ((i = 1; i <= MAX_PROC; ++i)); do
        test_yaml_regexp "/tests/0/threads/$i/messages/0/level" error
        test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/type" 'uint8_t'
        test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/offset" None
        test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/address" '(0x)?[0-9a-f]+'
        test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/actual" None
        test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/expected" None
        test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/mask" None
        test_yaml_regexp "/tests/0/threads/$i/messages/0/data-miscompare/remark" '.+'
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

selftest_freeze_socket1_common() {
    declare -A yamldump
    test_fail_socket1 sandstone_selftest -vvv --on-crash=kill --on-hang=kill -e selftest_freeze_socket1 --timeout=1s
    [[ "$status" -eq 2 ]]
    test_yaml_regexp "/exit" invalid
    test_yaml_regexp "/tests/0/result" 'timed out'
    test_yaml_numeric "/tests/0/test-runtime" 'value >= 1000'

    # only one socket should have frozen
    for ((i = 1; i <= yamldump[/tests/0/threads@len]; ++i)); do
        if [[ "${yamldump[/tests/0/threads/$i/id/package]}" = 1 ]]; then
            test_yaml_regexp "/tests/0/threads/$i/state" failed
            n=$((-1 + yamldump[/tests/0/threads/$i/messages@len]))
            test_yaml_regexp "/tests/0/threads/$i/messages/$n/text" '.*Thread is stuck'
        else
            [[ "${yamldump[/tests/0/threads/$i/state]}" != failed ]]
        fi
    done
}

@test "selftest_freeze_socket1" {
    selftest_freeze_socket1_common
}
@test "selftest_freeze_socket1 --max-cores-per-slice" {
    selftest_freeze_socket1_common --max-cores-per-slice=2
}

selftest_crash_common() {
    if $is_asan; then
        skip "Crashing tests skipped with ASAN"
    fi
    if ! declare -p yamldump >/dev/null 2>/dev/null; then
        declare -A yamldump
    fi

    local test=$1
    local code=$2
    local reason=$3
    if $is_windows; then
        code=$4
        reason=$5
    else
        # transform symbolic name to code
        code=$(kill -l $code)
    fi
    if [[ "$code" == "" ]]; then
        skip "Test skipped on this platform"
    fi

    sandstone_selftest --on-crash=kill -vvv -e $test
    [[ "$status" -eq 1 ]]
    test_yaml_regexp "/exit" fail
    test_yaml_regexp "/tests/0/result" "crash"
    test_yaml_regexp "/tests/0/result-details/crashed" True
    test_yaml_regexp "/tests/0/result-details/core-dump" '(True|False)'
    test_yaml_numeric "/tests/0/result-details/code" 'value > 0 && value == '$code
    test_yaml_regexp "/tests/0/result-details/reason" "$reason"
}

@test "selftest_abortinit" {
    selftest_crash_common selftest_abortinit SIGABRT "Aborted" 0xC0000602 "Aborted"
}

@test "selftest_abort" {
    selftest_crash_common selftest_abort SIGABRT "Aborted" 0xC0000602 "Aborted"
}

@test "selftest_sigill" {
    selftest_crash_common selftest_sigill SIGILL "Illegal instruction" 0xC000001D "Illegal instruction"
}

@test "selftest_sigfpe" {
    selftest_crash_common selftest_sigfpe SIGFPE "Floating point exception" 0xC0000094 'Integer division by zero'
}

@test "selftest_sigbus" {
    selftest_crash_common selftest_sigbus SIGBUS "Bus error"
}

@test "selftest_sigsegv_init" {
    selftest_crash_common selftest_sigsegv SIGSEGV "Segmentation fault" 0xC0000005 'Access violation'
}

@test "selftest_sigsegv" {
    selftest_crash_common selftest_sigsegv SIGSEGV "Segmentation fault" 0xC0000005 'Access violation'
}

@test "selftest_sigsegv_cleanup" {
    selftest_crash_common selftest_sigsegv SIGSEGV "Segmentation fault" 0xC0000005 'Access violation'
}

@test "selftest_sigsegv_instruction" {
    selftest_crash_common selftest_sigsegv_instruction SIGSEGV "Segmentation fault" 0xC0000005 'Access violation'
}

@test "selftest_fastfail" {
    if ! $is_windows; then
        skip "Windows-only test"
    fi

    # I don't know *why* we get this error, but we do
    selftest_crash_common selftest_fastfail x x 0xC0000409 "Stack buffer overrun"
}

@test "selftest_sigkill" {
    if $is_windows; then
        skip "Unix-only test"
    fi
    declare -A yamldump
    sandstone_selftest -vvv -e selftest_sigkill
    [[ "$status" -eq 2 ]]
    test_yaml_regexp "/exit" invalid    # interpreted as OOM killer
    test_yaml_regexp "/tests/0/result-details/crashed" True
    test_yaml_regexp "/tests/0/result-details/core-dump" '(True|False)'
    test_yaml_numeric "/tests/0/result-details/code" 'value > 0 && value == 9'
    test_yaml_regexp "/tests/0/result-details/reason" Killed
}

@test "selftest_sigkill --ignore-os-error" {
    if $is_windows; then
        skip "Unix-only test"
    fi
    declare -A yamldump
    sandstone_selftest -vvv -e selftest_sigkill --ignore-os-error
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/result-details/crashed" True
    test_yaml_regexp "/tests/0/result-details/reason" Killed
}

@test "selftest_malloc_fail" {
    declare -A yamldump
    selftest_crash_common selftest_malloc_fail SIGABRT "Aborted" 0xC0000017 "Out of memory condition"
    test_yaml_regexp "/tests/0/stderr messages" 'Out of memory condition'
}

selftest_crash_context_common() {
    if $is_asan; then
        skip "Crashing tests skipped with ASAN"
    fi
    if $is_windows; then
        skip "Backtrace functionality not available on Windows"
    fi
    if [[ `uname -r` = *-azure ]]; then
        skip "GitHub Hosted Actions somehow make this impossible"
    fi

    local signum=`kill -l SEGV`
    sandstone_selftest "$@"
    [[ "$status" -eq 1 ]]
    test_yaml_regexp "/exit" fail
    test_yaml_regexp "/tests/0/result" "crash"
    test_yaml_regexp "/tests/0/result-details/crashed" True

    local threadidx=$((yamldump[/tests/0/threads@len] - 1))
    test_yaml_regexp "/tests/0/threads/$threadidx/state" "failed"
    test_yaml_regexp "/tests/0/threads/$threadidx/messages/0/level" "error"
    test_yaml_regexp "/tests/0/threads/$threadidx/messages/0/text" ".*Received signal $signum \((Segmentation fault|Access violation)\) code=[0-9]+.* RIP = 0x.*"

    if [[ `uname -m` = x86_64 ]]; then
        # OpenDCDiag's built-in register dumper is only implemented for x86-64
        msgidx=$((yamldump[/tests/0/threads/$threadidx/messages@len] - 1))
        test_yaml_regexp "/tests/0/threads/$threadidx/messages/$msgidx/level" "info"
        test_yaml_regexp "/tests/0/threads/$threadidx/messages/$msgidx/text" "Registers:"
        test_yaml_regexp "/tests/0/threads/$threadidx/messages/$msgidx/text" " rax += 0x[0-9a-f]{16}.*"
    fi
}

@test "crash context" {
    declare -A yamldump
    selftest_crash_context_common -n1 -e selftest_sigsegv --on-crash=context

    # Ensure we can use this option even if gdb isn't found
    # (can't use run_sandstone_yaml here because we empty $PATH)
    (
        PATH=
        run $SANDSTONE -Y --selftests -e selftest_sigsegv --retest-on-failure=0 --on-crash=context -o - >/dev/null
        [[ $status -eq 1 ]]     # instead of 64 (EX_USAGE)
    )
}

crash_context_socket1_common() {
    declare -A yamldump
    test_fail_socket1 selftest_crash_context_common -e selftest_sigsegv_socket1 --on-crash=context "$@"

    # only one socket should have crashed
    local threadidx=$((yamldump[/tests/0/threads@len] - 1))
    test_yaml_numeric "/tests/0/threads/$threadidx/id/package" 'value == 1'
}

@test "crash context socket1" {
    crash_context_socket1_common
}
@test "crash context socket1 --max-cores-per-slice" {
    crash_context_socket1_common  --max-cores-per-slice=1
}

@test "crash backtrace" {
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

    declare -A yamldump
    selftest_crash_context_common -n1 --timeout=5m -e selftest_sigsegv --on-crash=backtrace

    test_yaml_regexp "/tests/0/threads/0/messages/0/level" "info"
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" "Backtrace:.*"
    test_yaml_regexp "/tests/0/threads/1/messages/1/level" "warning"

    # The crashing instruction varies with the target architecture
    case `uname -m` in
        x86_64)
            test_yaml_regexp "/tests/0/threads/1/messages/1/text" ".*\bmov\b.*"
            ;;
        aarch64)
            test_yaml_regexp "/tests/0/threads/1/messages/1/text" ".*\bldr\b.*"
            ;;
    esac
}

@test "selftest_oserror" {
    declare -A yamldump
    sandstone_selftest --on-crash=kill -vvv -e selftest_oserror
    [[ "$status" -eq 2 ]]
    test_yaml_regexp "/exit" invalid
    test_yaml_regexp "/tests/0/result" "operating system error"
    test_yaml_regexp "/tests/0/result-details/crashed" False
    test_yaml_regexp "/tests/0/result-details/core-dump" False
    test_yaml_numeric "/tests/0/result-details/code" 'value == 78' # EX_CONFIG
    test_yaml_regexp "/tests/0/result-details/reason" "Operating system error: configuration error"
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

function selftest_cpuset() {
    local expected_logical=$1
    local expected_package=$2
    local expected_core=$3
    local expected_thread=$4
    shift 4

    declare -A yamldump
    sandstone_selftest -vvv -e selftest_skip "$@"
    [[ "$status" -eq 0 ]]
    test_yaml_numeric "/cpu-info/0/logical" "value == $expected_logical"
    test_yaml_numeric "/cpu-info/0/package" "value == $expected_package"
    test_yaml_numeric "/cpu-info/0/core" "value == $expected_core"
    test_yaml_numeric "/cpu-info/0/thread" "value == $expected_thread"
}

@test "cpuset=number (first)" {
    # Get the first logical processor
    local -a cpuinfo=(`$SANDSTONE --dump-cpu-info | sed -n '/^[0-9]/{p;q;}'`)
    selftest_cpuset ${cpuinfo[0]} ${cpuinfo[1]} ${cpuinfo[2]} ${cpuinfo[3]} --cpuset=${cpuinfo[0]}
}

@test "cpuset=number (last)" {
    # Get the last logical processor
    local -a cpuinfo=(`$SANDSTONE --dump-cpu-info | sed -n '$p'`)
    selftest_cpuset ${cpuinfo[0]} ${cpuinfo[1]} ${cpuinfo[2]} ${cpuinfo[3]} --cpuset=${cpuinfo[0]}
}

@test "cpuset=topology (first)" {
    # Get the first logical processor
    local -a cpuinfo=(`$SANDSTONE --dump-cpu-info | sed -n '/^[0-9]/{p;q;}'`)
    selftest_cpuset ${cpuinfo[0]} ${cpuinfo[1]} ${cpuinfo[2]} ${cpuinfo[3]} \
        --cpuset=p${cpuinfo[1]}c${cpuinfo[2]}t${cpuinfo[3]}
}

@test "cpuset=topology (last)" {
    # Get the last logical processor
    local -a cpuinfo=(`$SANDSTONE --dump-cpu-info | sed -n '$p'`)
    selftest_cpuset ${cpuinfo[0]} ${cpuinfo[1]} ${cpuinfo[2]} ${cpuinfo[3]} \
        --cpuset=p${cpuinfo[1]}c${cpuinfo[2]}t${cpuinfo[3]}
}

selftest_cpuset_unsorted() {
    local MAX_PROC=`nproc`
    local cpuset=$1
    shift
    declare -A yamldump
    sandstone_selftest -e selftest_skip --cpuset="$cpuset"
    [[ "$status" -eq 0 ]]

    # Get all the processor numbers
    i=0
    for expected_logical in `$SANDSTONE --dump-cpu-info | awk '/^[0-9]/ { print $1; }'`; do
        test_yaml_numeric "/cpu-info/$i/logical" "value == $expected_logical"
        i=$((i + 1))
    done
}

@test "cpuset=number (inverse order)" {
    # make a list in inverse order
    local -a cpuset=($($SANDSTONE --dump-cpu-info | sort -rn |
                           awk '/^[0-9]/ { printf "%d,", $1; }'))
    cpuset=${cpuset%,}          # remove last comma

    selftest_cpuset_unsorted "$cpuset" "${cpuinfo[@]}"
}

@test "cpuset=number (inverse sorted order)" {
    # sort the CPU list by package, then core then thread
    # This differs from the above on Linux, on hyperthreaded machines
    local -a cpuset=($($SANDSTONE --dump-cpu-info | sort -rnk2,3 |
                           awk '/^[0-9]/ { printf "%d,", $1; }'))
    cpuset=${cpuset%,}          # remove last comma

    selftest_cpuset_unsorted "$cpuset" "${cpuinfo[@]}"
}

# Confirm that we are roughly using the threads we said we would
@test "thread usage" {
    local -a cpuset=(`$SANDSTONE --dump-cpu-info | awk '/^[0-9]/ { print $1 }'`)
    nproc=${#cpuset[@]}
    if $is_windows && ((nproc > 64)); then
        skip "FIXME: Too many CPUs on Windows"
    fi

    # Don't use sandstone_selftest to avoid -n$MAX_PROC
    VALIDATION=dump
    declare -A yamldump
    run_sandstone_yaml --disable=mce_check --no-triage --selftests --timeout=20s --retest-on-failure=0 -e selftest_logs_getcpu

    # Did we get anything?
    if [[ ${yamldump[/tests/0/result]} = skip ]]; then
        skip "Test did not report results: ${yamldump/tests/0/threads/0/messages/0/text}"
    fi

    test_yaml_numeric "/tests/0/threads@len" "value == $nproc"
    for ((i = 0; i < yamldump[/tests/0/threads@len]; ++i)); do
        test_yaml_regexp "/tests/0/threads/$i/messages/0/text" "I> ${cpuset[$i]}\$"
    done
}
