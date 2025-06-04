#!/usr/bin/bats
# -*- mode: sh -*-
# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
load ../testenv
load helpers

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
                "THIS IS AN UNOPTIMIZED BUILD"* | \
                "ok"*"mce_check")
                # acceptable line
                ;;
            "not ok"*)
                # inspect a little more
                if ! [[ "$line" =~ 'not ok '[\ 0-9]+\ ([^#\ ]+)\ *$suffix ]] ||
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
        run $SANDSTONE --output-format=tap --selftests --retest-on-failure=4 --on-crash=kill -e $test -o /dev/null -v
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
        run $SANDSTONE --output-format=tap --selftests --retest-on-failure=0 --on-crash=kill -e $test -o /dev/null -v
        [[ $status -eq 1 ]]
        sed 's/\r$//; /^wine: Unhandled/d' <<<"$output" | \
            tap_negative_check "$test" '# (Killed|Core Dumped):.*'
    done
}

@test "TAP output OS error" {
    run $SANDSTONE --output-format=tap --selftests --retest-on-failure=0 --on-crash=kill -e selftest_oserror -o /dev/null -v
    [[ $status -eq 2 ]]
    sed 's/\r$//' <<<"$output" | \
        tap_negative_check selftest_oserror '# Operating system error:.*' "exit: invalid"
}

@test "TAP silent output" {
    local -a opts=(--output-format=tap --quick --selftests --quiet --disable=mce_check --disable="*fork" -e @positive)
    $SANDSTONE "${opts[@]}" > $BATS_TEST_TMPDIR/output.tap

    sed -i -e 's/\r$//' $BATS_TEST_TMPDIR/output.tap
    {
        read line
        echo line 1: $line
        [[ "$line" = "# ${SANDSTONE##*/} ${opts[@]}" ]]

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
    local -a opts=(-Y --quick --selftests --quiet --disable=mce_check --disable="*fork" -e @positive)
    $SANDSTONE "${opts[@]}" > $BATS_TEST_TMPDIR/output.yaml

    sed -i -e 's/\r$//' $BATS_TEST_TMPDIR/output.yaml
    {
        read line
        echo line 1: $line
        [[ "$line" = "command-line: '${SANDSTONE##*/} ${opts[@]}'" ]]

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

    if $is_windows; then
        test_yaml_regexp "/os" 'Windows (Server )?v[0-9.]+'
        test_yaml_regexp "/runtime" 'MSVCRT|UCRT'
    else
        test_yaml_regexp "/os" "`uname -s` .*"
        [[ "${yamldump[/os]}" = "`uname -sr`" ]]    # exact match
        test_yaml_regexp "/runtime" '.*'            # free form, but must exist
    fi
    test_yaml_regexp "/openssl" "{'version':.*|None"
    test_yaml_numeric "/timing/duration" 'value == 1234'
    test_yaml_numeric "/timing/timeout" 'value == 12345'

    # just verify these exist
    for ((i = 0; i < MAX_PROC; ++i)); do
        if $is_windows; then
            test_yaml_numeric "/cpu-info/$i/logical-group" 'value >= 0'
        fi
        test_yaml_numeric "/cpu-info/$i/logical" 'value >= 0'
        test_yaml_numeric "/cpu-info/$i/package" 'value >= 0'
        test_yaml_numeric "/cpu-info/$i/numa_node" 'value >= -1'
        test_yaml_numeric "/cpu-info/$i/module" 'value >= 0'
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

selftest_pass() {
    declare -A yamldump
    sandstone_selftest "$@"
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_pass
    test_yaml_regexp "/tests/0/details/quality" production
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
    # This should run ONLY selftest_pass, not any of the others, not even mention them
    declare -A yamldump
    selftest_pass -e 'selftest_pass*'
    [[ ${yamldump[/tests]} != *selftest_pass_low_quality* ]]
    [[ ${yamldump[/tests]} != *selftest_pass_beta* ]]
    [[ ${yamldump[/tests]} != *selftest_pass_optional* ]]
}

@test "selftest_pass_beta" {
    # This should SKIP selftest_pass_beta
    declare -A yamldump
    sandstone_selftest -e selftest_pass_beta -e selftest_pass
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_pass_beta
    test_yaml_regexp "/tests/0/details/quality" beta
    test_yaml_regexp "/tests/0/result" skip
    test_yaml_regexp "/tests/0/skip-category" TestResourceIssue
    test_yaml_regexp "/tests/0/skip-reason" '.*BETA quality.*'
}

@test "selftest_pass_optional" {
    # This should RUN selftest_pass_optional
    declare -A yamldump
    sandstone_selftest -e selftest_pass_optional -e selftest_pass
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_pass_optional
    test_yaml_regexp "/tests/0/details/quality" production
    test_yaml_regexp "/tests/0/result" pass
}

@test "selftest_pass_low_quality" {
    # This should NOT run selftest_pass_low_quality
    declare -A yamldump
    selftest_pass -e 'selftest_pass_low_quality' -e selftest_pass
    [[ ${yamldump[/tests]} != *selftest_pass_low_quality* ]]
}

@test "selftest_pass group" {
    # This should run both selftest_pass and selftest_pass_optional,
    # skip selftest_pass_beta and not mention selftest_pass_low_quality
    declare -A yamldump
    sandstone_selftest -e '@selftest_passes'
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_pass
    test_yaml_regexp "/tests/0/result" pass
    test_yaml_regexp "/tests/1/test" selftest_pass_optional
    test_yaml_regexp "/tests/1/result" pass
    test_yaml_regexp "/tests/2/test" selftest_pass_beta
    test_yaml_regexp "/tests/2/result" skip
}

@test "selftest_cxxthrowcatch" {
    # Note: we want to test with the crash handler enabled (--on-crash)
    declare -A yamldump
    sandstone_selftest --on-crash=context -e selftest_cxxthrowcatch
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_cxxthrowcatch
    test_yaml_regexp "/tests/0/result" pass
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

@test "selftest_skip_minimum_cpu" {
    declare -A yamldump
    sandstone_selftest -e selftest_skip_minimum_cpu
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_skip_minimum_cpu
    test_yaml_regexp "/tests/0/result" skip
    test_yaml_regexp "/tests/0/skip-category" CpuNotSupported
    test_yaml_regexp "/tests/0/skip-reason" '.*test requires.*'
}

@test "selftest_log_skip_init" {
    declare -A yamldump
    sandstone_selftest -e selftest_log_skip_init
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_log_skip_init
    test_yaml_regexp "/tests/0/result" skip
    test_yaml_regexp "/tests/0/skip-category" Selftest
    test_yaml_regexp "/tests/0/skip-reason" '.*skip.*'
}

@test "selftest_skip_cleanup" {
    declare -A yamldump
    sandstone_selftest -e selftest_skip_cleanup
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_skip_cleanup
    test_yaml_regexp "/tests/0/result" skip
    test_yaml_regexp "/tests/0/skip-category" Runtime
    test_yaml_regexp "/tests/0/skip-reason" 'SKIP requested in cleanup'
}

@test "selftest_oserror_cleanup" {
    declare -A yamldump
    sandstone_selftest -e selftest_oserror_cleanup
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_oserror_cleanup
    test_yaml_regexp "/tests/0/result" skip
    test_yaml_regexp "/tests/0/skip-category" Runtime
    test_yaml_regexp "/tests/0/skip-reason" 'Unexpected OS error in cleanup.*'
}

@test "selftest_skipmsg_success_cleanup" {
    declare -A yamldump
    sandstone_selftest -e selftest_skipmsg_success_cleanup
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_skipmsg_success_cleanup
    test_yaml_regexp "/tests/0/result" skip
    test_yaml_regexp "/tests/0/skip-category" Selftest
    test_yaml_regexp "/tests/0/skip-reason" 'SUCCESS after skipmsg from cleanup'
}

@test "selftest_skipmsg_skip_cleanup" {
    declare -A yamldump
    sandstone_selftest -e selftest_skipmsg_skip_cleanup
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_skipmsg_skip_cleanup
    test_yaml_regexp "/tests/0/result" skip
    test_yaml_regexp "/tests/0/skip-category" Selftest
    test_yaml_regexp "/tests/0/skip-reason" 'SKIP after skipmsg from cleanup'
}

@test "selftest_log_skip_run_all_threads" {
    declare -A yamldump
    sandstone_selftest -e selftest_log_skip_run_all_threads
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/test" selftest_log_skip_run_all_threads
    test_yaml_regexp "/tests/0/result" skip
    test_yaml_regexp "/tests/0/skip-category" Runtime
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
    test_yaml_regexp "/tests/0/skip-category" Selftest
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

@test "selftest_timedpass -t 25 -T 250" {
    declare -A yamldump
    sandstone_selftest -e selftest_timedpass -t 25 -T 250
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    local test_count=${yamldump[/tests@len]}
    local i
    for ((i = 0; i < test_count; ++i)); do
        test_yaml_regexp "/tests/$i/result" pass
        test_yaml_numeric "/tests/$i/test-runtime" 'value >= 25'
    done
    test_yaml_numeric "/tests/$((i-1))/time-at-start/elapsed" 'value < 250'
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

@test "selftest_timedpass_no_fracture --max-test-loop-count=1" {
    # With just one loop, this should have very predictable timing
    declare -A yamldump
    sandstone_selftest -e selftest_timedpass_no_fracture --max-test-loop-count=1 -vvv
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/result" pass

    for ((i = 1; i <= MAX_PROC; ++i)); do
        test_yaml_numeric "/tests/0/threads/$i/loop-count" 'value == 1'
    done
}

@test "selftest_timedpass_no_fracture -t 250" {
    # With just one loop, this should have very predictable timing
    declare -A yamldump
    sandstone_selftest -e selftest_timedpass_no_fracture -t 250 -vvv
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/result" pass
    test_yaml_numeric "/tests/0/test-runtime" 'value >= 250'

    for ((i = 1; i <= MAX_PROC; ++i)); do
        test_yaml_numeric "/tests/0/threads/$i/loop-count" 'value > 1'
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

@test "--disable" {
    local expected=selftest_pass
    declare -A yamldump

    sandstone_selftest $($SANDSTONE --selftests --list-tests | sed -e /$expected/d -e 's/\r$//; s/^/--disable=/')
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass

    # Confirm we've run the test we expected to run
    test_yaml_regexp "/tests/0/test" selftest_pass
}

@test "wildcard --enable" {
    local tests=($($SANDSTONE --selftests --list-group-members @positive | sed -n '/^selftest_logs/{s/\r$//; p}'))
    [[ ${#tests[@]} -gt 0 ]]

    declare -A yamldump
    sandstone_selftest -e 'selftest_logs*'
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass

    # Confirm we've run the tests we expected to run
    test_yaml_numeric "/tests@len" 'value == '${#tests[@]}
    for ((i = 0; i < ${#tests[@]}; ++i)); do
        test_yaml_regexp "/tests/$i/test" "${tests[$i]}"
    done
}

@test "wildcard --disable" {
    declare -A yamldump

    # Note: order matters!
    sandstone_selftest --disable 'selftest_logs?*' -e 'selftest_logs*'
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass

    # Confirm we've run the test we expected to run
    test_yaml_regexp "/tests/0/test" selftest_logs
    test_yaml_numeric '/tests@len' 'value == 1'
}

@test "--ignore-unknown-tests" {
    local invalid_test=this_test_does_not_exist
    declare -A yamldump

    # Confirm it doesn't exist
    set -- -e $invalid_test -e selftest_pass
    run $SANDSTONE --selftest "$@"
    ((status == 64))
    [[ "$output" = *\'$invalid_test\'* ]]

    # Now check we can ignore it
    selftest_pass --ignore-unknown-test "$@"

    # Ditto on ignoring it
    selftest_pass --ignore-unknown-test --disable=$invalid_test "$@"
}

test_list_file_common() {
    declare -A yamldump
    local listcontents=$1
    local extraargs=()
    shift
    while [[ $# -gt 0 ]]; do
        if [[ "$1" = -- ]]; then
            shift
            break
        fi
        extraargs+=("$1")
        shift
    done

    local testlistfile=`mktempfile list.XXXXXX`
    echo "=== test list ==="
    printf "$listcontents" | tee "$testlistfile"
    echo "=== ==="

    sandstone_selftest --test-list-file "$testlistfile" "${extraargs[@]}"

    rm -f -- "$testlistfile"
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass

    # confirm each test
    local -i i=0
    local entry
    for entry; do
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

test_list_file() {
    local listcontents
    local -a expectedtests=()
    local arg
    for arg; do
        listcontents="$listcontents$arg\\n"
        arg=${arg%#*}
        if [[ "$arg" != "" ]]; then
            expectedtests+=("$arg")
        fi
    done
    test_list_file_common "$listcontents" -- "${expectedtests[@]}"
}

@test "--test-list-file with 1 test" {
    test_list_file selftest_pass
}

@test "--test-list-file with duplicate test" {
    test_list_file selftest_pass selftest_logs selftest_pass
}

@test "--test-list-file with optional test" {
    test_list_file selftest_pass selftest_pass_optional
}

@test "--test-list-file with duration" {
    test_list_file selftest_pass:default selftest_timedpass:250 selftest_timedpass:10 \
        '' 'selftest_timedpass: 10' '' "$(printf "selftest_timedpass:\t10")"
}

@test "--test-list-file with comments and empty lines" {
    test_list_file '# a file list' '' selftest_pass '' '# the end!'
}

@test "--test-list-file with --disable" {
    test_list_file_common 'selftest_pass\nselftest_logs' --disable=selftest_logs -- selftest_pass
}

@test "--test-list-file with wildcard --disable" {
    local testlist=$($SANDSTONE --selftests --list-group-members @positive |
                         grep '/selftest_logs/ { printf "%s\\n", $1 }')

    test_list_file_common "selftest_pass\\n$testlist" -- selftest_pass
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

@test "--test-list-file --ignore-unknown-test with unknown test name" {
    local name=`mktemp -u selftest_XXXXXX`
    test_list_file_common "selftest_pass\\n$name\\nselftest_logs" --ignore-unknown-tests -- \
                          selftest_pass selftest_logs
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
                   selftest_pass_beta selftest_pass_optional
                   selftest_skip selftest_pass selftest_logs)
    local -a not_to_run=(selftest_pass_low_quality selftest_pass_beta)

    local testlistfile=`mktempfile list.XXXXXX`
    echo "=== test list ==="
    printf '%s\n' ${list[@]} | tee "$testlistfile"
    echo "=== ==="

    sandstone_selftest --test-list-file "$testlistfile" "$@"
    rm -f -- "$testlistfile"
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass

    # confirm all but two of these tests ran
    test_yaml_numeric "/tests@len" "${#list[@]} - ${#not_to_run[@]}"

    # and that none of the ones we didn't want to run ran
    for ((i = 0; i < yamldump[/tests@len]; ++i)); do
        local norun
        for norun in "${not_to_run[@]}"; do
            [[ ${yamldump[/tests/test]} != "$norun" ]]
        done
    done
}

@test "--test-list-file ignores beta test" {
    test_list_file_ignores_beta
}

@test "--test-list-file --test-list-randomize ignores beta test" {
    test_list_file_ignores_beta --test-list-randomize
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

@test "selftest_logerror_init" {
    declare -A yamldump
    sandstone_selftest -e selftest_logerror_init
    [[ "$status" -eq 1 ]]
    test_yaml_regexp "/exit" fail
    i=$((0 + yamldump[/tests/0/threads@len]))
    [[ "$i" -eq 1 ]]
    test_yaml_regexp "/tests/0/threads/0/thread" 'main'
    test_yaml_regexp "/tests/0/threads/0/messages/0/level" error
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" 'E> Error logged in init.*'
}

@test "selftest_errormsg_cleanup" {
    declare -A yamldump
    sandstone_selftest -e selftest_errormsg_cleanup
    [[ "$status" -eq 1 ]]
    test_yaml_regexp "/exit" fail
    i=$((0 + yamldump[/tests/0/threads@len]))
    [[ "$i" -eq 1 ]]
    test_yaml_regexp "/tests/0/threads/0/thread" 'main'
    test_yaml_regexp "/tests/0/threads/0/messages/1/level" error
    test_yaml_regexp "/tests/0/threads/0/messages/1/text" 'E> Error logged in cleanup'
}

@test "selftest_fail_cleanup" {
    declare -A yamldump
    sandstone_selftest -e selftest_fail_cleanup
    [[ "$status" -eq 1 ]]
    test_yaml_regexp "/exit" fail
    i=$((0 + yamldump[/tests/0/threads@len]))
    [[ "$i" -eq 1 ]]
    test_yaml_regexp "/tests/0/threads/0/thread" 'main'
    test_yaml_regexp "/tests/0/threads/0/messages/1/level" info
    test_yaml_regexp "/tests/0/threads/0/messages/1/text" 'I> cleanup returns FAIL'
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
    grep -e '# Test failed 4 out of 4' $outputfile

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
    grep -e '# Test failed 3 out of 3' $outputfile
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
    test_yaml_numeric "/tests/0/threads/0/runtime" 'value >= 1000'
    if ! $is_windows; then
        test_yaml_regexp "/tests/0/threads/0/resource-usage" '\{.*\}'
    fi
    for ((i = 1; i <= MAX_PROC; ++i)); do
        test_yaml_regexp "/tests/0/threads/$i/state" failed
        n=$((-1 + yamldump[/tests/0/threads/$i/messages@len]))
        test_yaml_regexp "/tests/0/threads/$i/messages/$n/text" '.*Thread is stuck'
    done
}

@test "selftest_freeze_fork" {
    if $is_windows; then
        skip "Unix-only test"
    fi
    declare -A yamldump
    sandstone_selftest -vvv --on-crash=kill --on-hang=kill -e selftest_freeze_fork --timeout=1s
    [[ "$status" -eq 2 ]]
    test_yaml_regexp "/exit" invalid
    test_yaml_regexp "/tests/0/result" 'timed out'
    test_yaml_numeric "/tests/0/test-runtime" 'value >= 1000'
    test_yaml_numeric "/tests/0/threads/0/runtime" 'value >= 1000'
    if ! $is_windows; then
        test_yaml_regexp "/tests/0/threads/0/resource-usage" '\{.*\}'
    fi
    for ((i = 1; i <= MAX_PROC; ++i)); do
        test_yaml_regexp "/tests/0/threads/$i/state" failed
        n=$((-1 + yamldump[/tests/0/threads/$i/messages@len]))
        test_yaml_regexp "/tests/0/threads/$i/messages/$n/text" '.*Thread is stuck'

        # check that this child PID is *not* running
        local msg=/tests/0/threads/$i/messages/0/text
        test_yaml_regexp "$msg" '.*Child pid:.*'
        local pid=${yamldump[$msg]#I> Child pid: }
        if status=`ps ho s $pid`; then
            # PID still exists, but it might be a Zombie if we have no init at PID 1
            ps j "$pid"
            [[ $status = "Z" ]]
        fi
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

    local test=$1
    local code=$2
    if $is_windows; then
        code=$3
        reason=$4
    elif [[ "$code" != "" ]]; then
        # transform symbolic name to code
        reason=`python3 -c "from signal import *; print(strsignal($code)); exit($code)"` || code=$?
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
    # 0xC0000602 is STATUS_FAIL_FAST_EXCEPTION
    # 0xC0000409 is STATUS_STACK_BUFFER_OVERRUN, which is not a buffer overrun
    # - see https://devblogs.microsoft.com/oldnewthing/20190108-00/?p=100655
    #       https://devblogs.microsoft.com/oldnewthing/20080404-00/?p=22863
    selftest_crash_common selftest_abortinit SIGABRT '0xC0000602 || value == 0xC0000409' \
                          "Aborted|Program self-triggered abnormal termination"
}

@test "selftest_abort" {
    selftest_crash_common selftest_abort SIGABRT '0xC0000602 || value == 0xC0000409' \
                          "Aborted|Program self-triggered abnormal termination"
}

@test "selftest_sigill" {
    selftest_crash_common selftest_sigill SIGILL 0xC000001D "Illegal instruction"
}

@test "selftest_sigfpe" {
    selftest_crash_common selftest_sigfpe SIGFPE 0xC0000094 'Integer division by zero'
}

@test "selftest_sigbus" {
    selftest_crash_common selftest_sigbus SIGBUS
}

@test "selftest_sigsegv_init" {
    selftest_crash_common selftest_sigsegv SIGSEGV 0xC0000005 'Access violation'
}

@test "selftest_sigsegv" {
    selftest_crash_common selftest_sigsegv SIGSEGV 0xC0000005 'Access violation'
}

@test "selftest_sigsegv_cleanup" {
    selftest_crash_common selftest_sigsegv SIGSEGV 0xC0000005 'Access violation'
}

@test "selftest_sigsegv_instruction" {
    selftest_crash_common selftest_sigsegv_instruction SIGSEGV 0xC0000005 'Access violation'
}

@test "selftest_sigtrap_int3" {
    selftest_crash_common selftest_sigtrap_int3 SIGTRAP 0x80000003 'Breakpoint'
}

@test "selftest_fastfail" {
    if ! $is_windows; then
        skip "Windows-only test"
    fi

    selftest_crash_common selftest_fastfail ''  0xC0000409 "Program self-triggered abnormal termination"
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

@test "selftest_sigtrap_int3 --ignore-mce-error" {
    if ! $is_debug; then
        skip "Debug-only test"
    fi
    if $is_windows; then
        skip "Unix-only test"
    fi
    declare -A yamldump
    sandstone_selftest -vvv -e selftest_sigtrap_int3 --on-crash=context --ignore-mce-error
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/result" skip
    test_yaml_regexp "/tests/0/skip-category" IgnoredMceCategory
    test_yaml_regexp "/tests/0/skip-reason" "Debugging SIGTRAP"
    test_yaml_regexp "/tests/0/threads/2/messages/0/text" "W> MCE was delivered to or is related to this thread"
}

@test "selftest_malloc_fail" {
    declare -A yamldump
    selftest_crash_common selftest_malloc_fail SIGABRT 0xC0000017 "Out of memory condition"
    test_yaml_regexp "/tests/0/stderr messages" 'Out of memory condition'
}

@test "crash context" {
    declare -A yamldump
    selftest_crash_context_common -n1 -e selftest_sigsegv --on-crash=context

    # Ensure we can use this option even if gdb isn't found
    # (can't use run_sandstone_yaml here because we empty $PATH)
    if ! $is_windows; then (
        PATH=
        run $SANDSTONE -Y --selftests -e selftest_sigsegv --retest-on-failure=0 --on-crash=context -o - >/dev/null
        [[ $status -eq 1 ]]     # instead of 64 (EX_USAGE)
    ); fi
}

@test "crash backtrace" {
    check_gdb_usable
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

@test "num_cpus" {
    declare -A yamldump

    sandstone_selftest -e selftest_skip
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/tests/0/threads/0/messages/0/text" '.*"cpus":\s*'$MAX_PROC'\b.*'
}

selftest_interrupt_common() {
    local timeout=30000
    local signal=$1
    local -i signum=$(kill -l $signal)
    if $is_windows; then
        skip "Unix-only test"
    fi

    # We can't use sandstone_selftest or run_sandstone_yaml here - must run directly
    local yamlfile=`mktempfile output-XXXXXX.yaml`
    $SANDSTONE -Y -o - -n1 --max-test-loop-count=0 --selftests -e selftest_timedpass_fork -t $timeout > $yamlfile &
    local pid=$!

    # let's wait for the test to actually start
    sleep 1

    # now kill it, wait for it to finish, and capture the exit status
    kill -$signal $pid
    local -i exitcode=0
    wait $pid || exitcode=$?

    (echo ---; sed 's/\r$//' $yamlfile ) | \
        tee -a total_log_output.yaml # for bats' logger
    declare -A yamldump
    local structure=$(python3 $BATS_TEST_COMMONDIR/dumpyaml.py < $yamlfile)
    rm -f -- $yamlfile
    eval "yamldump=($structure)"

    # Confirm it was the correct signal
    if (( exitcode != (128 | signum) )); then
        echo >&2 'Incorrect exit code:' $exitcode
        false
    fi

    # Confirm the grandchild died too
    local msg=/tests/0/threads/0/messages/0/text
    test_yaml_regexp "$msg" '.*Child pid:.*'
    pid=${yamldump[$msg]#I> Child pid: }
    if status=`ps ho s $pid`; then
        # PID still exists, but it might be a Zombie if we have no init at PID 1
        ps j "$pid"
        [[ $status = "Z" ]]
    fi

    test_yaml_regexp "/exit" interrupted
    test_yaml_regexp "/tests/0/result" interrupted
    test_yaml_numeric "/tests/0/time-at-end/elapsed" "value < $timeout"
}

@test "interrupt-SIGHUP" {
    selftest_interrupt_common HUP
}
@test "interrupt-SIGINT" {
    selftest_interrupt_common INT
}
@test "interrupt-SIGTERM" {
    selftest_interrupt_common TERM
}

@test "idle injection" {
    declare -A yamldump
    for inject_idle in 0 10 20 30 40 50; do
        sandstone_selftest -e selftest_inject_idle --inject-idle $inject_idle
        [[ "$status" -eq 0 ]]
        test_yaml_regexp "/exit" pass
    done
}
