#!/bin/bash
# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

export ASAN_OPTIONS=malloc_fill_byte=0:detect_leaks=0:${ASAN_OPTIONS:+:$ASAN_OPTIONS}
BATS_TEST_COMMONDIR=${BASH_SOURCE[0]%/*}
is_asan=false
is_debug=false
is_windows=false
declare outputfile=""

MAX_PROC=`nproc`
[[ $MAX_PROC -le 4 ]] || MAX_PROC=4

if [[ -z "$SANDSTONE_BIN" ]]; then
    SANDSTONE_BIN=$BATS_TEST_COMMONDIR/../opendcdiag
fi
if [[ -z "$SANDSTONE" ]]; then
    SANDSTONE=$SANDSTONE_BIN
    if [[ `file $SANDSTONE_BIN` = *ELF* ]]; then
        current=`uname -m`
        [[ "$current" != "amd64" ]] || current=x86_64
        target=`eu-readelf -h $SANDSTONE_BIN | sed -n '/Machine:/{s/.* //;y/-/_/;p;q;}'`
        if [[ "${current,,}" != "${target,,}" ]]; then
            SANDSTONE="qemu-${target,,} $SANDSTONE"
        fi
        unset current target
    fi
fi
if [[ "$SANDSTONE_BIN" = *.exe ]]; then
    export is_windows=true
    if [[ `uname -s` = Linux ]]; then
        SANDSTONE="wine $SANDSTONE"
        export WINEDEBUG=-all
    fi
fi
SANDSTONE="$SANDSTONE --on-crash=core --on-hang=kill"

function setup()
{
    outputfile=
}

function teardown()
{
    rm -f /tmp/output.yaml /tmp/output.tap
    if [[ -f ./core ]]; then
        # Rename the core file so it won't get clobbered
        mv ./core core.batstest-${BATS_SUITE_TEST_NUMBER}
    fi
}

function setup_sandstone()
{
    if $SANDSTONE --is-debug-build >/dev/null 2>/dev/null; then
        export is_debug=true
    fi
    if $SANDSTONE --is-asan-build >/dev/null 2>/dev/null; then
        export is_asan=true
    fi
}

function mktempfile() {
    # find a temporary directory for us
    local tmpdir=$BATS_TEST_TMPDIR
    tmpdir=${tmpdir-$BATS_TMPDIR}
    tmpdir=${tmpdir-$TMPDIR}
    tmpdir=${tmpdir-/tmp}
    TMPDIR=$tmpdir mktemp --tmpdir "$@"
}

function run_sandstone_yaml_post()
{
    # any test may override
    :
}

function run_sandstone_yaml()
{
    local is_selftest=1
    [[ " $* " == *" --selftests "* ]] || is_selftest=0

    # bats' "run" function would help, but it fails on older bats...
    local yamlfile=`mktempfile output-XXXXXX.yaml`
    outputfile=`mktempfile output-XXXXXX.yaml`
    local command="$SANDSTONE -Y -o - \"\$@\" >&3; echo \$?"
    if [[ -n "$TASKSET" ]]; then
        command="taskset ${TASKSET} $command"
    fi
    local sss=$(bash -xc "$command" argv0 "$@" 3> $yamlfile)

    # Strip CR from CRLF
    sed 's/\r$//' $yamlfile > $outputfile
    rm -- $yamlfile
    (echo ---; cat $outputfile) | \
        tee -a total_log_output.yaml # for bats' logger

    local exit=$(sed -En '/^ *exit: (.*)$/s//\1/p' $outputfile)
    # confirm exit status
    case "$exit" in
        pass) expected=0 ;;
        fail) expected=1 ;;
        invalid) expected=2 ;;
        *)
            printf 'Tool exited with unknown "exit: %s"\n' "$exit"
            return 1
            ;;
    esac
    if [[ "$sss" -ne $expected ]]; then
        printf 'Tool had "exit: %s" but exit code was %d (expected %d)\n' $exit $sss $expected
        return 1
    fi

    if [[ -z "$VALIDATION" ]]; then
        VALIDATION=1
        if declare -p yamldump > /dev/null 2>&1; then
            VALIDATION=dump
        fi
    fi

    if [[ "$VALIDATION" = "dump" ]]; then
        # Load the YAML structure into the $yamldump associative array variable
        declare -p yamldump > /dev/null # errors out if variable is not pre-declared
        local structure=$(python3 $BATS_TEST_COMMONDIR/dumpyaml.py < $outputfile)
        eval "yamldump=($structure)"
    fi
    if [[ "$VALIDATION" != 0 ]]; then
        python3 $BATS_TEST_COMMONDIR/yamltest.py $outputfile
    fi
    if type -p yq > /dev/null; then
        # detect which yq tool we have
        local out=`yq . <<<"a: b" 2>/dev/null`
        if [[ "$out" = "a:"* ]]; then
            # the one from https://mikefarah.gitbook.io/yq/
            yq -ojson .
        else
            # the one from https://github.com/kislyuk/yq
            yq .
        fi > ${outputfile%.yaml}.json < $outputfile
    fi
    run_sandstone_yaml_post
    status=$sss
}

function sandstone_yq()
{
    type -p yq > /dev/null || skip "yq not installed"
    run_sandstone_yaml "$@"
}

function query_jq()
{
    local json=${outputfile%.yaml}.json
    if ! [[ -r $json ]]; then
        false "Cannot find output contents. Did you run a query using sandstone_yq?"
    fi

    local -a args=()
    while [[ $# ]]; do
        if ! [[ "$1" = -* ]]; then
            break
        fi
        args+=($1)
        shift
    done
    if (( $# == 1 )); then
        jq < $json "${args[@]}" "$@"
    else
        jq < $json "${args[@]}" -e "($1) == $2"
    fi
}

setup_sandstone

if [[ -n "$BATS_EXTRA_TESTENV" ]]; then
    . "$BATS_EXTRA_TESTENV"
fi
