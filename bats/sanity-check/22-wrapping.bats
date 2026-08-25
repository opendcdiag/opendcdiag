#!/usr/bin/bats
# -*- mode: sh -*-
# Copyright 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
load ../testenv
load helpers

function setup_file() {
    setup_sandstone
}

# The wrapper mechanism re-execs the child as program_invocation_name, which
# does not include any qemu/wine launcher prefix. Only run wrappers that must
# actually launch the tool when we are executing the binary directly.
function wrapper_skip_unless_direct() {
    if [[ "$SANDSTONE" != "$SANDSTONE_BIN" ]] &&
       [[ "$SANDSTONE" != "$SANDSTONE_BIN "* ]]; then
        skip "Not executing directly (executing '$SANDSTONE')"
    fi
}

@test "--wrapper-executable requires an argument" {
    run $SANDSTONE --wrapper-executable
    [[ $status -eq 64 ]]
    [[ "$output" == *"requires an argument"* ]]
}

@test "--wrapper-script requires an argument" {
    run $SANDSTONE --wrapper-script
    [[ $status -eq 64 ]]
    [[ "$output" == *"requires an argument"* ]]
}

@test "--wrapper-executable + --wrapper-script are incompatible" {
    run $SANDSTONE --selftests -e selftest_pass \
        --wrapper-executable env --wrapper-script 'exec "$0" "$@"'
    [[ $status -eq 64 ]]
    [[ "$output" == *"--wrapper-script is incompatible with other executable wrapper options"* ]]
}

@test "--wrapper-script + --wrapper-executable are incompatible" {
    run $SANDSTONE --selftests -e selftest_pass \
        --wrapper-script 'exec "$0" "$@"' --wrapper-executable env
    [[ $status -eq 64 ]]
    [[ "$output" == *"is incompatible with other executable wrapper options"* ]]
}

@test "--wrapper-script no-op wrapper runs the test" {
    declare -A yamldump
    wrapper_skip_unless_direct

    # A wrapper that just re-execs the tool must not change the result.
    sandstone_selftest -e selftest_pass --wrapper-script 'exec "$0" "$@"'
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/result" pass
}

@test "--wrapper-executable no-op wrapper runs the test" {
    declare -A yamldump
    wrapper_skip_unless_direct

    # env(1) execs its remaining arguments, i.e. the tool itself.
    sandstone_selftest -e selftest_pass --wrapper-executable env
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/result" pass
}

@test "executable wrapper forces exec fork-mode" {
    wrapper_skip_unless_direct

    # A wrapper is incompatible with any non-exec fork mode; the tool warns and
    # switches to -fexec instead of failing.
    run $SANDSTONE --selftests -e selftest_pass --quick -f no --wrapper-executable env
    [[ $status -eq 0 ]]
    [[ "$output" == *"--fork-mode=no is incompatible with executable wrappers; using -fexec"* ]]
}

@test "--wrapper-executable accumulates multiple arguments" {
    declare -A yamldump
    wrapper_skip_unless_direct

    # Each --wrapper-executable appends one argument to the wrapper command
    # line: `env FOO=bar <tool> ...`.
    sandstone_selftest -e selftest_pass \
        --wrapper-executable env --wrapper-executable FOO=bar
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/result" pass
}

@test "--wrapper-script is actually invoked" {
    declare -A yamldump
    wrapper_skip_unless_direct

    local marker=$BATS_TEST_TMPDIR/wrapper-script-marker
    rm -f "$marker"

    # Use the --opt=value form with single quotes and spaces in the script: the
    # whole argument must survive as one shell-recoverable token in the header.
    sandstone_selftest -e selftest_pass \
        "--wrapper-script=echo invoked > '$marker'; exec \"\$0\" \"\$@\""
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass

    # The command-line header must quote the whole --wrapper-script argument
    # (note the opening quote before "--wrapper-script") and escape the embedded
    # single quotes around the marker path as '\'' so the line is recoverable.
    test_yaml_regexp "/command-line" ".*'--wrapper-script=echo invoked > '\\\\''.*'\\\\''; exec.*"

    # The wrapper must have run before exec'ing the tool.
    [[ -f "$marker" ]]
    [[ "$(cat "$marker")" == invoked ]]
    rm -f "$marker"
}

@test "--wrapper-executable is actually invoked" {
    declare -A yamldump
    wrapper_skip_unless_direct
    if $is_windows; then
        skip "Shell scripts are not directly executable on Windows"
    fi

    local marker=$BATS_TEST_TMPDIR/wrapper-exec-marker
    local wrapper=$BATS_TEST_TMPDIR/wrapper-exec.sh
    rm -f "$marker"
    cat > "$wrapper" <<EOF
#!/bin/sh
echo invoked > "$marker"
exec "\$@"
EOF
    chmod +x "$wrapper"

    sandstone_selftest -e selftest_pass --wrapper-executable "$wrapper"
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass

    [[ -f "$marker" ]]
    [[ "$(cat "$marker")" == invoked ]]
    rm -f "$marker" "$wrapper"
}

@test "wrapper stderr is captured in stderr messages" {
    declare -A yamldump
    wrapper_skip_unless_direct

    # Anything the wrapper writes to stderr before exec'ing the tool must be
    # collected into the test's "stderr messages" field.
    sandstone_selftest -e selftest_pass \
        --wrapper-script 'echo WRAP_STDERR_MARKER >&2; exec "$0" "$@"'
    [[ "$status" -eq 0 ]]
    test_yaml_regexp "/exit" pass
    test_yaml_regexp "/tests/0/stderr messages" ".*WRAP_STDERR_MARKER.*"
}
