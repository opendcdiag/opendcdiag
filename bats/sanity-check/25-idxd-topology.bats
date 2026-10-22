#!/usr/bin/bats
# -*- mode: sh -*-
# Copyright 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
load ../testenv
load helpers

setup_file() {
    [[ "$SANDSTONE_DEVICE_TYPE" = "IDXD" ]] || skip "Tests specific to IDXD"
}

# Writes the enabled WQs of device type $1 (dsa, iax; default: both) reported by accel-config as JSON to $expected_json
accel_config_wqs() {
    local type=${1-}
    local label=${type^^}
    label=${label:-IDXD}
    command -v accel-config >/dev/null 2>&1 || skip "accel-config not installed"
    local accel_error
    accel_error=$(accel-config list 2>&1 >/dev/null) || skip "accel-config list failed: $accel_error"
    command -v jq >/dev/null 2>&1 || skip "jq not installed"
    [[ -d /sys/bus/dsa/devices ]] || skip "No $label devices detected"

    local prefix devdir found=0
    for prefix in ${type:-dsa iax}; do
        for devdir in /sys/bus/dsa/devices/$prefix*; do
            [[ -d "$devdir" ]] || continue
            found=1
            break 2
        done
    done
    (( found )) || skip "No $label devices detected"

    local accel_json=$(mktempfile accel-XXXXXX.json)
    accel-config list > "$accel_json"
    expected_json=$(mktempfile expected-XXXXXX.json)
    jq --arg type "${type:-dsa|iax}" '[.[] as $device |
        ($device.dev | capture("^(" + $type + ")(?<id>[0-9]+)$") | .id | tonumber) as $device_id |
        $device.groups[]?.grouped_workqueues[]? |
        {
            device: $device.dev,
            device_id: $device_id,
            wq_id: (.dev | capture("wq[0-9]+\\.(?<id>[0-9]+)") | .id | tonumber),
            group_id: .group_id
        }
    ]' "$accel_json" > "$expected_json"

    # accel-config only reports enabled devices/WQs
    [[ "$(jq 'length' "$expected_json")" -gt 0 ]] || skip "No enabled $label work queues"
}

check_deviceset_type() {
    local type=$1
    local expected_json
    accel_config_wqs "$type"

    local yamlfile=$(mktempfile output-XXXXXX.yaml)
    "$SANDSTONE_BIN" -Y -o - -v --deviceset="$type" '--disable=*' > "$yamlfile"
    [[ "$?" -eq 0 ]]

    python3 "$BATS_TEST_COMMONDIR/check_idxd_topology.py" --exact "$expected_json" "$yamlfile"
}

@test "IDXD selftest topology matches accel-config" {
    local expected_json
    accel_config_wqs

    local yamlfile=$(mktempfile output-XXXXXX.yaml)
    "$SANDSTONE_BIN" \
        --on-crash=core --on-hang=kill --ignore-mce-errors \
        -Y -o - -vvv \
        --disable='@special' --selftests --timeout=20s --retest-on-failure=0 \
        -e selftest_pass > "$yamlfile"
    [[ "$?" -eq 0 ]]

    python3 "$BATS_TEST_COMMONDIR/check_idxd_topology.py" "$expected_json" "$yamlfile"
}

@test "IDXD --deviceset=dsa lists all DSA work queues" {
    check_deviceset_type dsa
}

@test "IDXD --deviceset=iax lists all IAX work queues" {
    check_deviceset_type iax
}

# Sets $wq_count and the arrays $wqs ("wqX.Y"), $wq_devices ("dsaX") and $cpus (allowed CPUs, ascending)
wq_cpu_pairing_setup() {
    local expected_json
    accel_config_wqs
    wq_count=$(jq 'length' "$expected_json")
    wqs=($(jq -r '.[] | "wq\(.device_id).\(.wq_id)"' "$expected_json"))
    wq_devices=($(jq -r '.[].device' "$expected_json"))
    cpus=($(python3 -c 'import os; print(*sorted(os.sched_getaffinity(0)))'))
}

# Runs with the given --deviceset options and checks device-info lists exactly
# the expected "<device>:<wq_id>:<cpu>" entries, in order.
# Usage: run_and_expect_device_info <deviceset>... -- <expected>...
run_and_expect_device_info() {
    local args=()
    while [[ "$1" != "--" ]]; do
        args+=(--deviceset="$1")
        shift
    done
    shift

    local yamlfile=$(mktempfile output-XXXXXX.yaml)
    "$SANDSTONE_BIN" -Y -o - -v "${args[@]}" '--disable=*' > "$yamlfile"
    [[ "$?" -eq 0 ]]

    python3 - "$yamlfile" "$@" <<'EOF'
import sys, yaml
path, *expected = sys.argv[1:]
entries = yaml.safe_load(open(path))['device-info']
actual = [f"{e['device']}:{e['wq']}:{e['logical_cpu']}" for e in entries]
if actual != expected:
    sys.exit(f'device-info mismatch:\n  expected: {expected}\n  actual:   {actual}')
EOF
}

@test "IDXD --deviceset pairs one WQ with multiple CPUs" {
    local wq_count wqs wq_devices cpus
    wq_cpu_pairing_setup

    # can't create more pairs than there are WQs in the system
    local n=$(( wq_count < ${#cpus[@]} ? wq_count : ${#cpus[@]} ))
    (( n > 4 )) && n=4
    (( n >= 2 )) || skip "Need at least 2 WQs and 2 CPUs"

    local deviceset= expected=() cpu
    for cpu in "${cpus[@]:0:n}"; do
        deviceset+="${deviceset:+,}${wqs[0]}c$cpu"
        expected+=("${wq_devices[0]}:${wqs[0]#*.}:$cpu")
    done

    run_and_expect_device_info "$deviceset" -- "${expected[@]}"
}

@test "IDXD --deviceset negation removes a single WQ:CPU pair" {
    local wq_count wqs wq_devices cpus
    wq_cpu_pairing_setup
    (( wq_count >= 3 && ${#cpus[@]} >= 3 )) || skip "Need at least 3 WQs and 3 CPUs"

    local wq=${wqs[0]} dev=${wq_devices[0]} id=${wqs[0]#*.}
    local c0=${cpus[0]} c1=${cpus[1]} c2=${cpus[2]}
    # removing the last pair, then the first, must leave the others untouched
    run_and_expect_device_info "${wq}c$c0,${wq}c$c1,${wq}c$c2" "!${wq}c$c2" -- \
        "$dev:$id:$c0" "$dev:$id:$c1"
    run_and_expect_device_info "${wq}c$c0,${wq}c$c1,${wq}c$c2" "!${wq}c$c0" -- \
        "$dev:$id:$c1" "$dev:$id:$c2"
}

@test "IDXD --deviceset negation of a WQ removes all its CPU pairs" {
    local wq_count wqs wq_devices cpus
    wq_cpu_pairing_setup
    (( wq_count >= 4 && ${#cpus[@]} >= 4 )) || skip "Need at least 4 WQs and 4 CPUs"

    local wqA=${wqs[0]} wqB=${wqs[1]}
    local c0=${cpus[0]} c1=${cpus[1]} c2=${cpus[2]} c3=${cpus[3]}
    run_and_expect_device_info "${wqA}c$c0,${wqA}c$c1,${wqA}c$c2,${wqB}c$c3" "!${wqA}" -- \
        "${wq_devices[1]}:${wqB#*.}:$c3"
}

@test "IDXD --deviceset ignores duplicate WQ:CPU pairs" {
    local wq_count wqs wq_devices cpus
    wq_cpu_pairing_setup
    (( wq_count >= 2 && ${#cpus[@]} >= 2 )) || skip "Need at least 2 WQs and 2 CPUs"

    local wq=${wqs[0]} dev=${wq_devices[0]} id=${wqs[0]#*.}
    local c0=${cpus[0]} c1=${cpus[1]}
    run_and_expect_device_info "${wq}c$c0,${wq}c$c1,${wq}c$c0" -- \
        "$dev:$id:$c0" "$dev:$id:$c1"
}
