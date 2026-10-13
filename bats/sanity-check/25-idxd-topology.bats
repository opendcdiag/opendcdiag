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
    command -v jq >/dev/null 2>&1 || skip "jq not installed"
    [[ -d /sys/bus/dsa/devices ]] || skip "No $label devices detected"

    # accel-config reads the device attributes below; they are root-only
    local prefix devdir found=0
    for prefix in ${type:-dsa iax}; do
        for devdir in /sys/bus/dsa/devices/$prefix*; do
            [[ -d "$devdir" ]] || continue
            cat "$devdir/state" > /dev/null 2>&1 || skip "must run as root"
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
