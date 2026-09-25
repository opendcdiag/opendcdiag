#!/usr/bin/bats
# -*- mode: sh -*-
# Copyright 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0
load ../testenv
load helpers

setup_file() {
    [[ "$SANDSTONE_DEVICE_TYPE" = "IDXD" ]] || skip "Tests specific to IDXD"
}

@test "IDXD selftest topology matches accel-config" {
    command -v accel-config >/dev/null 2>&1 || skip "accel-config not installed"
    command -v jq >/dev/null 2>&1 || skip "jq not installed"
    [[ -d /sys/bus/dsa/devices ]] || skip "No DSA devices detected"

    # accel-config reads the device attributes below; they are root-only
    local devdir
    for devdir in /sys/bus/dsa/devices/dsa*; do
        [[ -d "$devdir" ]] || skip "No DSA devices detected"
        cat "$devdir/state" > /dev/null 2>&1 || skip "must run as root"
        break
    done

    local accel_json=$(mktempfile accel-XXXXXX.json)
    accel-config list > "$accel_json"
    local expected_json=$(mktempfile expected-XXXXXX.json)
    jq '[.[] as $device |
        ($device.dev | capture("dsa(?<id>[0-9]+)") | .id | tonumber) as $device_id |
        $device.groups[]?.grouped_workqueues[]? |
        {
            device: $device.dev,
            device_id: $device_id,
            wq_id: (.dev | capture("wq[0-9]+\\.(?<id>[0-9]+)") | .id | tonumber),
            group_id: .group_id
        }
    ]' "$accel_json" > "$expected_json"

    # accel-config only reports enabled devices/WQs
    [[ "$(jq 'length' "$expected_json")" -gt 0 ]] || skip "No enabled DSA work queues"

    local yamlfile=$(mktempfile output-XXXXXX.yaml)
    "$SANDSTONE_BIN" \
        --on-crash=core --on-hang=kill --ignore-mce-errors \
        -Y -o - -vvv \
        --disable='@special' --selftests --timeout=20s --retest-on-failure=0 \
        -e selftest_pass > "$yamlfile"
    [[ "$?" -eq 0 ]]

    python3 "$BATS_TEST_COMMONDIR/check_idxd_topology.py" "$expected_json" "$yamlfile"
}
