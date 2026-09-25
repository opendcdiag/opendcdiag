#!/usr/bin/env python3
# Copyright 2026 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

import json
import os
import sys

import yaml

def fail(msg):
    print(msg, file=sys.stderr)
    exit(1)

def main():
    expected_path, yaml_path = sys.argv[1], sys.argv[2]

    with open(expected_path, 'r', encoding='utf-8') as file:
        expected = json.load(file)

    expected_basic = set()
    expected_group = set()
    for wq in expected:
        name = wq['device']
        sysfs_path = os.path.realpath(f'/sys/bus/dsa/devices/{name}')
        bdf = os.path.basename(os.path.dirname(sysfs_path))
        if not bdf:
            continue
        expected_basic.add((wq['device_id'], wq['wq_id'], bdf))
        expected_group.add((wq['device_id'], wq['wq_id'], wq['group_id'], bdf))

    with open(yaml_path, 'r', encoding='utf-8') as file:
        data = yaml.safe_load(file) or {}

    actual_basic = set()
    actual_group = set()
    seen_group = False

    def consume(entry):
        nonlocal seen_group
        if not isinstance(entry, dict):
            return
        dev = entry.get('device')
        if dev is None:
            return
        device_id = int(str(dev)[3:])
        wq = entry.get('wq')
        if wq is None:
            return
        bdf = entry.get('pci_address')
        if bdf is not None:
            actual_basic.add((device_id, int(wq), str(bdf)))
        if 'group' in entry:
            seen_group = True
            actual_group.add((device_id, int(wq), int(entry['group']), str(bdf or '')))

    for entry in data.get('device-info', []):
        consume(entry)
    for test in data.get('tests', []):
        for thread in test.get('threads', []):
            consume(thread.get('id'))

    missing_basic = sorted(expected_basic - actual_basic)
    if missing_basic:
        fail(f'Missing device/wq/BDF tuples in opendcdiag output: {missing_basic}')
    if seen_group:
        missing_group = sorted(expected_group - actual_group)
        if missing_group:
            fail(f'Missing device/wq/group/BDF tuples in opendcdiag output: {missing_group}')


if __name__ == '__main__':
    main()
