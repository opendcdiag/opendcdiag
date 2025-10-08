#!/usr/bin/python3
# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

import yaml
import platform
import sys

def fail(msg):
    print(msg, file=sys.stderr)
    exit(1)

def validate_time(test, timetype):
    time = test[timetype]
    elapsed = time['elapsed']
    now = time['now']
    if not type(elapsed) is float:
        fail("elapsed {} for test {} was not a number".format(test['test'], timetype))


def validate_message(name, message):
    level = message['level']
    if not level in ("error", "warning", "info", "debug", "skip"):
        fail("found invalid message level in test {} (was: {})".format(name, level))
    if 'text' in message:
        if not type('text') is str:
            fail("found message with invalid 'text' for in test {}".format(name))
    if 'data' in message:
        if not type('data') is str:
            fail("found message with invalid 'data' for in test {}".format(name))
    if 'data-miscompare' in message:
        data_miscompare = message['data-miscompare']
        if level != 'error':
            fail("found a data miscompare that wasn't an error in test {} (was: {})".format(name, level))
        data_miscompare['description']
        data_miscompare['type']
        data_miscompare['offset']
        data_miscompare['address']
        data_miscompare['actual']
        data_miscompare['expected']
        data_miscompare['mask']
    return level == 'error'


def validate_thread(name, thr):
    n = thr['thread']

    if type(n) is int:
        thr['id']['logical']
        thr['id']['package']
        thr['id']['numa_node']
        thr['id']['module']
        thr['id']['core']

        if platform.uname().machine == 'x86-64':
            thr['id']['thread']
            thr['id']['family']
            thr['id']['model']
            thr['id']['stepping']
            thr['id']['microcode']
            thr['id']['ppin']
    elif not n.startswith('main'):
        fail('found unknown thread "{}" for test {}'.format(n, name))

    if 'loop-count' in thr:
        loop_count = thr['loop-count']
        if not type(loop_count) is int:
            fail('found invalid loop-count for thread "{}" for test {} (was: {})'
                 .format(n, name, loop_count))

    # Did this thread fail?
    if 'state' in thr:
        state = thr['state']
        if not state in ('failed', 'stuck'):
            fail('found invalid state for thread "{}" for test {} (was: {})'
                 .format(n, name, state))

    # Were there any messages?
    if not 'messages' in thr or thr['messages'] is None:
        return False
    any_error = False
    for msg in thr['messages']:
        any_error = validate_message(test, msg) or any_error
    return any_error


with open(sys.argv[1]) as file:
    log = yaml.safe_load(file)
    ignoring_timeouts = '--ignore-timeout' in log['command-line'] or '--ignore-os-error' in log['command-line']
    fatal_skips = '--fatal-skips' in log['command-line']
    exit_fail = False
    tests = []
    if 'tests' in log:
        tests = log['tests']
    for test in tests:
        name = test['test']
        details = test['details']
        details['quality']
        details['description']
        result = test['result']
        runtime = test['test-runtime']
        validate_time(test, 'time-at-start')
        validate_time(test, 'time-at-end')

        if not result in ('pass', 'fail', 'skip', 'timed out', 'crash', 'operating system error'):
            fail("result for test {} was not a valid one (was: {})".format(name, result))
            if (result in ('crash', 'operating system error')):
                test['result-details']['crashed']
                test['result-details']['coredump']
                test['result-details']['code']
                test['result-details']['reason']
        if not type(runtime) is float:
            fail('test-runtime for test{} was not a number'.format(name))

        # validate per-thread info
        if not 'threads' in test:
            continue
        any_failed = False
        for thr in test['threads']:
            any_failed = validate_thread(name, thr) or any_failed
        if any_failed and result in ('pass', 'skip'):
            fail("found at least one failing thread for test {} but it was not a failure (was: {})".format(name, result))
        if any_failed and ignoring_timeouts and result == 'timed out':
            any_failed = False
        if result == 'skip' and fatal_skips:
            any_failed = True
        exit_fail = exit_fail or any_failed

    exitmsg = log['exit']
    if not exitmsg in ('pass', 'fail', 'invalid'):
        fail("exit code was not an expected one (was: {})".format(exitmsg))
    if exit_fail and exitmsg == 'pass':
        fail('found at least one failing test but the overall result was "{}"'.format(exitmsg))


exit(0)
