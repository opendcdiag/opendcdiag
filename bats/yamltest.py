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


def validate_number(id, what, min, max = None):
    if what not in id:
        fail('{} not found in the thread identification'.format(what))
    n = id[what]
    if not isinstance(n, int):
        fail('{} is not an integer in the thread identification'.format(what))
    if n < min or (max is not None and n > max):
        fail('{} is outside of range for thread identification ({})'.format(what, n))


def validate_thread_id_cpu(id):
    validate_number(id, 'logical', -1)
    validate_number(id, 'package', -1)
    validate_number(id, 'numa_node', -1)
    validate_number(id, 'module', -1)
    validate_number(id, 'core', -1)
    validate_number(id, 'thread', -1)
    try:
        core_type = id['core_type']
        if core_type not in ('e', 'p'):
            fail('found invalid core type "{}" for thread {}'.format(core_type, id))
    except:
        pass

    if platform.uname().machine == 'x86-64':
        validate_number(id, 'family', -1, 0xffff)
        validate_number(id, 'model', -1, 0xffff)
        validate_number(id, 'stepping', -1, 0xffff)
        if not id['microcode'] is None:
            validate_number(id, 'microcode', -1)
        id['ppin']

def validate_thread_id_gpu(id):
    # TODO
    pass

def validate_thread(device_type, name, thr):
    n = thr['thread']

    if type(n) is int:
        if (device_type == "GPU"):
            validate_thread_id_gpu(thr['id'])
        else:
            validate_thread_id_cpu(thr['id'])
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
    if len(sys.argv) != 3:
        fail('device type argument missing')
        exit(1)
    if sys.argv[2] == "GPU":
        for thread in log['device-info']:
            validate_thread_id_gpu(thread)
    else:
        for thread in log['cpu-info']:
            validate_thread_id_cpu(thread)
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

        if not result in ('pass', 'fail', 'skip', 'timed out', 'crash', 'operating system error',
                          'interrupted'):
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
            any_failed = validate_thread(sys.argv[2], name, thr) or any_failed
        if any_failed and result in ('pass', 'skip'):
            fail("found at least one failing thread for test {} but it was not a failure (was: {})".format(name, result))
        if any_failed and ignoring_timeouts and result == 'timed out':
            any_failed = False
        if result == 'skip' and fatal_skips:
            any_failed = True
        exit_fail = exit_fail or any_failed

    exitmsg = log['exit']
    if not exitmsg in ('pass', 'fail', 'invalid', 'interrupted'):
        fail("exit code was not an expected one (was: {})".format(exitmsg))
    if exit_fail and exitmsg == 'pass':
        fail('found at least one failing test but the overall result was "{}"'.format(exitmsg))


exit(0)
