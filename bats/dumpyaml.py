#!/usr/bin/python3
# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

import sys, yaml
from shlex import quote

def dump_value(path, value):
    if type(value) is dict:
        dump_dict(path, value)
    elif type(value) is list:
        dump_list(path, value)
    else:
        #sys.stdout.write(path + "\1" + str(value) + "\0")
        print('[{}]={}'.format(quote(path), quote(str(value))))

def dump_list(path, array):
    if path != "":
        dump_value(path, str(array))
    dump_value(path + "@len", len(array))
    for i in range(0, len(array)):
        dump_value(path + f"/{i}", array[i])

def dump_dict(path, obj):
    if path != "":
        dump_value(path, str(obj))
    for entry in obj.items():
        dump_value(path + '/' + str(entry[0]), entry[1])

log = yaml.safe_load(sys.stdin)
dump_value("", log)

