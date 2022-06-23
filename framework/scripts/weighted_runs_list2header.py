#!/usr/bin/python3

import sys
import os

current = sys.argv[2] + '/'
root = sys.argv[3] + '/'
env = os.getenv("BUILTIN_LIST", "**")
default = sys.argv[1]

for filepath in [ root + env, root + default, current + env, current + default ]:
    try:
        with open(filepath, 'r', encoding="latin-1") as localfile:
            lines = localfile.readlines()
        print("// generated on", filepath, "with", len(lines), "entries")
        break
    except IOError:
        lines = []

print ("#pragma once")
print ("const char * const weighted_testlist[] = { ");
print ("#if !defined(SANDSTONE_GA) || SANDSTONE_GA==0")
for line in lines:
    line = line.strip()

    print("        \"" + line + "\",")
print("#endif")

print("        NULL")
print ("};")
