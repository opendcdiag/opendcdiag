#!/usr/bin/python3

import sys

with open(sys.argv[1], 'r', encoding="latin-1") as localfile:
    lines = localfile.readlines()


print ("#pragma once")
print ("const char * const weighted_testlist[] = { ");
print ("#if !defined(SANDSTONE_GA) || SANDSTONE_GA==0")
for line in lines:
    line = line.strip()
    
    print("        \"" + line + "\",")

print("        NULL")
print("#endif")
print ("};")
