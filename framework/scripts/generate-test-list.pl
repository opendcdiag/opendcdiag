#!/usr/bin/perl
# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

use strict;
my @test_order;
my $output = shift @ARGV;
unless ($output eq "-") {
    open OUTPUT, ">", $output;
    select OUTPUT;
}
print '/* This is a generated file. DO NOT EDIT! */

#ifndef TEST_LIST_H
#define TEST_LIST_H

#include "sandstone_tests.h"

';

# Collect the test list
push @ARGV, "/dev/stdin" unless scalar @ARGV;
while ($_ = shift @ARGV) {
    open LIST, "<", $_ or die("Could not open $_: $!");
    while (<LIST>) {
        s/^\s+//;               # remove leading space
        s/#.*$//;               # remove comments
        s/\s+$//;               # remove trailing space
        next if /^$/;           # skip empty lines
        push @test_order, $_;
    }
    close LIST;
}

# Make sorted a list of all unique tests
my %alltests = map { ($_ => 1) } @test_order;

# Print all test declarations
for my $test (sort keys %alltests) {
    printf "extern struct test _test_%s;\n", $test;
}

# Print the test order
print "\nstatic constexpr struct test *ordered_test_list[] = {\n";
for my $test (@test_order) {
    printf "    \&_test_%s,\n", $test;
}

print '};
#endif /* TEST_LIST_H */
';
