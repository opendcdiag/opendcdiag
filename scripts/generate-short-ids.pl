#!/usr/bin/perl

# Copyright (C) 2026 Intel Corporation.
# This source code is Intel Confidential and not for distribution
# outside of Intel without explicit permission from the authors.

use Digest::SHA qw(sha256_hex);
use File::Find;
use File::Spec;
use strict;

sub find_dirs($@) {
    my $path = shift @_;
    my @dirs = @_;
    my @result;
    if (scalar @dirs) {
        my $candidate = $dirs[0];
        my ($volume, $directories, $file) = File::Spec->splitpath($path);
        my @directories = File::Spec->splitdir($directories);
        while (scalar @directories) {
            $path = File::Spec->catpath($volume, File::Spec->catdir(@directories), '');
            last if (-d "$path/$candidate");
            pop @directories;
        }
        die("Could not find the $candidate is.") unless scalar @directories;

        @result = map { "$path/$_" } @dirs;
    }
    return @result;
}

my $declare_test_rx = qr/^DECLARE_TEST\s*\((\w+)/;
my $me = $0;
unless (scalar @ARGV) {
print "$0 <output> [secret] <test-dir...>
Produces a listing of short test IDs for all tests found in test-dir.
  output        file name or \"-\" for stdout
  secret        (optional) initial vector for the hashing
  test-dir      one or more directories under which to find test sources
";
}

my $output = shift @ARGV;
unless ($output eq "-") {
    open OUTPUT, ">", $output;
    select OUTPUT;
}

# See if we have a secret file
my $secret = "";
if (scalar @ARGV && -f $ARGV[0]) {
    open F, "<", $ARGV[0];
    shift @ARGV;
    $secret = <F>;
    chomp $secret;
    close F;
}

# Find the directories
my @test_subdirs = find_dirs($me, @ARGV);

# Find all possible tests in the source code
my @alltests = qw(mce_check);
find(sub {
    return unless $_ =~ m/\.(c|cpp)$/;
    open F, "<", $_
        or die("Could not open $File::Find::name: $!");
    while (<F>) {
        push @alltests, $1 if m/$declare_test_rx/;
    }
    close F;
}, @test_subdirs);

print '/* This is a generated file. DO NOT EDIT! */

/* These are all tests, including those we will not use */
';

# Print all test declarations
for my $test (sort @alltests) {
    my $digest = sha256_hex($secret . $test);
    $digest = substr($digest, 0, 6);        # only the first three bytes (24 bits)
    printf "#define TEST_ID_%-30s %s\n", $test, $digest;
}
