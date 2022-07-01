#!/usr/bin/perl -l

# Copyright 2022 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

use strict;
use File::Spec;
open STDERR, ">", File::Spec->devnull(); # close stderr

my $file = shift @ARGV;
my $match = shift @ARGV;
my $suffix = shift @ARGV or "";
my $deps = "";

if (scalar $match) {
    $match =~ s/\.exe$//;       # drop .exe extension, if happened
    $match .= '-';              # add dash
}
$suffix = "-$suffix" if (scalar $suffix);

# See if we're in a Git repository
my $description = `git -C $ENV{MESON_SOURCE_ROOT} describe --always --tags --match="$match*" --abbrev=12 --dirty`;
if ($? == 0) {
    # We are, so use the output of git describe (stripped of $match)
    chomp $description;
    $description =~ s/\Q$match\E//;
    $description .= $suffix;

    my $gitdir = $ENV{MESON_SOURCE_ROOT} . "/" . ".git";
    if (-f $gitdir) {
        # .git is a "gitdir:" file
        open GITDIR, "<", $gitdir;
        $gitdir = <GITDIR>;
        $gitdir =~ s/^gitdir: //;
        close GITDIR;
    }

    my $ref = "HEAD";
    my $reffile = "$gitdir/$ref";
    do {
        $reffile = "$gitdir/packed-refs" unless (-f $reffile);
        $deps .= " $reffile";
        $ref = `git -C $ENV{MESON_SOURCE_ROOT} symbolic-ref $ref`;
        chomp $ref;
        $reffile = "$gitdir/$ref";
    } while ($? == 0);
}

# Check if the .hash file has useful information too
open F, "<", $ENV{MESON_SOURCE_ROOT} . "/" . ".hash";
my $line = <F>;
chomp $line;
close F;
if ($line =~ m/^([0-9a-f]+) (.*)/) {
    # Output from a git archive
    $deps .= " .hash";
    $description = "";
    my $hash = $1;
    my @refs = split /, /, $2;
    for my $ref (@refs) {
        next unless $ref =~ m/tag: \Q$match\E(.*)/;
        # git archive of a matching tag
        $description = sprintf("v%s%s (%s)", $1, $suffix, $hash);
        last;
    }

    # didn't find a matching tag, so use the hash
    $description = "$hash$suffix" unless scalar $description
}

# Use RELEASE_NO environment variable if available
if ($ENV{'RELEASE_NO'}) {
    $description = $ENV{'RELEASE_NO'} . $suffix;
}

$description = "<unknown version>" unless scalar $description;

# Save the description
open F, ">", $file;
printf F "#define GIT_ID \"%s\"\n", $description;
close F;

# And create a Makefile dependency for us to be called again
my $depfile = ($file =~ s,^(.*/)([^/]+),$1.$2.d,r);
open F, ">", $depfile;
printf F "%s: %s\n", $file, $deps;
close F;
