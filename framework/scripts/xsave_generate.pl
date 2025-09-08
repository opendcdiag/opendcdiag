#!/usr/bin/env perl

# Copyright 2025 Intel Corporation.
# SPDX-License-Identifier: Apache-2.0

# Read input from file specified by first argument
my $input_conf_file = shift @ARGV;
open(FH, '<', $input_conf_file) or die $!;

my @xsaveStates;
while (<FH>) {
    chomp $_;
    m/#\s*(.*)\s*/;
    my $comment = $1;

    s/#.*$//;
    s/^\s+//;
    next if $_ eq "";

    if (s/^xsave=//) {
        my ($name, $value, $required) = split /\s+/;
        $required =~ s/[^a-z0-9_,]/_/g;
        push @xsaveStates,
            { id => $name, value => $value, required_for => $required, comment => $comment };
    }
}
close FH;

# Print the header output
my $headername = "";
my $headerguard = "";
if ($headername = shift @ARGV) {

    $headerguard = uc($headername);
    $headerguard =~ s/[^A-Z0-9_]/_/g;

    print qq|// This is a generated file. DO NOT EDIT.
// Please see $0
#ifndef $headerguard
#define $headerguard\n|;
}

# Produce the list of XSAVE states
print "\nenum XSaveBits {\n";
my $xsaveEnumPrefix = "XSave_";
for my $state (@xsaveStates) {
    my $value = $state->{value};
    unless ($value =~ /^0x/) {
        # Compound value
        $value = join(" | ", map { $xsaveEnumPrefix . $_ } split(/\|/, $value));
    }
    printf "    %s%-12s = %s,", $xsaveEnumPrefix, $state->{id}, $value;
    printf "%s// %s", ' ' x (18 - length($value)), $state->{comment}
        if $state->{comment} ne '';
    printf "\n";
};
print "};\n";

printf qq|
// -- implementation end --
#endif /* $headerguard */\n|;
