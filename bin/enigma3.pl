#!/usr/bin/env perl

# vim: ai si sw=4 sts=4 et fdc=4 fmr=AAA,ZZZ fdm=marker

use warnings;
use strict;
use v5.22;
use experimental qw(postderef signatures smartmatch);

use Getopt::Long qw( GetOptionsFromArray :config pass_through no_ignore_case auto_help );
use Data::Printer;
use lib qw(./lib ../lib);
use Enigma qw(processCli autoCrypt cliCrypt);

#my $alpha = $Enigma::Alpha;

my @strings = processCli(@ARGV);

@strings ? autoCrypt(@strings) : cliCrypt();

# interactive has different modes; plain it just shows positions and
# lightboard.  you can add transitions with --transisitons
# or you can show wiring instead of lightboard with --wiring 
# lightboard transitions wiring/fancy_wiring
# 1          0           0
# 1          1           0
# 0          0           1

