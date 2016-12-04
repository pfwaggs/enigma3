#!/usr/bin/env perl

# vim: ai si sw=4 sts=4 et fdc=4 fmr=AAA,ZZZ fdm=marker

use warnings;
use strict;
use v5.22;
use experimental qw(postderef signatures smartmatch);

use Getopt::Long qw( GetOptionsFromArray :config pass_through no_ignore_case auto_help );
use Data::Printer;
use JSON;
use Path::Tiny;
#use Pod::Usage;
use Cwd;
use Enigma;

my $alpha = $Enigma::Alpha;

my @unused = Enigma::ProcessCli(@ARGV);

# we need to get state saving to work.
#Enigma::PresetSave(%Enigma::Options) if exists $Enigma::Options{save};

#@Enigma::Rotors = Enigma::ConfigureMachine(%Enigma::Options);
#Enigma::ConfigureMachine(%Enigma::Options);
Enigma::ConfigureMachine();

@unused ? Enigma::EncryptAuto(@unused) : Enigma::EncryptInteractive();

# interactive has different modes; plain it just shows positions and
# lightboard.  you can add transitions with --transisitons
# or you can show wiring instead of lightboard with --wiring 
# lightboard transitions wiring/fancy_wiring
# 1          0           0
# 1          1           0
# 0          0           1

#Enigma::StateCheck({rotors=>\@rotors, state_check=>$pass_opts{state_check}}) if $pass_opts{state_check};
