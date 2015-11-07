#!/usr/bin/env perl

# vim: ai si sw=4 sts=4 et fdc=4 fmr=AAA,ZZZ fdm=marker

use warnings;
use strict;
use v5.18;

use Getopt::Long qw( :config no_ignore_case auto_help );
use Data::Printer;
#use Pod::Usage;
use Cwd;

BEGIN {
    unshift @INC, cwd().'/lib';
}
use Enigma;

sub qp {
    my @input = @_;
    warn $input[0];
    p $input[1];
    die $input[2];
}

my $alpha = $Enigma::alpha;

my %opts = (rotor_file => 'etc/rotors.txt',);
my @opts = ( 'rotor_file=s',);

my %pass_opts = (verbose=>0, wiring=>0, transitions=>0, state_check=>0);
my @pass_opts = (
    'state_check' => sub { $pass_opts{state_check}++},
    'verbose'     => sub { $pass_opts{verbose}      = 1 - $pass_opts{verbose} },
    'transitions' => sub { $pass_opts{transitions}  = 1 - $pass_opts{transitions} },
    'wiring'      => sub { $pass_opts{wiring}       = 1 - $pass_opts{wiring} },
);

my %universal = (reflector => 'A',);
my @universal = (
    'rotors=s'    => sub { $universal{rotors}       = [reverse split /,/, uc $_[1]] },
    'rings=s'     => sub { $universal{rings}        = [reverse split /,/, uc $_[1]] },
    'settings=s'  => sub { $universal{settings}     = [reverse split /,/, uc $_[1]] },
    'stecker=s'   => sub { $universal{stecker}      = [split /,/, uc $_[1]] },
    'reflector=s' => sub { $universal{reflector}    = uc $_[1] },
);
GetOptions( \%opts, @opts, @pass_opts, @universal ) or die 'something goes here';

my @rotors = Enigma::Configure_machine({%opts, %universal});

Enigma::State_check({rotors=>\@rotors, state_check=>$pass_opts{state_check}}) if $pass_opts{state_check};

if (@ARGV) {
    Enigma::Encrypt_auto({rotors => \@rotors, strings => \@ARGV});
} else {

# interactive has different modes; plain it just shows positions and
# lightboard.  you can add transitions with --transisitons
# or you can show wiring instead of lightboard with --wiring 
# lightboard transitions wiring
# 1          0           0
# 1          1           0
# 0          0           1

    $pass_opts{transitions} = 0 if $pass_opts{wiring};
    Enigma::Encrypt_interactive({rotors => \@rotors, %pass_opts});
}

