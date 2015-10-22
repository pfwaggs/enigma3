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
my $alpha = $Enigma::alpha;
my $rotor_file = 'etc/rotors.txt';
my %rotor_db = Enigma::Load_rotors($rotor_file);

my %opts = (reflector => 'A');
my @opts = (
    'verbose', 'display', 'wiring', #'reverse',
    'rotors=s'    => sub { $opts{rotors}     = [reverse split /,/, uc $_[1]] },
    'rings=s'     => sub { $opts{rings}      = [reverse split /,/, uc $_[1]] },
    'settings=s'  => sub { $opts{settings}   = [reverse split /,/, uc $_[1]] },
    'stecker=s'   => sub { $opts{stecker}    = [split /,/, uc $_[1]] },
    'reflector=s' => sub { $opts{reflector} = uc $_[1] },
);
GetOptions( \%opts, @opts ) or die 'something goes here';
#if ($opts{reverse}) {
#    $opts{rotors}   = [reverse @{$opts{rotors}}];
#    $opts{rings}    = [reverse @{$opts{rings}}];
#    $opts{settings} = [reverse @{$opts{settings}}];
#}

my @rotors;
push @rotors, $opts{stecker} ? Enigma::Set_stecker(@{$opts{stecker}}) : $alpha;
while (my ($ndx, $val) = each (@{$opts{rotors}}) ) {
    push @rotors, {Enigma::Get_rotor($rotor_db{$val}, $opts{rings}[$ndx], $opts{settings}[$ndx], $opts{display}//0, $opts{verbose}//0)};
}
push @rotors, $rotor_db{$opts{reflector}}{rotor};

if ($opts{wiring}) {
    Enigma::Encrypt_wiring(\@rotors);
} else {
    @ARGV ?  Enigma::Encrypt_auto({rotors=>\@rotors,strings=>\@ARGV}) : Enigma::Encrypt_interactive(@rotors);
}
