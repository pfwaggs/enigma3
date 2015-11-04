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

my %opts = (reflector => 'A', rotor_file => 'etc/rotors.txt');
my @opts = (
    'verbose', 'display', 'wiring', #'reverse',
    'rotor_file=s',
    'rotors=s'    => sub { $opts{rotors}     = [reverse split /,/, uc $_[1]] },
    'rings=s'     => sub { $opts{rings}      = [reverse split /,/, uc $_[1]] },
    'settings=s'  => sub { $opts{settings}   = [reverse split /,/, uc $_[1]] },
    'stecker=s'   => sub { $opts{stecker}    = [split /,/, uc $_[1]] },
    'reflector=s' => sub { $opts{reflector}  = uc $_[1] },
);
GetOptions( \%opts, @opts ) or die 'something goes here';
$opts{verbose} = 1 if $opts{wiring}; # wiring implies verbose but not vice versa

#if ($opts{reverse}) {
#    $opts{rotors}   = [reverse @{$opts{rotors}}];
#    $opts{rings}    = [reverse @{$opts{rings}}];
#    $opts{settings} = [reverse @{$opts{settings}}];
#}

my %rotor_db = Enigma::Load_rotors($opts{rotor_file});
my @rotors;
push @rotors, $opts{stecker} ? Enigma::Set_stecker(@{$opts{stecker}}) : $alpha;
while (my ($ndx, $val) = each (@{$opts{rotors}}) ) {
    push @rotors, {Enigma::Get_rotor($rotor_db{$val}, $opts{rings}[$ndx], $opts{settings}[$ndx], $opts{display}//0, $opts{verbose}//0)};
}
push @rotors, $rotor_db{$opts{reflector}}{rotor};

# want to see state so add an option

if (@ARGV) {
    Enigma::Encrypt_auto({rotors=>\@rotors,strings=>\@ARGV});
} else {
    Enigma::Encrypt_interactive({rotors=>\@rotors, wiring=>$opts{wiring}//0, verbose=>$opts{verbose}//0});
}

