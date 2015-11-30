#!/usr/bin/env perl

# vim: ai si sw=4 sts=4 et fdc=4 fmr=AAA,ZZZ fdm=marker

use warnings;
use strict;
use v5.18;

use Getopt::Long qw( GetOptionsFromArray :config pass_through no_ignore_case auto_help );
use Data::Printer;
use JSON::PP;
use Path::Tiny;
#use Pod::Usage;
use Cwd;

BEGIN {
    unshift @INC, cwd().'/lib';
}
use Enigma;

my $alpha = $Enigma::alpha;

# do we have a optional config file?
my $config = 'etc/default_config.jsn';
GetOptionsFromArray( \@ARGV, 'config=s' => \$config);

# load up the config file
my $jpp = JSON::PP->new->pretty->canonical;
my $string = join(' ',path($config)->lines({chomp=>1}));
my %opts = %{$jpp->decode($string)};
#warn 'defaults: '; p %opts; die 'stop';

# these get passed through to called routines.
my %pass_opts = (wiring=>0, fancy_wiring=>0, transitions=>0, state_check=>0);
my @pass_opts = (
    'state_check'  => sub { $pass_opts{state_check}++},
    'transitions'  => sub { $pass_opts{transitions}  = 1 - $pass_opts{transitions}  },
    'wiring'       => sub { $pass_opts{wiring}       = 1 - $pass_opts{wiring}       },
    'fancy_wiring' => sub { $pass_opts{fancy_wiring} = 1 - $pass_opts{fancy_wiring} },
);

#GetOptions( \%opts, @opts, @pass_opts,) or die 'something goes here';
GetOptions( \%opts, @{$opts{opts}}, 'build_config=s', @pass_opts,) or die 'something goes here';

if ($opts{build_config}//0) {
    Enigma::Build_config(\%opts);
    die 'done';
} else {
    %opts = Enigma::Parse(\%opts);
}

my %universal;
@universal{qw(rotors rings settings stecker reflector)} = @opts{qw(rotors rings settings stecker reflector)};
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

    $pass_opts{transitions} = 0 if $pass_opts{wiring} or $pass_opts{fancy_wiring};
    Enigma::Encrypt_interactive({rotors => \@rotors, %pass_opts});
}

