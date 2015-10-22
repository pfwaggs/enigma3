package Enigma;

# preamble #AAA
use warnings;
use strict;
use v5.18;

use Term::ReadKey;
use Path::Tiny;
#use Data::Dumper;
use Data::Printer;
my $nl = "\n";
my $tb = "\t";
our $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
#ZZZ

# Load_rotors DONE #AAA
sub Load_rotors {
    my $file = shift;
    my %rotors;
    my $A = ord 'A';
    # first we read in the rotors file and save contents
    for (path($file)->lines({chomp=>1})) {
        next if /^#/;
        my ($key, $rotor, $ring) = split /\s+:\s+/;
        $rotors{$key}{rotor} = $rotor;
        $rotors{$key}{notch} = $ring if $key =~ /^[IV]+/;
    }
    return wantarray ? %rotors : \%rotors;
}

#ZZZ

# Get_rotor DONE #AAA
sub Get_rotor {
    our $alpha;
    my %rtn = %{shift @_}; # this gives us rotor and notch key/value
    $rtn{window} = $alpha;
    $rtn{alpha} = $alpha;
    my $ring = shift;
    my $setting = shift;
    my $display = shift // 0;
    my $verbose = shift // 0;

    my @spaces = (' ')x26;
    $spaces[0] = '|';
    $spaces[ord($_)-ord('A')] = '#' for split //,$rtn{notch};
    my $tyre = join('',@spaces);
    my @rtn;
    push(@rtn, $rtn{window}, $tyre, $alpha, $rtn{rotor}, '='x25) if $verbose;

    my $offset = ord($ring)-ord('A');
    $tyre =~ s/^(.{$offset})(.+)$/$2$1/;
    $rtn{window} =~ s/^(.{$offset})(.+)$/$2$1/;
    push(@rtn, $rtn{window}, $tyre, $alpha, $rtn{rotor}, '='x25) if $verbose;

    my $set = (ord($setting) - ord($ring)) % 26;
    $tyre  =~ s/^(.{$set})(.+)$/$2$1/;
    $rtn{window} =~ s/^(.{$set})(.+)$/$2$1/;
    $rtn{rotor} =~ s/^(.{$set})(.+)$/$2$1/;
    push(@rtn, $rtn{window}, $tyre, $alpha, $rtn{rotor}, '='x25) if $verbose;
    
    #my $shift_alpha = $alpha =~ s/(.+)(.)/$2$1/r;
    my $shift_alpha = $alpha =~ s/(.+)(.{$set})/$2$1/r;
    eval "\$rtn{rotor} =~ tr/$alpha/$shift_alpha/";
#    while ($set) {
#	eval "\$rtn{rotor} =~ tr/$alpha/$shift_alpha/";
#    } continue {
#	$set--;
#    }
    push @rtn, $rtn{window}, $tyre, $alpha, $rtn{rotor}, '='x25;
    p @rtn if $display;
    return wantarray ? %rtn : \%rtn;
}
#ZZZ

# Set_stecker DONE #AAA
sub Set_stecker {
    my %stecker = map {$_ => $_} ('A' .. 'Z');
    for (@_) {
        my ($left, $right) = split //;
        $stecker{$left} = $right;
        $stecker{$right} = $left;
    }
#   map {$stecker{$_} = $_} grep {! exists $stecker{$_}} ('A' .. 'Z');
    return join('',@stecker{sort keys %stecker});
}
#ZZZ

# Show_rotors #AAA
sub Show_rotors {
    my @state = @{shift @_};
    my @window = ();
    for (1..3) {
        $state[4-$_]{window} =~ /^(.)/;
        push @window,$1;
    }
    return join(' ',@window);
}
#ZZZ

# Step_rotor DONE #AAA
sub Step_rotor {
    my %rtn = %{shift @_};
#   p %rtn;
    map {s/^(.)(.+)$/$2$1/} @rtn{qw(window rotor)};
    eval "\$rtn{rotor} =~ tr/ABCDEFGHIJKLMNOPQRSTUVWXYZ/ZABCDEFGHIJKLMNOPQRSTUVWXY/";
#   p %rtn;
#   die 'one step';
    return wantarray ? %rtn : \%rtn;
}
#ZZZ

# Step_machine DONE #AAA
sub Step_machine {
    my @state = (@_);
#   p @state;

    my %rotor_f = %{$state[1]};
    my %rotor_m = %{$state[2]};
    my %rotor_s = %{$state[3]};

    my $pawl_f = $rotor_f{window} =~ /^$rotor_f{notch}/ ? 1 : 0;
    my $pawl_m = $rotor_m{window} =~ /^$rotor_m{notch}/ ? 1 : 0;
    %rotor_f = Step_rotor(\%rotor_f);
    if ($pawl_f) {
        %rotor_m = Step_rotor(\%rotor_m);
    }
    if ($pawl_m) {
        %rotor_m = Step_rotor(\%rotor_m) unless $pawl_f;
        %rotor_s = Step_rotor(\%rotor_s);
    }
    $state[1] = \%rotor_f;
    $state[2] = \%rotor_m;
    $state[3] = \%rotor_s;
#   p @state;

    return wantarray ? @state : \@state;
}
#ZZZ

# Encrypt_letter DONE #AAA
sub Encrypt_letter {
    my @rotors = @{shift @_};
    my $char = shift;

    my @tmp = ();
    @rotors = Step_machine(@rotors);

    push @tmp, $char;
    # through the stecker
    eval "\$char =~ tr/$alpha/$rotors[0]/";
    push @tmp, $char;
    # through the rotors
    for (qw{1 2 3}) {
	eval "\$char =~ tr/$alpha/$rotors[$_]{rotor}/";
	push @tmp, $char;
    }
    # through the reflector
    eval "\$char =~ tr/$alpha/$rotors[4]/";
    push @tmp, $char;
    # backwards through the rotors
    for (qw{3 2 1}) {
	eval "\$char =~ tr/$rotors[$_]{rotor}/$alpha/";
	push @tmp, $char;
    }
    # finally back through the stecker
    eval "\$char =~ tr/$rotors[0]/$alpha/";
    push @tmp, $char;
    return (\@rotors, $char, \@tmp);
#   $rtn{$word}{xfrm} .= $char;
#   $rtn{$word}{steps} = \@tmp;
#   return wantarray ? %rtn : \%rtn;
}
#ZZZ

# Encrypt_auto DONE #AAA
sub Encrypt_auto {
    my %input = %{shift @_};
    my $rotor_aref = $input{rotors};
    my @strings = @{$input{strings}};

    my %rtn;
    for my $word (@strings) {
        $rtn{$word}{xfrm} = '';
        for my $char (split //, uc $word) {
	    ($rotor_aref, $char, undef) = Encrypt_letter($rotor_aref, $char);
	    $rtn{$word}{xfrm} .= $char;
	}
    }
    say join(' ', @strings);
    say join(' ', map {$rtn{$_}{xfrm}} @strings);
}
#ZZZ

# Encrypt_interactive DONE #AAA
sub Encrypt_interactive {
    my $rotor_aref = [@_];

    my @data = path("etc/lightboard.txt")->lines({chomp=>1});
    my $blank = $nl x @data;
    my %mapping;
    for my $letter ('A'..'Z') {
	$mapping{$letter} = [map {s/[^$letter\n]/ /gr} @data];
    }
    my $input;
    my $output;
    system('clear');
    say $blank; #for @data;
    print "? ";
    chomp ($input = <STDIN>);
    while ($input ne 'quit') {
	system('clear');
	($rotor_aref, $output, undef) = Encrypt_letter($rotor_aref, uc $input);
	say for @{$mapping{$output}};
    } continue {
	print "? ";
	chomp ($input = <STDIN>);
    }

}
#ZZZ

# Encrypt_wiring DONE #AAA
sub Encrypt_wiring {
    our $alpha;
#   my @state = @{shift @_};
    my $rotor_aref = shift;
    my @state = @$rotor_aref;
    
    # first we set up the matrix
    system('clear');
    my @setup;
    push @setup, [map {"  $_  "} split //, $alpha]; #$state[0]];
    for my $ndx (1..3) {
	push @setup, [map {"  $_  "} split //, $state[$ndx]{window}];
    }
    push @setup, [map {"  $_  "} split //, $alpha]; #$state[4]];

    map {s/^|$/  /g} @{$setup[$_]} for (0 .. 4);

    my @output = ();
    for my $col (0..25) {
	push @output, join(' ',reverse map {$setup[$_][$col]} (0..4));
    }
    say for @output;

    my $input;
    print "? ";
    chomp ($input = <STDIN>);
    while ($input ne 'quit') {
	system('clear');
	($rotor_aref, my $output, my $transition_aref) = Encrypt_letter($rotor_aref, uc $input);
	my @transitions = @$transition_aref;
	@state = @$rotor_aref;
	@setup = ();
	push @setup, [map {" $_ "} split //, $alpha]; #$state[0]];
	for my $ndx (1..3) {
	    push @setup, [map {" $_ "} split //, $state[$ndx]{window}];
	}
	push @setup, [map {" $_ "} split //, $alpha]; #$state[4]];


	# now we move through the transition list. first the stecker
	my ($ndx) = grep {$setup[0][$_] =~ /$transitions[0]/} (0..25);
	$setup[0][$ndx] =~ s/ /</g;

	# then we step through the rotors
	for my $a (1..3) {
	    my ($ndx) = grep {$setup[$a][$_] =~ /$transitions[$a]/} (0..25);
	    $setup[$a][$ndx] =~ s/ /</g;
	}
	# into the reflector
	($ndx) = grep {$setup[4][$_] =~ /$transitions[4]/} (0..25);
	$setup[4][$ndx] =~ s/ /</g;
	# and back out of the reflector
	($ndx) = grep {$setup[4][$_] =~ /$transitions[5]/} (0..25);
	$setup[4][$ndx] =~ s/ />/g;

	# through the rotors the other way.
	for $a (1..3) {
	    my ($ndx) = grep {$setup[$a][$_] =~ /$transitions[9-$a]/} (0..25);
	    $setup[$a][$ndx] =~ s/ />/g;
	}
	# back through the stecker
	($ndx) = grep {$setup[0][$_] =~ /$transitions[9]/} (0..25);
	$setup[0][$ndx] =~ s/ />/g;

	# add some space padding except for reflector
	map {s/^|$/ /g} @{$setup[$_]} for (0..3);

	# now do the reflector
	my ($start,$stop) = grep {$setup[4][$_] !~ /\s$/} (0..25);
	($start,$stop) = ($stop,$start) if $stop<$start;
#$setup[4][$_] = ' '.$setup[4][$_] for (0..25);
	map {s/^|$/ /g} @{$setup[4]};
#$setup[4][$start] =~ s/ $/+/;
	$setup[4][$start] =~ s/^ /+/;
#$setup[4][$stop]  =~ s/ $/+/;
	$setup[4][$stop]  =~ s/^ /+/;
	for ($start+1 .. $stop-1) {
	   #$setup[4][$_] =~ s/ $/|/;
	    $setup[4][$_] =~ s/^ /|/;
	}

	map {s/^|$/  /g} @{$setup[$_]} for (0 .. 4);
#	for my $col (0 .. 4) {
#	    map {s/^|$/  /g} @{$setup[$col]};
#	}

	# now build the steps using the windows from the rotors.
	@output = ();
	for my $col (0..25) {
	    push @output, join(' ',reverse map {$setup[$_][$col]} (0..4));
	}
	say for @output;
    } continue {
	print "? ";
	chomp ($input = <STDIN>);
    }
}
#ZZZ

## Show_vertical #AAA
#sub Show_vertical {
#    my @rotors = @{shift @_};
#    my @transitions = @{shift @_};
#
#    my @order = (0 .. 4);
#    my @matrix;
#    for my $rotor (@rotors) {
#	push @matrix, [split //, ref $rotor eq 'HASH' ? $rotor->{rotor} : $rotor]; #convert all strings to lists
#    }
#    my @matrix_transpose;
#    my $count = 0;
#    while (@{$matrix[0]}) {
#	my @str = ();
#	push @str, shift @{$matrix[$_]} for @order;
#	$matrix_transpose[$count++] = join('',@str);
#    }
#p @matrix_transpose;
#
#die 'done';
##    for my $level (@levels) {
##	my @row = ();
##	for my $wheel (@order) {
##	    push @row, $rotor[$wheel][$level]
##	}
##    }
#}
##ZZZ

1;
