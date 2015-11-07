package Enigma;

# preamble #AAA
use warnings;
use strict;
use v5.18;

use Term::ReadKey;
use Path::Tiny;
use Data::Printer;
my $nl = "\n";
my $tb = "\t";
our $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
#ZZZ

# _Load_rotors DONE #AAA
sub _Load_rotors {
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

# _Get_rotor DONE #AAA
sub _Get_rotor {
    my $alpha = $Enigma::alpha;
    my %rtn = %{shift @_}; # this gives us rotor and notch key/value
    $rtn{window} = $alpha;
    my $ring = shift;
    my $setting = shift;

    # first we generate the raw display values (nothing in rtn changes here)
    # the tyre shows where A (|) and notch(s) (#) are before being aligned
    my @spaces = (' ')x26;
    $spaces[0] = '|';
    $spaces[ord($_)-ord('A')] = '#' for split //,$rtn{notch};
    my $tyre = join('',@spaces);
    push @{$rtn{display}}, [$rtn{window}, $tyre, $alpha, $rtn{rotor}, '='x25];

    # now we align the tyre and the rtn{window} to accomodate the ring setting
    my $offset = ord($ring)-ord('A');
    $tyre =~ s/^(.{$offset})(.+)$/$2$1/;
    $rtn{window} =~ s/^(.{$offset})(.+)$/$2$1/;
    push @{$rtn{display}}, [$rtn{window}, $tyre, $alpha, $rtn{rotor}, '='x25];

    # now we adjust the tyre, rtn{window} and rtn{rotor} for the offset
    # distance between ring and the base setting
    my $set = (ord($setting) - ord($ring)) % 26;
    $tyre  =~ s/^(.{$set})(.+)$/$2$1/;
    $rtn{window} =~ s/^(.{$set})(.+)$/$2$1/;
    $rtn{rotor} =~ s/^(.{$set})(.+)$/$2$1/;
    push @{$rtn{display}}, [$rtn{window}, $tyre, $alpha, $rtn{rotor}, '='x25];
    
    # need to adjust the rtn{roor} to accomodate the set value.  the moves the
    # transform values backwards in the alphabet
    my $shift_alpha = $alpha =~ s/(.+)(.{$set})/$2$1/r; # nb the pattern split is reverse from above
    eval "\$rtn{rotor} =~ tr/$alpha/$shift_alpha/";
    push @{$rtn{display}}, [$rtn{window}, $tyre, $alpha, $rtn{rotor}, '='x25];
    return wantarray ? %rtn : \%rtn;
}
#ZZZ

# _Set_stecker DONE #AAA
sub _Set_stecker {
    my @input = @{shift @_};
    my %stecker = map {$_ => $_} ('A' .. 'Z');
    for (@input) {
	next unless defined;
        my ($left, $right) = split //;
        $stecker{$left} = $right;
        $stecker{$right} = $left;
    }
#   map {$stecker{$_} = $_} grep {! exists $stecker{$_}} ('A' .. 'Z');
    return join('',@stecker{sort keys %stecker});
}
#ZZZ

## Show_rotors #AAA
#sub Show_rotors {
#    my @state = @{shift @_};
#    my @window = ();
#    for (1..3) {
#        $state[4-$_]{window} =~ /^(.)/;
#        push @window,$1;
#    }
#    return join(' ',@window);
#}
##ZZZ

# _Step_rotor DONE #AAA
sub _Step_rotor {
    my %rtn = %{shift @_};
#   p %rtn;
    map {s/^(.)(.+)$/$2$1/} @rtn{qw(window rotor)};
    eval "\$rtn{rotor} =~ tr/ABCDEFGHIJKLMNOPQRSTUVWXYZ/ZABCDEFGHIJKLMNOPQRSTUVWXY/";
#   p %rtn;
#   die 'one step';
    return wantarray ? %rtn : \%rtn;
}
#ZZZ

# _Step_machine DONE #AAA
sub _Step_machine {
    my @state = (@_);
#   p @state;

    my %rotor_f = %{$state[1]};
    my %rotor_m = %{$state[2]};
    my %rotor_s = %{$state[3]};

    my $pawl_f = $rotor_f{window} =~ /^$rotor_f{notch}/ ? 1 : 0;
    my $pawl_m = $rotor_m{window} =~ /^$rotor_m{notch}/ ? 1 : 0;
    %rotor_f = _Step_rotor(\%rotor_f);
    if ($pawl_f) {
        %rotor_m = _Step_rotor(\%rotor_m);
    }
    if ($pawl_m) {
        %rotor_m = _Step_rotor(\%rotor_m) unless $pawl_f;
        %rotor_s = _Step_rotor(\%rotor_s);
    }
    $state[1] = \%rotor_f;
    $state[2] = \%rotor_m;
    $state[3] = \%rotor_s;
#   p @state;

    return wantarray ? @state : \@state;
}
#ZZZ

# _Encrypt_letter DONE #AAA
sub _Encrypt_letter {
    my @rotors = @{shift @_};
    my $char = shift;
    my @subs = ();
    @rotors = _Step_machine(@rotors);

    push @subs, $char;
    # through the stecker
    eval "\$char =~ tr/$alpha/$rotors[0]/";
    push @subs, $char;

    # through the rotors
    for (qw{1 2 3}) {
	eval "\$char =~ tr/$alpha/$rotors[$_]{rotor}/";
	push @subs, $char;
    }
    # through the reflector
    eval "\$char =~ tr/$alpha/$rotors[4]/";
    push @subs, $char;
    # backwards through the rotors
    for (qw{3 2 1}) {
	eval "\$char =~ tr/$rotors[$_]{rotor}/$alpha/";
	push @subs, $char;
    }
    # finally back through the stecker
    eval "\$char =~ tr/$rotors[0]/$alpha/";
    push @subs, $char;
    
    return (\@rotors, $char, \@subs);
}
#ZZZ

# _Build_wires DONE #AAA
sub _Build_wires {
    # this structure captures the right-to-left and left-to-right transitions
    # through the machine.
    my %struct = (
        stecker=>{ r_l=>qq($_[0] $_[1]), l_r=>qq($_[8] $_[9]), },
        rotors=>[
            { r_l=>qq($_[1] $_[2]), l_r=>qq($_[7] $_[8]), },
            { r_l=>qq($_[2] $_[3]), l_r=>qq($_[6] $_[7]), },
            { r_l=>qq($_[3] $_[4]), l_r=>qq($_[5] $_[6]), },
        ],
        reflector=>qq($_[4] $_[5]),
    );

    my @wires;
    my $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

    # first we wire up the reflector and push that on the return list;
    # essentially we only do half of what we need for the rotors and stecker
    # see next section for more info
    my @reflector = map {" $_ "} split //, $alpha;
    my ($enter, $exit) = split /\W/, $struct{reflector};
    $enter = ord($enter) - ord('A');
    $exit  = ord($exit)  - ord('A');
    $reflector[$enter] =~ s/ (\w) /+$1</;
    $reflector[$exit]  =~ s/ (\w) /+$1>/;
    my ($start, $end) = $enter<$exit ? ($enter, $exit) : ($exit, $enter);
    for ($start+1..$end-1) {
        $reflector[$_] =~ s/ /|/;
    }
    push @wires, [@reflector];

    # now we map the rotors and stecker. we use the ascii < and > to show flow
    # direction, + to show direction change (horiz to vert).  first we map
    # things flowing right to left (how the enigma is wired) then we map going
    # the other way.  but this all happens within a single rotor or stecker
    # nb. rotors are traversed in reverse order so we can make output easier
    # to construct
    for my $rotor (reverse(@{$struct{rotors}}), $struct{stecker}) {

        # build the left and right halves of the rotor.  we are left/right
        # contacts to right/left contacts
        my @right = map {"  $_"} split //, $alpha;
        my @left  = map {"$_  "} split //, $alpha;

        # we parse the enter and exit contacts from the right-to-left motion
        # for the respective 'rotor'.
        my ($enter1, $exit1) = split /\W/, $rotor->{r_l};
        $enter1 = ord($enter1) - ord('A');
        $exit1  = ord($exit1)  - ord('A');
        my $fix_right = $enter1; # we may need to fix a cross-over point later.
        $right[$enter1] =~ s/  / </; # mapping entry flow contact
        $left[$enter1]  =~ s/  /+ /; # mapping entry dir change
        $left[$exit1]   =~ s/  /< /; # mapping exit flow contact
        # put pipes to show connections between flow and dir change characters
        ($start, $end) = $enter1<$exit1 ? ($enter1, $exit1) : ($exit1, $enter1);
        for ($start+1..$end-1) {
            $left[$_] =~ s/  /| /;
        }

        # repeat all above for the left-to-right movement.
        my ($enter2, $exit2) = split /\W/, $rotor->{l_r};
        $enter2 = ord($enter2) - ord('A');
        $exit2  = ord($exit2)  - ord('A');
        my $fix_left = $enter2;
        $left[$enter2]   =~ s/  /> /;
        $right[$enter2] =~ s/  / +/;
        $right[$exit2]  =~ s/  / >/;
        ($start, $end) = $enter2<$exit2 ? ($enter2, $exit2) : ($exit2, $enter2);
        for ($start+1..$end-1) {
            $right[$_] =~ s/  / |/;
        }
        # force the fix locations to have flow direction.  case where a pipe
        # moves over a flow symbol.  do this after the rest have been mapped
        $right[$fix_right] =~ s/ ./ </;
        $left[$fix_left] =~ s/. /> /;

        # prepare the tmp array that holds the work we just did
        # 25 rows that consists of the left/right contact points and wires
        my @tmp;
        push @tmp, map {join(' ',$left[$_], $right[$_])} (0..25); 
        # for the row with a '+' we want all space to be '-'. this gives our transition to the other contact point
        map {s/ /-/g} grep {/[\+]/} @tmp;
        # silly correction when enter1==exit1 or enter2==exit2.  want to force
        # the crossover point to be a flow direction.  i.e. a straight through
        # connection
        $tmp[$enter1] =~ s/\+/</ if $enter1 == $exit1;
        $tmp[$enter2] =~ s/\+/>/ if $enter2 == $exit2;
        push @wires, [@tmp];
    }
    # finally we join all rows using pipes so they 'look' like a rotor in
    # presentation.
    my @rtn;
    for my $row (0..25) {
        push @rtn, join('|     |', map {$wires[$_][$row]} (0..4));
    }
    return wantarray ? @rtn : \@rtn;
}
#ZZZ

# _Show_positions DONE AAA
sub _Show_positions {
    my $file = 'etc/alphabet.txt';
    my @lines = path($file)->lines({chomp=>1});

    my @alphas;
    for my $l (@_) {
	$l =~ s/^(.)(.+)?$/$1/;
	push @alphas, [grep {/$l/} @lines];
    }
    my @output;
    while (my ($ndx, $line) = each ($alphas[0])) {
	push @output, ["\t\t\t\t".join("\t", $alphas[0][$ndx],$alphas[1][$ndx],$alphas[2][$ndx])];
    }
    return wantarray ? @output : \@output;
}
#ZZZ

# Configure_machine DONE #AAA
sub Configure_machine {
    my %input = %{shift @_};
    my %rotor_db = Enigma::_Load_rotors($input{rotor_file});
    my @rtn;
    push @rtn, Enigma::_Set_stecker($input{stecker}//[undef]);
    while (my ($ndx,$val) = each (@{$input{rotors}})) {
	push @rtn, {Enigma::_Get_rotor($rotor_db{$val}, $input{rings}[$ndx], $input{settings}[$ndx])};
    }
    push @rtn, $rotor_db{$input{reflector}}{rotor};
    return wantarray ? @rtn : \@rtn;
}
#ZZZ

# State_check DONE #AAA
sub State_check {
    my %input = %{shift @_};
    my @rotors = @{$input{rotors}};
    my $state_check = $input{state_check};
    for my $ndx (1,2,3) {
	system('clear');
	my $rotor = $rotors[$ndx];
	warn "config steps for rotor $ndx";
	my @display = @{$rotor->{display}};
	if ($state_check > 1) {
	    for my $step (0,1,2) {
		say $_ for @{$display[$step]};
	    }
	}
	say $_ for @{$display[3]};
	my $tmp = <STDIN>;
    }
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
	    ($rotor_aref, $char, undef) = _Encrypt_letter($rotor_aref, $char);
	    $rtn{$word}{xfrm} .= $char;
	}
    }
    say join(' ', @strings);
    say join(' ', map {$rtn{$_}{xfrm}} @strings);
}
#ZZZ

# Encrypt_interactive DONE #AAA
sub Encrypt_interactive {
    my %input = %{shift @_};
    my $rotor_aref  = $input{rotors};
    my $wiring      = $input{wiring};
    my $transitions = $input{transitions};

    my @data = path("etc/lightboard.txt")->lines({chomp=>1});
    my $blank = $nl x @data;
    my %mapping;
    for my $letter ('A'..'Z') {
	$mapping{$letter} = [map {s/[^$letter\n]/ /gr} @data];
    }
    my $input;
    my $output;
    system('clear');
    say @$_ for (Enigma::_Show_positions(map {$rotor_aref->[$_]{window}} (3,2,1)));
    say ''; # blank line
    print "? ";
    chomp ($input = <STDIN>);
    until ($input =~ /^(?i)quit(.+)?\z/) {
	system('clear');
	($rotor_aref, $output, my $steps) = _Encrypt_letter($rotor_aref, uc $input);
	say @$_ for (Enigma::_Show_positions(map {$rotor_aref->[$_]{window}} (3,2,1)));
	say ''; # blank line
	say for ($wiring ? (_Build_wires(@$steps)) : @{$mapping{$output}});
	say join('->', @$steps) if $transitions;
    } continue {
	print "? ";
	chomp ($input = <STDIN>);
    }

}
#ZZZ

1;
