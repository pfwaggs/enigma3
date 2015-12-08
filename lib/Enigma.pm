package Enigma;

# preamble #AAA
use warnings;
use strict;
use v5.18;

use Term::ReadKey;
use Path::Tiny;
use Data::Printer;
use JSON::PP;
my $nl = "\n";
my $tb = "\t";
our $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

sub _qp {
    my @input = @_;
    warn $input[0];
    p $input[1];
    die $input[2]//0;
}

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
    $tyre =~ s/^(.{$ring})(.+)$/$2$1/;
    $rtn{window} =~ s/^(.{$ring})(.+)$/$2$1/;
    push @{$rtn{display}}, [$rtn{window}, $tyre, $alpha, $rtn{rotor}, '='x25];

    # now we adjust the tyre, rtn{window} and rtn{rotor} for the offset
    # distance between ring and the base setting
    my $set = ($setting - $ring) % 26;
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
    return join('',@stecker{sort keys %stecker});
}
#ZZZ

# _Step_rotor DONE #AAA
sub _Step_rotor {
    my %rtn = %{shift @_};
    map {s/^(.)(.+)$/$2$1/} @rtn{qw(window rotor)};
    eval "\$rtn{rotor} =~ tr/ABCDEFGHIJKLMNOPQRSTUVWXYZ/ZABCDEFGHIJKLMNOPQRSTUVWXY/";
    return wantarray ? %rtn : \%rtn;
}
#ZZZ

# _Step_machine DONE #AAA
sub _Step_machine {
    my @state = (@_);

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

# _Build_fancy_wires DONE #AAA
sub _Build_fancy_wires {
    # this structure captures the right-to-left and left-to-right transitions
    # through the machine.
    my %struct = (
        stecker=>{ r_l=>qq($_[0] $_[1]), l_r=>qq($_[8] $_[9]), },
        rotors=>[
            { r_l=>qq($_[3] $_[4]), l_r=>qq($_[5] $_[6]), },
            { r_l=>qq($_[2] $_[3]), l_r=>qq($_[6] $_[7]), },
            { r_l=>qq($_[1] $_[2]), l_r=>qq($_[7] $_[8]), },
        ],
        reflector=>qq($_[4] $_[5]),
    );

    my @wires;
    my $alpha = $Enigma::alpha; #'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

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
    for my $rotor (@{$struct{rotors}}, $struct{stecker}) {

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
    my $spaces = 11;
    my $dashes = ($spaces-1)/2;
    $spaces = ' 'x$spaces;
    $dashes = '-'x$dashes;
    for my $row (0..25) {
	my $str = join("|$spaces|", map {$wires[$_][$row]} (0..4)) =~ s/((<|>)\w\|)($spaces)(\|\w(<|>))/$1$dashes$2$dashes$4/gr;
	$str =~ s/((<|>)\|)($spaces)/$1$dashes$2$dashes/;
	$str =~ s/(<\w)$/$1------- key/;
	$str =~ s/(>\w)$/$1--- lamp/;
        push @rtn, $str;
    }
    return wantarray ? @rtn : \@rtn;
}
#ZZZ

# _Build_wires DONE #AAA
sub _Build_wires {
    my $alpha = $Enigma::alpha;
    # this structure captures the right-to-left and left-to-right transitions
    # through the machine.
    my %struct = (
        stecker=>{ r_l=>[$_[0], $_[1]], l_r=>[$_[8], $_[9]], },
        rotors=>[
            { r_l=>[$_[3], $_[4]], l_r=>[$_[5], $_[6]], },
            { r_l=>[$_[2], $_[3]], l_r=>[$_[6], $_[7]], },
            { r_l=>[$_[1], $_[2]], l_r=>[$_[7], $_[8]], },
        ],
        reflector=>{ r_l=>[$_[4], $_[5]] },
    );
    
    # adjust struct to have ascii ord vice char values.  saves from doing
    # regex search
    for my $wheel (values %struct) {
	if (ref $wheel eq 'HASH') {
	    for my $key (keys %$wheel) {
		map {$_ = ord($_)-ord('A')} @{$wheel->{$key}};
	    }
	} else {
	    for my $href (@$wheel) {
		for my $key (keys %$href) {
		    map {$_ = ord($_)-ord('A')} @{$href->{$key}};
		}
	    }
	}
    }

    # initialize the wheels array
    my @wheels;
    for my $wheel (0..4) {
	push @wheels, [map {" $_ "} split //, $alpha];
    }

    # do the reflector (index 0 in wheels) first then do the rest
    # first we pick up direction then we add pipes to make it look good
    my ($enter, $exit) = @{$struct{reflector}{r_l}};
    $wheels[0][$enter] =~ s/ (\w) $/+$1</;
    $wheels[0][$exit]  =~ s/ (\w) $/+$1>/;
    my ($start, $end) = $enter<$exit ? ($enter, $exit) : ($exit, $enter);
    for ($start+1..$end-1) {
        $wheels[0][$_] =~ s/ /|/;
    }

    my @bunch = (@{$struct{rotors}},$struct{stecker}); # we have to create this list so while doesn't loop forever
    while (my ($ndx, $href) = each (@bunch)) {
	$wheels[1+$ndx][$href->{r_l}[0]] =~ s/ $/</;
	$wheels[1+$ndx][$href->{r_l}[1]] =~ s/^ /</;
	$wheels[1+$ndx][$href->{l_r}[0]] =~ s/^ />/;
	$wheels[1+$ndx][$href->{l_r}[1]] =~ s/ $/>/;
    }

    # nb the wheels consist of arrays of arrays so we need to glue the rows
    # together in column order.  after the join, we change space to - when
    # between two <'s or >'s.  we do not have the cases > < or < > to worry about
    # also add some on the ends to show key and lamp values.
    my @rtn;
    for my $row (0..25) {
	my $str = join('     ', map {$wheels[$_][$row]} (0..4)) =~ s/(<|>)(\s{5})(<|>)/$1-----$3/gr;
	$str =~ s/(\w<)$/$1------- key/;
	$str =~ s/(\w>)$/$1--- lamp/;
        push @rtn, $str;
    }
    return wantarray ? @rtn : \@rtn;

}
#ZZZ

# _Show_positions DONE AAA
sub _Show_positions {
    my $file = '../etc/alphabet.txt';
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

# Build_config #AAA
sub Build_config {
    my %hash = %{shift @_};
    my $file = $hash{build_config};
    delete $hash{build_config};
    my $jpp = JSON::PP->new->pretty->canonical;
    path($file)->spew([$jpp->encode(\%hash)]);
}
#ZZZ

# Parse #AAA
sub Parse {
    my %hash = %{shift @_};
    my $split_char = ':';
    $hash{rotors}    = [reverse split /$split_char/, uc $hash{rotors}];
    $hash{rings}     = [reverse split /$split_char/, uc $hash{rings}];
    $hash{settings}  = [reverse split /$split_char/, uc $hash{settings}];
    $hash{stecker}   = [split /$split_char/, uc $hash{stecker}];
    $hash{reflector} = uc $hash{reflector};
    $hash{rings}    = [map {/\d/ ? --$_ : (ord($_)-ord('A'))} map {s/^0//r} @{$hash{rings}}];
    $hash{settings} = [map {/\d/ ? --$_ : (ord($_)-ord('A'))} map {s/^0//r} @{$hash{settings}}];
    return wantarray ? %hash : \%hash;
}
#ZZZ

# Configure_machine DONE #AAA
sub Configure_machine {
    my %input = %{shift @_};
    my %rotor_db = Enigma::_Load_rotors("../$input{rotor_file}");
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

    my $rotor_aref   = $input{rotors};
    my $wiring       = $input{wiring};
    my $fancy_wiring = $input{fancy_wiring};
    my $transitions  = $input{transitions};

    my @data = path("../etc/lightboard.txt")->lines({chomp=>1});
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
	if ($wiring) {
	    say for _Build_wires(@$steps);
	} elsif ($fancy_wiring) {
	    say for _Build_fancy_wires(@$steps);
	} else {
	    say for @{$mapping{$output}};
	}
	say join('->', @$steps) if $transitions;
    } continue {
	print "? ";
	chomp ($input = <STDIN>);
    }

}
#ZZZ

# Menu_pick #AAA
sub Menu_pick {
    # input options :
    #	clear screen: (1)/0
    #	max: -1/(1)/n/n+
    #	header: undef
    #	prompt: pick lines:
    #	preset: undef
    #
    # input menu :
    # input array < \@ or @

# defaults #AAA
    my %opts = (clear=>1, max=>1, header=>undef, prompt=>'pick lines: ',presets=>[],);
    %opts = (%opts, %{shift @_}) if ref $_[0] eq 'HASH';
    my @data = ref $_[0] eq 'ARRAY' ? @{shift @_} : @_;
    my $max = $opts{max} == -1 ? @data : $opts{max};
#ZZZ

#   warn 'starting with :'.p %opts; die 'first'.$nl;
    my $picked = '*';
    my $select = $picked^' ';
    my @choices = (' ') x @data;
    my $seq = 1;

    my @_menu = map {{str=>$data[$_], s=>' ', x=>1+$_}} keys @data;
    for (@{$opts{presets}}) {
	$_menu[$_]{s} ^= $select;
	$_menu[$_]{order} = $seq++;
    }
    p @_menu;
    my $picks;
    while (1) {
	system('clear') if $opts{clear};
	say $opts{header} if defined $opts{header};
	say join(' : ', @{$_}{qw{s x str}}) for @_menu;
	print $opts{prompt};
	chomp ($picks = <STDIN>);
	last if $picks =~ /^(?i)q/;
	for (map {$_-1} $picks =~ /^(?i)a/ ? (1..$max) : split /\D/,$picks) {
	    $_menu[$_]{s} ^= $select;
	    $_menu[$_]{order} = $seq++;
	}
    } continue {
	last if ($max == grep {$_->{s} eq $picked} @_menu) and ($picks !~ /^(?i)a/);
    }
    my @found = sort {$_menu[$a]{order} <=> $_menu[$b]{order}} grep {$_menu[$_]{s} eq $picked} keys @_menu;
    my @rtn = @found <= $max ? @found : @found[0..$max-1];
    return wantarray ? @rtn : \@rtn;
}
#ZZZ

1;
