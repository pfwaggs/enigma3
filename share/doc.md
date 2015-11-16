# NAME

enigma.pl

# synopsis

enigma3.pl (pass\_options) (options) [--config file

# description

This is an enigma emulator. You configure via the command line or a config file.

Basic operation entails configuration and data entry.  If the data to be transformed is given on the command line then
the program runs in automatic mode.  Otherwise, enigma3.pl runs as an interactive program.

# (options)

- **---build\_config**
    tells the system to save the initial configuration to a file

- **---rotor\_file**

    This is used to override the default of 'etc/rotors.txt'.  

- **---rotors R:R:R**

    Specify the rotors in left to right order. Use Roman numerals (traditional nomenclature). 
    \(default: II:I:III)

- **---ring (L:L:L|N:N:N)**

    Specify the ring setting of the rotors. You can use either the letter ('A') or the number ('01') for the values. 
    \(default: X:M:V)

- **---position (L:L:L|N:N:N)**

    Specify the initial position of the rotors. Follows the same format as for 'ring'.
    \(default: A:B:L)

- **---stecker LL(:LL....)**

    This specifies the stecker pairs to be used. Specify as pairs of letters separated by ':'.
    \(default: AM:FI:NV:PS:TU:WZ)

- **---reflector L**

    Specify the reflector to use. (default is the 'A' reflector)

# (pass-through\_options)

these options are passed through to various library calls.

- **---transitions**

    Shows the substition chain; a simple list of letters that show key->stecker->rotor1->rotor2->rotor3->reflector->rotor3->rotor2->rotor1->stecker->lamp.  This option just shows those values.

- **---state\_check**

    Used to show the initial state of the machine.  Mainly for debugging.

- **---wiring**

    Shows a simplified ascii graphic of the wiring state of the machine at that time.

- **---fancy\_wiring**

    This shows a graphic that looks more like the rotor should.  The mapping is kept internal to the rotor.  There are lines that connect one side of the rotor to the other and some lines that connect the rotors.

# example

enigma3.pl 
(nb. the daily key is FOL but the message key is ABL)

plaintext : FEIND LIQEI NFANT ERIEK OLONN EBEOB AQTET XANFA NGSUE  
ciphertext: GCDSE AHUGW TQGRK VLFGX UCALX VYMIG MMNMF DXTGN VHVRM  

plaintext : DAUSG ANGBA ERWAL DEXEN DEDRE IKMOS TWAER TSNEU STADT  
ciphertext: MEVOU YFZSL RHDRR XFJWC FHUHM UNZEF RDISI KBGPM YVXUZ  

\(example from Frode Weierud\'s [Cryptocellar website](http://cryptocellar.web.cern.ch/cryptocellar/enigma/EMsg1930.html).

Another site with good info is [Bletchley Park](http://www.codesandciphers.org.uk).

# author

Bill Pemberton
<pfwaggs@gmail.com>
