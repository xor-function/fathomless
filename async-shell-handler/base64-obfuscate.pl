#!/usr/bin/perl
# 
# base64 obfuscator
#
# Encodes a raw string into base64 then uses a polyalphabetic 
# routine to shift only the alaphabetic characters using a 
# random alpabetic key. The purpose behind this is to force 
# manual cracking to get the original base64 encoded data.
#
# 				xor-function, license GPLv3


use strict;
use warnings;
use MIME::Base64;
             
sub enc_string {

        my $string = $_[0];
	# Passing an empty string to encode_base64 to prevent any newlines
        my $enc_string = encode_base64($string, '');

        return $enc_string;

}

# requires a true base64 encoded string, use after deobfuscating
sub dec_string {

        my $raw_string = $_[0];
        my $dec_string = decode_base64($raw_string);

        return $dec_string;
}

# requires integer which determines character length of string
sub gen_key {

        my $lenght = $_[0];

        my @chr = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", 
		   "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z" 
               );
 
        my $rloop = int($lenght);

        my $rstring;
        while ($rloop != 0) {
                $rstring .= $chr[int(rand(26))];
                $rloop--;
        }

        return $rstring;
}

# function obfuscates base64 encoded string using a polyalphabetic cipher
# routing to defeat automated analysis engines.
sub obfuscate_base64 { 

	my $action = $_[0];
	my $key	   = $_[1];
	my $string = $_[2];

	my %alpha = (  "1" => "A",
                       "2" => "B",
                       "3" => "C",
                       "4" => "D",
                       "5" => "E",
                       "6" => "F",
                       "7" => "G",
                       "8" => "H",
                       "9" => "I",
                       "10" => "J",
                       "11" => "K",
                       "12" => "L",
                       "13" => "M",
                       "14" => "N",
                       "15" => "O",
                       "16" => "P",
                       "17" => "Q",
                       "18" => "R",
                       "19" => "S",
                       "20" => "T",
                       "21" => "U",
                       "22" => "V",
                       "23" => "W",
                       "24" => "X",
		       "25" => "Y",
		       "26" => "Z",
	);

	my %inv_alpha = reverse %alpha;

	my @strg_array = split(//, $string);
        my @key_array  = split(//, $key);

	my $obase64;
	my $count = 0;
        foreach my $ch (@strg_array) {

		 if ( $ch =~ /[a-z,A-Z]/m )
    {

			my $uch = uc $ch; 
                        my $ival = $inv_alpha{$uch};
                        my $s = $key_array[$count];

                        unless ($s) { $count = 0; $s = $key_array[0]; }  # reset key to beginging
			
			my $S = uc $s;
			my $shift_val = $inv_alpha{$S};
			
			my $val;
			if ( $action =~ /hide/m ) 
			     { $val = int($ival) + int($shift_val); }
			else { $val = int($ival) - int($shift_val); }


			if ( int($val) < '1'  ) { $val = int($val) + int(26) }
			if ( int($val) > '26' ) { $val = int($val) - int(26) }

			my $nchar = $alpha{$val};
				
			if ( $ch =~ /[a-z]/m ) 
			     { my $lchar = lc $nchar; $obase64 .= $lchar; }  
			else { my $uchar = uc $nchar; $obase64 .= $uchar; } 

  } else { $obase64 .= $ch; }

	} 

	$count++;	
	return $obase64;

} 


sub main { 

  my $string = $_[0];

	my $clear_b64 = enc_string($string); 
	my $key = gen_key("70");
	
	# obfuscate and de-ofuscate data to test integrity of obfuscated data, debugging 
	my $ob64 = obfuscate_base64( 'hide', $key, $clear_b64 );
	my $clear_ob64 = obfuscate_base64 ( 'clear', $key, $ob64 );
	my $clear_string = dec_string($clear_ob64);

#	print "[ clear string ] : $string \n";  
#	print "[ clear base64 ] : $clear_b64";
	print "\n[ obfuscated base64 ]\n $ob64";
#	print "[ clear base64 ] : $clear_ob64";
	print "\n[ clear string ]\n $clear_string";
	print "\n[ key ]\n $key \n\n";
} 

if (@ARGV < 1 || @ARGV > 1) {  print "[!] usage: ./base64-obfuscate.pl [your string or variable that contains a string] \n"; exit(); } 
main(@ARGV);

