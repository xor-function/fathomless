
<# 
ps1-obfuscator

originally intended to work on Invoke-Mimikatz when it needs to be copied to disk.
Found this technique should work on most ps1 scripts.

xor-function

#>

function gen-enccmd {

	param($clrcmd)

	$bytescmd = [System.Text.Encoding]::Unicode.GetBytes($clrcmd.ToString()) 
	$enccmd = [Convert]::ToBase64String($bytescmd) 

	return $enccmd
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
	$rs = New-Object System.Random 
	1..40 | % { $key += [Char]$rs.next(97,122) }
	$kstring = [string]::join("", ($key))
	return $kstring
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

function b64Enc {

	param (
	
		#[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[string]$file = $( read-host "Path to script " )
	)

	$test = test-path $file
	if ($test) 
	{ 	
	
		$string = get-content .\$file | out-string
		$base64str = base64string-encode $string
	
		$base64str > .\b64-enc-str.txt
		
		write-output "`n[+] Base64 encoded strings saved to b64-enc-str.txt"
		
		$msg = "`[+] To execute use the following command:`n"
		$msg += 'powershell -c "&{IEX([System.Text.Encoding]::UTF8.getString([System.Convert]::Frombase64String((gc .\b64-enc-str.txt|out-string))))}"'
		$msg += "`n"
		
		write-output $msg
	
		

	} else { write-output "`n[!] file not found, check path!`n" }
	
}

function obfu {

	param (
	
		#[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[string]$file = $( read-host "Path to script " )
	)
	
	$test = test-path $file
	if ($test) 
	{ 
	
		$string = get-content .\$file | out-string
		$base64str = base64string-encode $string

		$k = gen-key

		$ob = obfuscate-base64 hide $k $base64str
	
		$ob > .\obfuscated-base64.txt

		$msg = "[+] key : $k " + "`n"
		$msg += "[+] obfuscated string saved to obfuscated-base64.txt" + "`n"
		$msg += "[+] to run:" + "`n"
		$msg += 'powershell -c "&{IEX $(gc .\launcher.ps1|out-string);execute .\obfuscated-base64.txt ' + $k + ' }"' + "`n"
		
		write-output $msg
		
	} else { write-output "`n[!] file not found, check path!`n" }

}

function deobfu { 

	param (
	
		#[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[string]$file = $( read-host "Path to obfuscated data " ),
		
		#[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[string]$key = $( read-host "Enter de-obfuscation key " )
		
	)
	
	$test = test-path $file
	if ($test) 
	{ 
	
		$obfuscatedStr = get-content .\$file | out-string
		$b64str = obfuscate-base64 clear $key $obfuscatedStr
		$string = base64string-decode $b64str
	
		$string > .\original-strings.txt 
	
		write-output "[+] Original de-obfuscated text saved to original-strings.txt"
		
	} else { write-output "`n[!] file not found, check path!`n" }
	
}
	
	
function main {

	param (
		#[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[string]$num = $( read-host "Enter option #" )
	)

	if ($num -eq '1') 
	{ 
		write-output "`n[>] Enter path to .ps1 script to base64 encode only`n"

		b64Enc; exit 
	}

	if ($num -eq '2') 
	{ 
		write-output "`n[>] Enter path to .ps1 script to turn into obfuscated base64`n"

		obfu; exit 
	}

	if ($num -eq '3') 
	{ 
		write-output "`n[>] enter path to obfuscated text file.`n"

		deobfu; exit 
	}

	write-output "[!] Enter number 1 or 2, try again."

}	

$menu = @"


==============================================================
		PowerShell Script Obfuscator 					
==============================================================

[?] Select fuction to use
	1. base64 encode
 	2. obfuscate  
 	3. de-obfuscate

"@

write-output $menu

while (1) { main }
