
# Launcher for obfuscated strings


function base64string-decode($encstring) {

	$decstring = [System.Text.Encoding]::UTF8.getString([System.Convert]::Frombase64String($encstring))

	return $decstring
}

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


function execute( $file, $key ) {

	if (!($key)){ write-output "`n[!] requires de-ofuscation key!`n"; exit }
	
	$test = test-path $file
	if ($test) { 
	
		$obb64 = get-content .\$file | out-string
		$b64str = obfuscate-base64 clear $key $obb64
		$str = base64string-decode $b64str
		
		IEX $str
	
	} else { write-output "`n[!] file not found, check path!`n" }
	

}

