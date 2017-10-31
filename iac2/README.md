# IAC2

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

Warning need to add OS detection so that the wmi c-types don't get used if windows is not
detected.

```
