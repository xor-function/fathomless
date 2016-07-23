# fathomless

#### async-shell-handler

Provides a prototype C&C web server along with an asynchronous powershell client, and a basic command interface.
The server is hosted on an lighttpd server using HTTPS with a self-signed certificate. Since the C&C is a cgi hosted on a lighttpd server you can edit the included lighttpd.conf to only allow connections from the expected IP range.

The async client performs basic key fingerprint comparison for the self-signed cert and basic authentication to the C&C. These values are randomly generated upon installation. All requests and responses from the client are performed via HTTPS GET requests with url safe base64 encoded strings.

The client initially operates in memory so if it exits or the system reboots the process will be terminated and flushed from memory.

Persistence has been added via the shortcut-inject and simple-persistence functions avaliable in the async and tcp powershell clients.

#### gen-obfuscated

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

#### boot2own

A toolkit that generates a live OS from a crunchbang iso. When a workstation is booted to this live environment it's hard drive is mounted and the NTLM hash of the local admin (RID 500) is extracted. The admin hash is then leveraged 
in attacks against a Windows domain network using a patched winexe binary.

* Note UEFI is not currently supported, I am working on a approach for this...

For more details browse to each folder.

##### Use only with permission from network owners (make sure it's in writing). 

#### Might? todo?

* add pdf/usb vector to gen-obfuscated.
* add the ability to reflectively load binaries/dll's.
