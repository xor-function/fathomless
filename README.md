# fathomless

#### async-shell-handler

Provides a prototype C&C web server along with an asynchronous powershell client, and a basic command interface.
The server is hosted on an lighttpd server using HTTPS with a self-signed certificate. 

The async client performs basic key fingerprint comparison and authentication. These values are randomly generated 
upon installation. All requests and responses from the client are performed via HTTPS GET requests with url safe base64 encoded strings.

Persistence has not been currently implemented, and if the client exits or the system reboots the process will be terminated.

#### gen-obfuscated

Enables execution of a command string on systems while evading countermeasures, specifically AV signature based detection. This is accomplished by focusing on obfuscating command strings that typically downloads a short script involved in first-stage/initial access.

So an example execution chain would be:
```
[command string downloader (gen-obfuscated)] -> [remote stager script (async-client)] -> [load payloads; shellcode, dll's, other ps1 scripts]
```

Ideally most code should be loaded and executed in memory only.

This code is not made to make reverse engineering impossible or even slow it down. It's specific purpose is to evade automated signature based detection.

Currently supported methods.
* vbscript 
* vba macros
* hta

#### boot2own

A toolkit that generates a live OS from a crunchbang iso. When a workstation is booted to this live environment it's hard drive is mounted and the NTLM hash of the local admin (RID 500) is extracted. The admin hash is then leveraged 
in attacks against a Windows domain network using a patched winexe binary.

For more details browse to each folder.

##### Use only with permission from network owners (make sure it's in writing). 
