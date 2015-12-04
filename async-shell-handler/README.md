# async-shell-handler
asynchronous multi-shell handler

Includes a server side cgi application and a powershell client.
It performs handeling of systems that have executed the async-client
script. This allows the individual running the server hosting the
cgi to enter shell commands to be executed by clients asynchronously.

The information is exchanged in an encoded format, the secure nature
directly relies upon the use of SSL/TLS.

# Install

Developed for use one a regular Ubuntu 14.04 LTS server distro.
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

* get-info                       
Displays a summary of current host

* exec-script [name-of-script]  
Executes script hosted server side in /var/async-shell/ps-scripts by IEX 
requires the name of the script filename as a parameter.

* obfuscate [name of text file / script] 
(shorcut method for use with text files)
Uses a polyalphabetic obfuscation method on base64 strings writes obfuscated
string to file and provides a de-obfuscation key.

* de-obfuscate [(name of text file / script), (key)]
(shorcut method for use with text files)
Performs the inverse of the obfuscation function requires the text file with the
obfuscated base64 data and de-obfuscation key as parameters.

* gen-key
generates a random alphabetic string for use with the obfuscate-base64 function

* obfuscate-base64 [(action:hide or clear ), (key: obfuscation or de-ofuscation), (base64-string)]
The function that contains the obfuscation engine, it works only with clear base64 data.

* gen-enccmd [your command string]
Generates a PowerShell formatted encoded command. Insure to quote your command
string.
```
gen-enccmd "cmd /c ipconfig /all"
```
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

For more info http://nightowlconsulting.com/asynchronous-shell-handler/
