# ps12bat
Powershell script to batch script

This will encode and embed the ps1 script selected in a batch script 
using base64 encoding.

upon execution on target system it will extract the base64 encoded 
script to a base64 encoded file, then it will create a userland registry 
key to run a powershell command to load the encoded file and execute it 
upon user login.

# use
```
ps C:\>.\ps12bat.ps1
```
Then enter the path of the script you wish to convert.
