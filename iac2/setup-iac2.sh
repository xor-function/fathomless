#!/bin/bash
#
# setup iaa monitor server
#

title() {

        echo "[*]==================================================[*]"
        echo "[*] Installing...                IA Agent C2 Server  [*]"
        echo "[*]==================================================[*]"

}

# func requires args: username
chk_usr() {

	if [ "$(whoami)" != "$1" ]; then
		echo "[!] you need to be root, exiting..."
        exit
    fi

}

chk_tubes() {

    echo "[*] Checking your tubes..."
    if ! ping -c 1 google.com > /dev/null 2>&1  ; then
		if ! ping -c 1 yahoo.com > /dev/null 2>&1  ; then
			if ! ping -c 1 bing.com > /dev/null 2>&1 ; then
                echo "[!] Do you have an internet connection?, exiting..."
                exit 1
            fi
		fi
	fi
    echo "[+] tubes working..."

}

# func requires argument
get_aptpkg() {

    tpkg=$(dpkg -s $1 | grep "install ok install")
    if [ -z "$tpkg" ]; then

        if [ -z $aptup ]; then
            # rm -rf /var/lib/apt/lists/*
            apt-get update
            aptup=1
        fi

        echo "[*] installing $1"
        if ! apt-get -y install $1; then
            echo "[!] APT failed to install "$1", are your repos working? Exiting..."
            exit 1
        fi

    else
        echo "[+] $1 is already installed"
    fi
}

get_permission() {
while true; do
       printf "\n"
       read ansr
       case $ansr in
              [Yy] ) break;;
              [Nn] ) echo "[!] exiting..."; exit;;
                 * ) echo "[!] Not a valid entry, please answer y or n";;
       esac
done
echo "Continuing..."

}

# Uses a foldername, directory as a parameter
folder_perm() {
	chown www-data:www-data $1
	chmod 755 $1
}


# uses a filename as a parameter
file_perm() {
	chown www-data:www-data $1
	chmod 644 $1
}

rstr_short() {
	echo $(cat /dev/urandom | tr -dc '[:alnum:]' | head -c 8 )
}

rstr_long() {
	echo $(cat /dev/urandom | tr -dc _A-Z-a-z-0-9 | head -c 30 | base64)
}

clear
title
chk_usr root
chk_tubes

if [ ! -e ./lighttpd.conf ]; then
	echo "[!] could not find the lighttpd.conf file, cannot continue..."
	echo "[ ] exiting..."
	exit 1
elif [ ! -e ./iaa-monitor.pl ];then
        echo "[!] could not find the uptime-agent-monitor.pl file, cannot continue..."
        echo "[ ] exiting..."
        exit 1
elif [ ! -e ./inital-access-agent.ps1 ]; then
        echo "[!] could not find the client file, cannot continue..."
        echo "[ ] exiting..."
        exit 1
fi

if [ -e /etc/lighttpd/lighttpd.conf ]; then
	echo "[!]=====[!]=======[!]========[!]========[!]=========[!]===========[!]==========[!]"
	echo "[ ] lighttpd has been detected on your system"
	echo "[ ] the configuration files and ssl folder for lighttpd will be overwritten."
	echo "[ ] for the shell-handler. If you do NOT wish to continue take a look at the SSL"
	echo "[ ] setting in the included lighttpd.conf for the ssl settings."
	echo "[ ] continue? (y/n)"
	get_permission
	if [ -d /etc/lighttpd/ssl ]; then
		rm -rf /etc/lighttpd/ssl
	fi
fi

if [ -d /var/iac2 ]; then
	echo "[!] iac2 folder detected, folder contains info about systems runing the client"
	echo "[ ] by proceeding this folder will be deleted"
	echo "[ ] continue? (y/n)"
	get_permission
	rm -rf /var/iac2
fi

get_aptpkg lighttpd
get_aptpkg openssl
get_aptpkg perl
get_aptpkg libcgi-application-perl

## [ Fail2ban ] ##########

#get_aptpkg fail2ban
#cat ./fail2ban.conf > /etc/fail2ban/jail.conf
#service fail2ban restart


## [ WEB SERVER ] #########

cat ./lighttpd.conf > /etc/lighttpd/lighttpd.conf
mkdir /etc/lighttpd/ssl
folder_perm /etc/lighttpd/ssl
openssl req -new -x509 -keyout /etc/lighttpd/ssl/server.pem -out /etc/lighttpd/ssl/server.pem -days 365 -nodes
ps_keyprint=$(openssl x509 -in /etc/lighttpd/ssl/server.pem -fingerprint -noout | cut -d'=' -f2 | tr -d : )
sh_keyprint=$(openssl x509 -in /etc/lighttpd/ssl/server.pem -fingerprint -noout | cut -d'=' -f2 )

## [ MOVING FILES ] #######

# cleaning up default files generated upon installation
rm -rf /var/www/*

echo "[*] Placing perl cgi app in web root folder [ /var/www ]"
cp iaa-monitor.pl /var/www/index.pl

echo "[*] Setting web root folder permissions..."
file_perm /var/www/index.pl

echo "[*] Generating random password for shell-handler."
mkdir -p /var/iac2/systems

pass=$(rstr_long)
echo $pass > /var/iac2/init-pass

folder_perm /var/iac2
folder_perm /var/iac2/systems

service lighttpd restart

echo "[]=========================================================================================[]"
echo "[]"
echo "[] Paste this URL in the inital-access-agent.ps1 script "
echo "[]"
echo "[] \$uri = https://your-ip-or-domain/"
echo "[]"
echo "[] Client password needed to be granted access to connect to web app"
echo "[] Paste this in the agent powershell or perl script as the \$key variable"
echo "[]"
echo "[] \$key = $pass "
echo "[]"
echo "[] The following is the thumb/finger print of your self-signed certificate"
echo "[] paste in the \$certfingerprint variable "
echo "[]"
echo "[] Powershell:  "
echo "[] \$certfingerprint = $ps_keyprint "
echo "[]"
echo "[] Bash Shell Linux:"
echo "[] \$certfingerprint = $sh_keyprint "
echo "[]"
echo "[]=========================================================================================[]"

exit 0
