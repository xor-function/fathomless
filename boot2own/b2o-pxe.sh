#!/bin/bash
#
# b2o-pxe.sh creates a pxe server that serves the B2O LiveCD.
#
# b2o-pxe.sh is part of boot2own-1.0
# boot2own-1.0 creates rapid automated attacks that takes
# advantage of unauthorized physical access to Windows workstations.
#
# copyright (C) 2014 xor-function
# license BSD-3
#
#--------------------------------------------------------------------

use() {
echo ""
echo "usage: ./b2o-pxe.sh boot2own.iso"
echo ""
}

# func requires args: username
check_usr() {
   if [ "$(whoami)" != "$1" ]; then
       echo "[!] you need to be root, exiting..."
       exit
   fi
}

tstamp() {
   date +"%F"_"%H":"%M"
}

# func requires aguments (full path/file name) and tstamp() func ****
make_runlog() {
   touch $1
   echo "script run on "$(tstamp)"" > $1
}

check_tubes() {
   echo "[*] Checking your tubes..."
   if ! ping -c 1 google.com > /dev/null 2>&1  ; then
      if ! ping -c 1 yahoo.com > /dev/null 2>&1  ; then
         if ! ping -c 1 bing.com > /dev/null 2>&1 ; then
             clear
             echo "[!] Do you have an internet connection???"
             exit 2
         fi
      fi
   fi
   echo "[+] tubes working..."
}

# func requires aguments ****
get_aptpkg() {

  tpkg=$(dpkg -s $1 | grep "install ok installed")
  if [ -z "$tpkg" ]; then

        if [ -z $aptup ]; then
           apt-get update
           aptup='1'
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
     read answer
     case $answer in
          [Yy] ) break;;
          [Yy][eE][sS] ) break;;
          [nN] ) printf "\nExiting Now \n"; exit;;
          [Nn][oO] ) printf "\nExiting Now \n"; exit;;
            *  ) printf "\nNot Valid, Answer y or n\n";;
     esac
 done
}

check_usr root

if [[ $# -gt 1 || $# -lt 1 ]] ; then
     use
     exit
fi

if [[ ! -f $1 ]]; then
   use
   echo "[!] Thats not a file"
   exit
fi

fchk=$(echo "$1" | grep -i "boot2own.iso")

if [ -z $fchk ]; then
    echo "[!] Did you change the iso's name?"
    exit
fi

IMG=$1
PSIP='10.0.0.1'
NMSK='255.255.255.0'
IFS=. read -r if1 if2 if3 if4 <<< "$PSIP"
IFS=. read -r msk1 msk2 msk3 msk4 <<< "$NMSK"
NETIP=$(printf "%d.%d.%d.%d\n" "$((if1 & msk1))" "$((if2 & msk2))" "$((if3 & msk3))" "$((if4 & msk4))")

IFS=. read -r ip1 ip2 ip3 ip4 <<< "$PSIP"
DHCPL=$(printf "%d.%d.%d.%d\n" "$((ip1))" "$((ip2))" "$((ip3))" "$((if4 + 4 ))")

IFS=. read -r ip1 ip2 ip3 ip4 <<< "$PSIP"
DHCPH=$(printf "%d.%d.%d.%d\n" "$((ip1))" "$((ip2))" "$((ip3))" "$((if4 + 99 ))")

clear
echo ""
echo "DEVICE IP WILL BE SET TO 10.0.0.1"
echo "To run this script properly it needs to run as root and have a working internet"
echo "connection. This script will install the apt packages dnsmasq and syslinux to"
echo "create a functioning PXE server. The network configuration of your eth0 interface"
echo "on your rpi will be modified acording to the above variables."
echo "The B2O iso file will be copied to /tftpboot/b2o"
echo "to have it boot over PXE"
echo ""
echo "WARNING---WARNING---WARNING"
echo "If you are using the eth0 connection for your main network connection this will"
echo "most likely disable your internet connection"
echo ""
echo "You may have to connect to the internet over WiFi or use a usb to ethernet adapter"
echo "The program wicd-curses may prove usefull for establising a wireless connection"
echo "with ease through ssh."
echo ""
echo "CONTINUE? (y/n)"

get_permission
check_usr root
check_tubes

if [ ! -e /var/log/rpi-pxe ]; then

   apt-get update
   get_aptpkg dnsmasq
   get_aptpkg syslinux-common

 else

   echo "You ran this script before, to continue it will erase the /tftpboot folder"
   echo "along with the interface and dnsmasq configuration files."
   echo "You need to perform a backup if any of the files are important to you."
   echo "CONTINUE? (y/n)?"

   get_permission
   rm -rf /tftpboot

fi

mkdir -p /tftpboot/{pxelinux.cfg,b2o}
cp /usr/lib/syslinux/{memdisk,menu.c32,vesamenu.c32,pxelinux.0} /tftpboot
mkdir /mnt/bt2own
echo "[*] mounting iso and extracting contents to PXE boot directory"
mount -t iso9660 -o loop $IMG /mnt/bt2own
if [ ! -d /mnt/bt2own/live ]; then
         echo "[!] mount failed, is this the correct iso?"
         exit
fi
echo "[*] Copying extracted iso content to /tftpboot"
cp /mnt/bt2own/live/{filesystem.squashfs,initrd.img,vmlinuz} /tftpboot/b2o/
if [ ! -f /tftpboot/b2o/vmlinuz ]; then
         echo "[!] something went wrong, exiting..."
         exit
fi
umount /mnt/bt2own
rm -rf /mnt/bt2own
#Begin writing to pxelinux.cfg/default
#||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||

cat > /tftpboot/pxelinux.cfg/default <<EOL

default boot2own
prompt 0
label boot2own
KERNEL b2o/vmlinuz
APPEND initrd=b2o/initrd.img boot=live config live-config.hostname=null live-config.username=b2o fetch=tftp://$PSIP/b2o/filesystem.squashfs

EOL
#||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
#Finished creating pxelinux.cfg/defualt


echo "[*] Writing to /etc/network/interfaces ..."
cat > /etc/network/interfaces << EOL
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
address $PSIP
netmask $NMSK
network $NETIP

EOL

echo "[*] Creating/writing to /etc/dnsmasq.conf"
cat > /etc/dnsmasq.conf << EOL
enable-tftp
tftp-root=/tftpboot
dhcp-boot=pxelinux.0
interface=eth0
dhcp-range=eth0,$DHCPL,$DHCPH,$NMSK,12h
log-queries
log-facility=/var/log/dnsmasq.log
server=208.67.222.222
no-resolv

EOL

# wrapping up....
ifdown eth0
ifup eth0

ipup=$(ip addr | grep eth0 | grep inet | awk -F" " '{print $2}'| cut -d'/' -f 1)

if [ -z $ipup ]; then
  echo "[!] IP address not set, trying again"
  ifdown eth0
  ifconfig eth0 down
  ifconfig eth0 up
  ifup eth0
  echo "[*] if IP is still not up after exit, restart networking manually"
fi

if ! service dnsmasq stop; then
     killall dnsmasq
      if ! service dnsmasq start; then
           echo "Something is probably using port 53 use"
           echo "sudo netstat -tapen | grep ":53""
           echo "to find out which program is causing problems"
           exit 7
      fi
 else
    service dnsmasq start
fi

make_runlog /var/log/rpi-pxe
echo "[+] Script finished successfully, exiting..."

exit 0
