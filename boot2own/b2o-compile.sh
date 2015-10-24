#!/bin/bash
#
# b2o-compile.sh compiles a patch winexe binary that has the ablity of
# passing NTLM hashes.
#
# b2o-compile.sh is part of boot2own-1.0
# boot2own-1.0 creates rapid automated attacks that takes
# advantage of unauthorized physical access to Windows workstations.
#
# copyright (C) 2014 xor-function
# license BSD-3
#
#--------------------------------------------------------------------

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
     read -e answer
     case $answer in
          [Yy] ) break;;
          [Yy][eE][sS] ) break;;
          [nN] ) printf "\nExiting Now \n"; exit;;
          [Nn][oO] ) printf "\nExiting Now \n"; exit;;
            *  ) printf "\nNot Valid, Answer y or n\n";;
     esac
  done
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
             clear
             echo "[!] Do you have an internet connection???"
             exit 2
         fi
      fi
   fi
   echo "[+] tubes working..."
}

spath="$( cd "$(dirname "$0")" ; pwd -P )"
chk_usr root
chk_tubes
clear

echo "WARNINIG----WARNING----WARNING"
echo "This will only compile patched winexe on a Debian distro (Ubuntu/Crunchbang)"
echo "Use on another GNU/Linux distro will most likely fail..."
echo "continue (y/n)?"
get_permission

if [ -d $spath/srcs/binary/ ]; then
   echo "[!] detected binary folder you have run this before, cleaning up..."
   rm -rf $spath/srcs/binary/
fi

if [ -d $spath/srcs/winexe-waf/ ]; then
   echo "[!] detected extracted winexe sources, cleaning up..."
   rm -rf $spath/srcs/winexe-waf/
fi

echo "[*] installing dependancies..."
mgw64=$(apt-cache search gcc-mingw-w64)
if [[ -z $mgw64 ]]; then

  echo "[!] gcc-mingw-w64 was not found on your repos, cannot contiune"
  echo "    are you on Ubuntu 12.04 ?"
  exit

 else

   get_aptpkg 'binutils-mingw-w64'
   get_aptpkg 'gcc-mingw-w64'
   get_aptpkg 'mingw-w64'
   get_aptpkg 'mingw-w64-dev'

fi

dep="autoconf cmake comerr-dev g++ gcc libtalloc-dev libtevent-dev libpopt-dev libbsd-dev libc6-dev zlib1g-dev make python-dev xterm"

for i in $dep; do
get_aptpkg $i
done

if [ -e  $spath/srcs/binary/pwinexe ]; then
	echo "[+] pwinexe is already compiled, exiting..."
        exit
fi

echo "[*] preping winexe and samba sources"
cd $spath/srcs/
tar xzf winexe-waf.tar.gz
cd winexe-waf/
rm -rf samba/
cp ../samba-hashpass.patch .
cp ../samba-4.0.4.tar.gz .
tar xzf samba-4.0.4.tar.gz
mv samba-4.0.4 samba

echo "[*] Patching winexe..."
cd samba
patch -p1 < ../../samba-hashpass.patch

echo "[*] Compiling a patched winexe binary, please wait..."
cd ../source
./waf configure --use-samba-tree-headers
./waf build
mkdir $spath/srcs/binary
mv build/winexe $spath/srcs/binary/pwinexe
cd $spath

echo "[*] copying pwinexe to live-files/boot-2-own/"
cp $spath/srcs/binary/pwinexe $spath/live-files/boot-2-own/
chmod +x $spath/live-files/boot-2-own/pwinexe

if [ ! -e $spath/live-files/boot-2-own/pwinexe ]; then
     echo "[!] something went wrong, check if pwinexe is in $spath/winexe-build/binary/"
     echo "    if it is check folder permissions if not check dependancies."
     exit 1
fi

echo "[+] Done compiling, now use b2o-isogen.sh to generate liveCD."
exit

