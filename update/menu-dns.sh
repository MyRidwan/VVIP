#!/bin/bash
MYIP=$(wget -qO- ipinfo.io/ip);

colornow=$(cat /etc/ssnvpn/theme/color.conf)
NC="\e[0m"
COLOR1="$(cat /etc/ssnvpn/theme/$colornow | grep -w "TEXT" | cut -d: -f2|sed 's/ //g')"
COLBG1="$(cat /etc/ssnvpn/theme/$colornow | grep -w "BG" | cut -d: -f2|sed 's/ //g')"

APIGIT=$(cat /etc/ssnvpn/github/api)
EMAILGIT=$(cat /etc/ssnvpn/github/email)
USERGIT=$(cat /etc/ssnvpn/github/username)

export RED='\033[0;31m';
export GREEN='\033[0;32m';
export ERROR="[${RED}ERROR${NC}]";
export INFO="[${GREEN}INFO${NC}]";
# // Export Color & Information
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[0;33m'
export BLUE='\033[0;34m'
export PURPLE='\033[0;35m'
export CYAN='\033[0;36m'
export LIGHT='\033[0;37m'
export NC='\033[0m'


function setdns(){
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}                 • USERS LOGS •                ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
read -p "│  DNS : " setdnss

if [ -z $setdnss ]; then
echo -e "$COLOR1│${NC}"
echo -e "$COLOR1│${NC}  ${ERROR} DNS Cannot Be Empty";
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-dns 
else
echo "$setdnss" > /root/dns
echo -e "$COLOR1│${NC}  ${INFO} Copy DNS To Resolv.conf";
echo "nameserver $setdnss" > /etc/resolv.conf
sleep 2
echo -e "$COLOR1│${NC}  ${INFO} Copy DNS To Resolv.conf.d/head";
echo "nameserver $setdnss" > /etc/resolvconf/resolv.conf.d/head
sleep 2
echo -e "$COLOR1│${NC}  ${INFO} DNS Update Successfully";
fi
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-dns 
}

function resdns(){
    clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}                 • USERS LOGS •                ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
read -p "│   Reset Default DNS [Y/N]: " -e answer
if [[ "$answer" = 'y' ]]; then
dnsfile="/root/dns"
if test -f "$dnsfile"; then
rm /root/dns
fi
echo -e "$COLOR1│${NC}"
echo -e "$COLOR1│${NC}  ${INFO} Delete Resolv.conf DNS";
echo "nameserver 8.8.8.8" > /etc/resolv.conf
sleep 2
echo -e "$COLOR1│${NC}  ${INFO} Delete Resolv.conf.d/head DNS";
echo "nameserver 8.8.8.8" > /etc/resolvconf/resolv.conf.d/head
sleep 2
else
echo -e "$COLOR1│${NC}"
echo -e "$COLOR1│${NC}   $INFO Operation Cancelled By User"
fi
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}              •  •            $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-dns 
}

clear
echo -e "$PURPLE┌─────────────────────────────────────────────────┐${NC}"
echo -e "$PURPLE│ ${BLUE}                $NC•$BLUE USERS LOGS $NC•                 $PURPLE │$NC"
echo -e "$PURPLE└─────────────────────────────────────────────────┘${NC}"
echo -e " $PURPLE┌───────────────────────────────────────────────┐${NC}"
dnsfile="/root/dns"
if test -f "$dnsfile"; then
udns=$(cat /root/dns)
echo -e "$COLOR1│${NC}"
echo -e "$COLOR1│${NC}   Active DNS : $udns"
echo -e "$COLOR1│${NC}"
fi
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}01${NC}]  CHANGE DNS  "
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}02${NC}]  RESET DNS  "
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}03${NC}]  CONTENT CEK "
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}04${NC}]  RENEW"
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}05${NC}]  USER"
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}06${NC}]  REBOOT"
echo -e " $PURPLE│$NC "
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}00${NC}]  Go Back"
echo -e " $PURPLE└───────────────────────────────────────────────┘${NC}"
echo -e "$PURPLE┌──────────────────────${NC} BY $PURPLE───────────────────────┐${NC}"
echo -e "$PURPLE│${BLUE}                 $NC•$BLUE RstoreVPN $NC•                $PURPLE│$NC"
echo -e "$PURPLE└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -p " Select menu :  "  opt
echo -e   ""
case $opt in
01 | 1) clear ; setdns ;;
02 | 2) clear ; resdns ;;
03 | 3) clear ; delipvps ;;
04 | 4) clear ; renewipvps ;;
05 | 5) clear ; useripvps ;;
06 | 6) clear ; $ressee ;;
00 | 0) clear ; menu ;;
*) clear ; menu-dns ;;
esac
