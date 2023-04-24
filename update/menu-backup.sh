#!/bin/bash
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
###########- COLOR CODE -##############
colornow=$(cat /etc/ssnvpn/theme/color.conf)
NC="\e[0m"
RED="\033[0;31m" 
COLOR1="$(cat /etc/ssnvpn/theme/$colornow | grep -w "TEXT" | cut -d: -f2|sed 's/ //g')"
COLBG1="$(cat /etc/ssnvpn/theme/$colornow | grep -w "BG" | cut -d: -f2|sed 's/ //g')"                    
# // Export Color & Information
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[0;33m'
export BLUE='\033[0;34m'
export PURPLE='\033[0;35m'
export CYAN='\033[0;36m'
export LIGHT='\033[0;37m'
export NC='\033[0m'

clear
echo -e "$PURPLE┌─────────────────────────────────────────────────┐${NC}"
echo -e "$PURPLE│ ${BLUE}                $NC•$BLUE MENU BACKUP $NC•                $PURPLE │$NC"
echo -e "$PURPLE└─────────────────────────────────────────────────┘${NC}"
echo -e " $PURPLE┌───────────────────────────────────────────────┐${NC}"
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}01${NC}]  BACKUP VPS  "
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}02${NC}]  RESTORE VPS   "
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}03${NC}]  BACKUP API "
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}04${NC}]  RESET API"
echo -e " $PURPLE│$NC "
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}00${NC}]  Go Back"
echo -e " $PURPLE└───────────────────────────────────────────────┘${NC}"
echo -e "$PURPLE┌──────────────────────${NC} BY $PURPLE───────────────────────┐${NC}"
echo -e "$PURPLE│${BLUE}                 $NC•$BLUE RstoreVPN $NC•                $PURPLE│$NC"
echo -e "$PURPLE└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -p " Select menu :  "  opt
echo -e ""
case $opt in
01 | 1) clear ; backup ;;
02 | 2) clear ; restore ;;
03 | 3) clear ; menu3 ;;
04 | 4) clear ; menu4 ;;
00 | 0) clear ; menu ;;
*) clear ; menu-backup ;;
esac

       
