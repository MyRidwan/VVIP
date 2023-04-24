#!/bin/bash
MYIP=$(wget -qO- ipinfo.io/ip);

colornow=$(cat /etc/ssnvpn/theme/color.conf)
NC="\e[0m"
COLOR1="$(cat /etc/ssnvpn/theme/$colornow | grep -w "TEXT" | cut -d: -f2|sed 's/ //g')"
COLBG1="$(cat /etc/ssnvpn/theme/$colornow | grep -w "BG" | cut -d: -f2|sed 's/ //g')"

APIGIT=$(cat /etc/ssnvpn/github/api)
EMAILGIT=$(cat /etc/ssnvpn/github/email)
USERGIT=$(cat /etc/ssnvpn/github/username)


function setapi(){
    clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}              • IPVPS GITHUB API •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"

if [[ -f /etc/ssnvpn/github/api && -f /etc/ssnvpn/github/email && /etc/ssnvpn/github/username ]]; then
   rec="OK"
else
    mkdir /etc/ssnvpn/github > /dev/null 2>&1
fi

read -p " E-mail   : " EMAIL1
if [ -z $EMAIL1 ]; then
echo -e "$COLOR1│${NC}   [INFO] Please Input Your Github Email Adress"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ip
fi

read -p " Username : " USERNAME1
if [ -z $USERNAME1 ]; then
echo -e "$COLOR1│${NC}   [INFO] Please Input Your Github Username"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ip
fi

read -p " API      : " API1
if [ -z $API1 ]; then
echo -e "$COLOR1│${NC}  [INFO] Please Input Your Github API"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -n 1 -s -r -p "  Press any key to back on menu"
menu-ip
fi

sleep 2
echo "$EMAIL1" > /etc/ssnvpn/github/email
echo "$USERNAME1" > /etc/ssnvpn/github/username
echo "$API1" > /etc/ssnvpn/github/api
echo "ON" > /etc/ssnvpn/github/gitstat
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}               • REGISTER IPVPS •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}   [INFO] Github Api Setup Successfully"
echo -e "$COLOR1│${NC}"
echo -e "$COLOR1│${NC}   • Email : $EMAIL1"
echo -e "$COLOR1│${NC}   • User  : $USERNAME1"
echo -e "$COLOR1│${NC}   • API   : $API1"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ip
}

function viewapi(){
    clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}             • LIST REGISTER IP •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}  • Email : $EMAILGIT"
echo -e "$COLOR1│${NC}  • User  : $USERGIT"
echo -e "$COLOR1│${NC}  • API   : $APIGIT"
echo -e "$COLOR1│${NC}  • All U need Is Create a new repository "
echo -e "$COLOR1│${NC}    & Nammed : permission "
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ip
}

function add_ip(){
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}               • REGISTER IPVPS •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
rm -rf /root/izinvps
read -p "│  NEW IPVPS : " daftar
echo -e "$COLOR1│${NC}"
echo -e "$COLOR1│${NC}  [INFO] Checking the IPVPS!"
sleep 1
REQIP=$(curl -sS https://raw.githubusercontent.com/${USERGIT}/izinvps/ipuk/ip | awk '{print $4}' | grep $daftar)
if [[ $daftar = $REQIP ]]; then
echo -e "$COLOR1│${NC}  [INFO] VPS IP Already Registered!!"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ip
else
echo -e "$COLOR1│${NC}  [INFO] OK! IP VPS is not Registered!"
echo -e "$COLOR1│${NC}  [INFO] Lets Regester it!"
sleep 3
clear
fi
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}               • REGISTER IPVPS •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
read -p "│  User Name  : " client
if [ -z $client ]; then
cd
echo -e "$COLOR1│${NC}  [INFO] Please Input client"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ip
fi


read -p "│  EXP Date   : " exp
if [ -z $exp ]; then
cd
echo -e "$COLOR1│${NC}   [INFO] Please Input exp date"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ip
fi

x="ok"

satu="ON"
dua="OFF"
while true $x != "ok"
do
echo -e "$COLOR1│${NC}"
echo -e "$COLOR1│${NC}  ${COLOR1}[01]${NC} • ADMIN   ${COLOR1}[02]${NC} • NORMAL"
echo -e "$COLOR1│${NC}"
echo -ne "│  Input your choice : "; read list
echo ""
case "$list" in 
   1) isadmin="$satu";break;;
   2) isadmin="$dua";break;;
esac
done


exp=$(date -d "$exp days" +"%Y-%m-%d")
hariini=$(date -d "0 days" +"%Y-%m-%d")
git config --global user.email "${EMAILGIT}" &> /dev/null
git config --global user.name "${USERGIT}" &> /dev/null
git clone https://github.com/${USERGIT}/izinvps.git &> /dev/null
cd /root/izinvps/ &> /dev/null
rm -rf .git &> /dev/null
git init &> /dev/null
touch ip &> /dev/null
touch newuser &> /dev/null
TEXT="
Name        : $client 
Admin Panel : $isadmin
Exp         : $exp 
IPVPS       : $daftar 
Reg Date    : $hariini
" 
echo "${TEXT}" >>/root/izinvps/newuser 
echo "### $client $exp $daftar $isadmin" >>/root/izinvps/ip 
git add .
git commit -m register &> /dev/null
git branch -M ipuk &> /dev/null
git remote add origin https://github.com/${USERGIT}/izinvps.git &> /dev/null
git push -f https://${APIGIT}@github.com/${USERGIT}/izinvps.git &> /dev/null
sleep 1
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}               • REGISTER IPVPS •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}  Client IP Regested Successfully"
echo -e "$COLOR1│${NC}"
echo -e "$COLOR1│${NC}  Client Name   : $client"
echo -e "$COLOR1│${NC}  Admin Panel   : $isadmin"
echo -e "$COLOR1│${NC}  IP VPS        : $daftar"
echo -e "$COLOR1│${NC}  Register Date : $TheKill"
echo -e "$COLOR1│${NC}  Expired Date  : $exp"
cd
rm -rf /root/izinvps
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}              •  •            $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ip
}
function delipvps(){
clear
rm -rf /root/izinvps &> /dev/null
git config --global user.email "${EMAILGIT}" &> /dev/null
git config --global user.name "${USERGIT}" &> /dev/null
git clone https://github.com/${USERGIT}/izinvps.git &> /dev/null
cd /root/izinvps/ &> /dev/null
rm -rf .git &> /dev/null
git init &> /dev/null
touch ip &> /dev/null
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}                 • DELETE IPVPS •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
grep -E "^### " "/root/izinvps/ip" | cut -d ' ' -f 2-4 | nl -s '. '
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo ""
read -rp "   Please Input Number : " nombor
if [ -z $nombor ]; then
cd
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}                 • DELETE IPVPS •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1│${NC}   [INFO] Please Input Correct Number"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ip
fi

name1=$(grep -E "^### " "/root/izinvps/ip" | cut -d ' ' -f 2 | sed -n "$nombor"p) #name
exp=$(grep -E "^### " "/root/izinvps/ip" | cut -d ' ' -f 3 | sed -n "$nombor"p) #exp
ivps1=$(grep -E "^### " "/root/izinvps/ip" | cut -d ' ' -f 4 | sed -n "$nombor"p) #ip
sed -i "s/### $name1 $exp $ivps1//g" /root/izinvps/ip &> /dev/null
hariini2=$(date -d "0 days" +"%Y-%m-%d")
TEXTD="
Name     : $name1
IPVPS    : $ivps1  
Status   : Deleted on  $hariini2
" 
echo "${TEXTD}" >>/root/izinvps/delete_log  &> /dev/null

git add . &> /dev/null
git commit -m remove &> /dev/null
git branch -M ipuk &> /dev/null
git remote add origin https://github.com/${USERGIT}/izinvps.git &> /dev/null
git push -f https://${APIGIT}@github.com/${USERGIT}/izinvps.git &> /dev/null
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}               • REGISTER IPVPS •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}  Client IP Deleted Successfully"
echo -e "$COLOR1│${NC}"
echo -e "$COLOR1│${NC}  Ip VPS       : $ivps1"
echo -e "$COLOR1│${NC}  Expired Date : $exp"
echo -e "$COLOR1│${NC}  Client Name  : $name1"
cd
rm -rf /root/izinvps
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ip
}

function renewipvps(){
 clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}               • REGISTER IPVPS •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
rm -rf /root/izinvps
git config --global user.email "${EMAILGIT}" &> /dev/null
git config --global user.name "${USERGIT}" &> /dev/null
git clone https://github.com/${USERGIT}/izinvps.git
cd /root/izinvps/
rm -rf .git
git init
touch ip
echo -e "   [ ${Lyellow}INFO${NC} ] Checking list.."

NUMBER_OF_CLIENTS=$(grep -c -E "^### " "/root/izinvps/ip")
if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
  clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}               • REGISTER IPVPS •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}   [INFO] You have no existing clients!"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ip
fi
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}               • REGISTER IPVPS •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
grep -E "^### " "/root/izinvps/ip" | cut -d ' ' -f 2-4 | nl -s '. '
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
  if [[ ${CLIENT_NUMBER} == '1' ]]; then
    read -rp " Select one client [1]: " CLIENT_NUMBER
  else
    read -rp " Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
  fi
if [ -z $CLIENT_NUMBER ]; then
cd
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}               • REGISTER IPVPS •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}   [INFO] Please Input Correct Number"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ip
fi
done
echo -e ""
read -p " Expired (days): " masaaktif
if [ -z $masaaktif ]; then
cd
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}               • REGISTER IPVPS •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}  [INFO] Please Input Correct Number"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ip
fi
name1=$(grep -E "^### " "/root/izinvps/ip" | cut -d ' ' -f 2 | sed -n "${CLIENT_NUMBER}"p) #name
exp=$(grep -E "^### " "/root/izinvps/ip" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p) #exp
ivps1=$(grep -E "^### " "/root/izinvps/ip" | cut -d ' ' -f 4 | sed -n "${CLIENT_NUMBER}"p) #ip

now=$(date +%Y-%m-%d)
d1=$(date -d "$exp" +%s)
d2=$(date -d "$now" +%s)
exp2=$(((d1 - d2) / 86400))
exp3=$(($exp2 + $masaaktif))
exp4=$(date -d "$exp3 days" +"%Y-%m-%d")
sed -i "s/### $name1 $exp $ivps1/### $name1 $exp4 $ivps1/g" /root/izinvps/ip
git add .
git commit -m renew
git branch -M ipuk
git remote add origin https://github.com/${USERGIT}/izinvps.git
git push -f https://${APIGIT}@github.com/${USERGIT}/izinvps.git
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}               • REGISTER IPVPS •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}  Client IP VPS Renew Successfully"
echo -e "$COLOR1│${NC}"
echo -e "$COLOR1│${NC}  Ip VPS        : $ivps1"
echo -e "$COLOR1│${NC}  Renew Date    : $now"
echo -e "$COLOR1│${NC}  Days Added    : $masaaktif Days"
echo -e "$COLOR1│${NC}  Expired Date  : $exp4"
echo -e "$COLOR1│${NC}  Client Name   : $name1"
cd
rm -rf /root/izinvps
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ip
}

function useripvps(){
clear
rm -rf /root/izinvps
git config --global user.email "${EMAILGIT}"
git config --global user.name "${USERGIT}"
git clone https://github.com/${USERGIT}/izinvps.git
cd /root/izinvps/
rm -rf .git
git init
touch ip
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}               • REGISTER IPVPS •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
grep -E "^### " "/root/izinvps/ip" | cut -d ' ' -f 2 | nl -s '. '
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
cd
rm -rf /root/izinvps
echo -e ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ip
}
function resetipvps(){
clear
rm -f /etc/ssnvpn/github/email
rm -f /etc/ssnvpn/github/username
rm -f /etc/ssnvpn/github/api
rm -f /etc/ssnvpn/github/gitstat
echo "OFF" > /etc/ssnvpn/github/gitstat
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}              • RESET GITUB API •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}  [INFO] Github API Reseted Successfully"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ip  
}
Isadmin=$(curl -sS https://raw.githubusercontent.com/MyRidwan/izinvps/ipuk/ip | grep $MYIP | awk '{print $5}')
if [ "$Isadmin" = "OFF" ]; then
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}            • PREMIUM USER ONLY •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} [INFO] Only PRO Users Can Use This Panel"
echo -e "$COLOR1│${NC} [INFO] Buy Premium Membership : "
echo -e "$COLOR1│${NC} [INFO] PM : "
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ip  
fi
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}               • REGISTER IPVPS •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
GITREQ=/etc/ssnvpn/github/gitstat
if [ -f "$GITREQ" ]; then
    cekk="ok"
else 
    mkdir /etc/ssnvpn/github
    touch /etc/ssnvpn/github/gitstat
    echo "OFF" > /etc/ssnvpn/github/gitstat
fi

stst1=$(cat /etc/ssnvpn/github/gitstat)
if [ "$stst1" = "OFF" ]; then
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}               • REGISTER IPVPS •              ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}   • You Need To Set Github API First!"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -n 1 -s -r -p "   Press any key to Set API"
setapi
fi
stst=$(cat /etc/ssnvpn/github/gitstat)
if [ "$stst" = "ON" ]; then
APIOK="CEK API"
rex="viewapi"
else
APIOK="SET API"
rex="setapi"
fi
if [ "$stst" = "ON" ]; then
ISON="RESET API"
ressee="resetipvps"
else
ISON=""
ressee="menu-ip"
fi
echo -e "   $COLOR1 [01]$NC • $APIOK        $COLOR1 [04]$NC • RENEW IPVPS" 
echo -e "   $COLOR1 [02]$NC • ADD IPVPS      $COLOR1 [05]$NC • LIST IPVPS"
echo -e "   $COLOR1 [03]$NC • DELETE IPVPS   $COLOR1 [06]$NC • $ISON"
echo -e "   "
echo -e "   $COLOR1 [00]$NC • GO BACK"

echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -p " Select menu :  "  opt
echo -e   ""
case $opt in
01 | 1) clear ; $rex ;;
02 | 2) clear ; add_ip ;;
03 | 3) clear ; delipvps ;;
04 | 4) clear ; renewipvps ;;
05 | 5) clear ; useripvps ;;
06 | 6) clear ; $ressee ;;
00 | 0) clear ; menu ;;
*) clear ; menu-ip ;;
esac
