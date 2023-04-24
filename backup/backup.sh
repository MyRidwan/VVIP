#!/bin/bash
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
###########- COLOR CODE -##############
colornow=$(cat /etc/ssnvpn/theme/color.conf)
NC="\e[0m"
RED="\033[0;31m" 
COLOR1="$(cat /etc/ssnvpn/theme/$colornow | grep -w "TEXT" | cut -d: -f2|sed 's/ //g')"
COLBG1="$(cat /etc/ssnvpn/theme/$colornow | grep -w "BG" | cut -d: -f2|sed 's/ //g')"                    
###########- END COLOR CODE -##########

BURIQ () {
    curl -sS https://raw.githubusercontent.com/myridwan/izinvps/ipuk/ip > /root/tmp
    data=( `cat /root/tmp | grep -E "^### " | awk '{print $2}'` )
    for user in "${data[@]}"
    do
    exp=( `grep -E "^### $user" "/root/tmp" | awk '{print $3}'` )
    d1=(`date -d "$exp" +%s`)
    d2=(`date -d "$biji" +%s`)
    exp2=$(( (d1 - d2) / 86400 ))
    if [[ "$exp2" -le "0" ]]; then
    echo $user > /etc/.$user.ini
    else
    rm -f /etc/.$user.ini > /dev/null 2>&1
    fi
    done
    rm -f /root/tmp
}

MYIP=$(curl -sS ipv4.icanhazip.com)
Name=$(curl -sS https://raw.githubusercontent.com/myridwan/izinvps/ipuk/ip | grep $MYIP | awk '{print $2}')
echo $Name > /usr/local/etc/.$Name.ini
CekOne=$(cat /usr/local/etc/.$Name.ini)

Bloman () {
if [ -f "/etc/.$Name.ini" ]; then
CekTwo=$(cat /etc/.$Name.ini)
    if [ "$CekOne" = "$CekTwo" ]; then
        res="Expired"
    fi
else
res="Permission Accepted..."
fi
}

PERMISSION () {
    MYIP=$(curl -sS ipv4.icanhazip.com)
    IZIN=$(curl -sS https://raw.githubusercontent.com/myridwan/izinvps/ipuk/ip | awk '{print $4}' | grep $MYIP)
    if [ "$MYIP" = "$IZIN" ]; then
    Bloman
    else
    res="Permission Denied!"
    fi
    BURIQ
}
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
PERMISSION
if [ -f /home/needupdate ]; then
red "Your script need to update first !"
exit 0
elif [ "$res" = "Permission Accepted..." ]; then
echo -ne
else
red "Permission Denied!"
exit 0
fi

IP=$(curl -sS ipv4.icanhazip.com);
date=$(date +"%Y-%m-%d")

#itoken=$(curl -sS https://raw.githubusercontent.com/SSHSEDANG4/update/main/asu)

MYIP=$(curl -sS ipv4.icanhazip.com)
NameUser=$(curl -sS https://raw.githubusercontent.com/myridwan/izinvps/ipuk/ip | grep $MYIP | awk '{print $2}')


clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}             • BACKUP PANEL MENU •             ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC}  [INFO] Create password for database"
read -rp "   [INFO] Enter password : " -e InputPass
sleep 1
if [[ -z $InputPass ]]; then
exit 0
fi
echo -e "$COLOR1│${NC}  [INFO] Processing... "
mkdir -p /root/backup
sleep 2

cp -r /root/.acme.sh /root/backup/ &> /dev/null
cp /etc/passwd /root/backup/ &> /dev/null
cp /etc/group /root/backup/ &> /dev/null
cp /etc/shadow /root/backup/ &> /dev/null
cp /etc/gshadow /root/backup/ &> /dev/null
cp /etc/ppp/chap-secrets /root/backup/chap-secrets &> /dev/null
cp /etc/ipsec.d/passwd /root/backup/passwd1 &> /dev/null
cp -r /var/lib/ssnvpn-pro/ /root/backup/ssnvpn-pro &> /dev/null
cp -r /etc/xray /root/backup/xray &> /dev/null
cp -r /home/vps/public_html /root/backup/public_html &> /dev/null
cp -r /etc/cron.d /root/backup/cron.d &> /dev/null
cp /etc/crontab /root/backup/crontab &> /dev/null
cd /root
zip -rP $InputPass $NameUser.zip backup > /dev/null 2>&1

##############++++++++++++++++++++++++#############
LLatest=`date`
Get_Data () {
git clone https://github.com/myridwan/backup.git /root/user-backup/ &> /dev/null
}

Mkdir_Data () {
mkdir -p /root/user-backup/$NameUser
}

Input_Data_Append () {
if [ ! -f "/root/user-backup/$NameUser/$NameUser-last-backup" ]; then
touch /root/user-backup/$NameUser/$NameUser-last-backup
fi
echo -e "User         : $NameUser
last-backup : $LLatest
" >> /root/user-backup/$NameUser/$NameUser-last-backup
mv /root/$NameUser.zip /root/user-backup/$NameUser/
}

Save_And_Exit () {
    DATE=$(date +'%d %B %Y')
    cd /root/user-backup
    git config --global user.email "alnurridwan112@gmail.com" &> /dev/null
    git config --global user.name "myridwan" &> /dev/null
    rm -rf .git &> /dev/null
    git init &> /dev/null
    git add . &> /dev/null
    git commit -m backup &> /dev/null
    git branch -M ipuk &> /dev/null
    git remote add origin https://github.com/myridwan/backup
    git push -f https://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@github.com/myridwan/backup.git &> /dev/null
}

if [ ! -d "/root/user-backup/" ]; then
sleep 1
echo -e "$COLOR1│${NC}  [INFO] Getting database... "
Get_Data
Mkdir_Data
sleep 1
echo -e "$COLOR1│${NC}  [INFO] Getting info server... "
Input_Data_Append
sleep 1
echo -e "$COLOR1│${NC}  [INFO] Processing updating server...... "
Save_And_Exit
fi
link="https://raw.githubusercontent.com/myridwan/backup/ipuk/$NameUser/$NameUser.zip"
sleep 1
echo -e "$COLOR1│${NC}  [INFO] Backup done "
sleep 1
echo
sleep 1
echo -e "$COLOR1│${NC}  [INFO] Generete Link Backup "
echo -e "$COLOR1│${NC}"
sleep 2
echo -e "$COLOR1│${NC}  The following is a link to your vps data backup file.
$COLOR1│${NC}  Your VPS IP $IP
$COLOR1│${NC}
$COLOR1│${NC}  $link
$COLOR1│${NC}  save the link pliss!
$COLOR1│${NC}
$COLOR1│${NC}  If you want to restore data, please enter the link above.
$COLOR1│${NC}  Thank You For Using Our Services"
cd
rm -rf /root/backup &> /dev/null
rm -rf /root/user-backup &> /dev/null
rm -f /root/$NameUser.zip &> /dev/null
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}              • RidwanSTORE •                $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo
read -n 1 -s -r -p "   Press any key to back on menu"
menu-backup
