#!/bin/bash
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
###########- COLOR CODE -##############
AKUN="AKUN SSH"
TIMES="10"
CHATID="1210833546"
KEY="6006599143:AAEgstCAioq35JgX97HaW_G3TAkLKzLZS_w"
URL="https://api.telegram.org/bot$KEY/sendMessage"
colornow=$(cat /etc/ssnvpn/theme/color.conf)
NC="\e[0m"
RED="\033[0;31m" 
COLOR1="\033[1;36m"
COLBG1="\e[1;97;101m"                 
# // Export Color & Information
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[0;33m'
export BLUE='\033[0;34m'
export PURPLE='\033[0;35m'
export CYAN='\033[0;36m'
export LIGHT='\033[0;37m'
export NC='\033[0m'
red='\e[1;31m'
green='\e[1;32m'
NC='\e[0m'
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }

function addssh(){
clear
dnsdomain=$(cat /etc/xray/dns)
dnskey=$(cat /etc/slowdns/server.pub)
domen=`cat /etc/xray/domain`
portsshws=`cat ~/log-install.txt | grep -w "SSH Websocket" | cut -d: -f2 | awk '{print $1}'`
wsssl=`cat /root/log-install.txt | grep -w "SSH SSL Websocket" | cut -d: -f2 | awk '{print $1}'`

echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " ${COLBG1}            • SSH PANEL MENU •          ${NC} "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
read -p "   Username : " Login
read -p "   Owner     : " OWNER
read -p "Input Id Grup (-1001911868043) : " CHATIDGC
CEKFILE=/etc/xray/ssh.txt
if [ -f "$CEKFILE" ]; then
file001="OK"
else
touch /etc/xray/ssh.txt
fi

if grep -qw "$Login" /etc/xray/ssh.txt; then
echo -e "  [Error] Username \e[31m$Login\e[0m already exist"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
read -n 1 -s -r -p "  Press any key to back on menu"
menu-ssh
else
echo "$Login" >> /etc/xray/ssh.txt
fi

if [ -z $Login ]; then
echo -e " [Error] Username cannot be empty "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
read -n 1 -s -r -p "    Press any key to back on menu"
menu-ssh
fi

read -p "   Password : " Pass
if [ -z $Pass ]; then
echo -e "  [Error] Password cannot be empty "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ssh
fi
read -p "   Expired (hari): " masaaktif
if [ -z $masaaktif ]; then
echo -e "  [Error] EXP Date cannot be empty "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
read -n 1 -s -r -p "  Press any key to back on menu"
menu-ssh
fi
#####BOT-TRX
END
<☘️🔥TRX="
<code>INFO MASKU -Transaksi</code>
<code>────────────────────</code>
<b>  ⚠️TRANSAKSI SSH OVPN⚠️      </b>
<code>────────────────────</code>
<code>🌟Owner   : $OWNER</code>
<code>🌟Detail  : $AKUN</code>
<code>🌟Durasi  : $exp</code>
<code>🌟Server  : $domen</code>
<code>────────────────────</code>
<i>Notifikasi Via RstoreBOT</i>
<b>Tele : @kytxz</b>
"
curl -s --max-time $TIMES -d "chat_id=$CHATIDGC&disable_web_page_preview=1&text=$TRX&parse_mode=html" $URL
clear
###########
IP=$(curl -sS ifconfig.me);
ossl=`cat /root/log-install.txt | grep -w "OpenVPN" | cut -f2 -d: | awk '{print $6}'`
opensh=`cat /root/log-install.txt | grep -w "OpenSSH" | cut -f2 -d: | awk '{print $1}'`
db=`cat /root/log-install.txt | grep -w "Dropbear" | cut -f2 -d: | awk '{print $1,$2}'`
ssl="$(cat ~/log-install.txt | grep -w "Stunnel4" | cut -d: -f2)"
sqd="$(cat ~/log-install.txt | grep -w "Squid" | cut -d: -f2)"
ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
ovpn2="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
dnsdomain=$(cat /etc/xray/dns)
dnskey=$(cat /etc/slowdns/server.pub)
OhpSSH=`cat /root/log-install.txt | grep -w "OHP SSH" | cut -d: -f2 | awk '{print $1}'`
OhpDB=`cat /root/log-install.txt | grep -w "OHP DBear" | cut -d: -f2 | awk '{print $1}'`
OhpOVPN=`cat /root/log-install.txt | grep -w "OHP OpenVPN" | cut -d: -f2 | awk '{print $1}'`

sleep 1
clear
useradd -e `date -d "$masaaktif days" +"%Y-%m-%d"` -s /bin/false -M $Login
exp="$(chage -l $Login | grep "Account expires" | awk -F": " '{print $2}')"
echo -e "$Pass\n$Pass\n"|passwd $Login &> /dev/null
PID=`ps -ef |grep -v grep | grep sshws |awk '{print $2}'`

if [[ ! -z "${PID}" ]]; then
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " ${COLBG1}           • SSH PANEL MENU •           ${NC} "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "  Username   : $Login" 
echo -e "  Password   : $Pass"
echo -e "  Expired On : $exp" 
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "  IP         : $IP" 
echo -e "  Host       : $domen" 
echo -e "  OpenSSH    : $opensh"
echo -e "  Dropbear   : $db" 
echo -e "  SSH-WS     : $portsshws, 8880" 
echo -e "  SSH-SSL-WS : $wsssl" 
echo -e "  SSH-UDP    : 56-65545"
echo -e "  SSL/TLS    :$ssl" 
echo -e "  UDPGW      : 7100-7300" 
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "  GET wss://bug.com/ HTTP/1.1[crlf]Host: [host] [crlf]Upgrade: websocket[crlf][crlf]"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
else
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " ${COLBG1}            • SSH PANEL MENU •          ${NC} "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "  Username   : $Login" 
echo -e "  Password   : $Pass"
echo -e "  Expired On : $exp" 
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "  IP         : $IP" 
echo -e "  Host       : $domen" 
echo -e "  OpenSSH    : $opensh"
echo -e "  Dropbear   : $db" 
echo -e "  SSH-WS     : $portsshws, 8880" 
echo -e "  SSH-SSL-WS : $wsssl" 
echo -e "  SSH-UDP    : 56-65545"
echo -e "  SSL/TLS    :$ssl" 
echo -e "  UDPGW      : 7100-7300" 
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "  GET wss://bug.com/ HTTP/1.1[crlf]Host: [host] [crlf]Upgrade: websocket[crlf][crlf]"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
fi
echo -e ""
read -n 1 -s -r -p "  Press any key to back on menu"
menu-ssh
}
function sshwss(){
    clear
portdb=`cat ~/log-install.txt | grep -w "Dropbear" | cut -d: -f2|sed 's/ //g' | cut -f2 -d","`
portsshws=`cat ~/log-install.txt | grep -w "SSH Websocket" | cut -d: -f2 | awk '{print $1}'`
if [ -f "/etc/systemd/system/sshws.service" ]; then
clear
else
wget -q -O /usr/bin/proxy3.js "https://raw.githubusercontent.com/myridwan/VVIP/ipuk/ssh/proxy3.js"
cat <<EOF > /etc/systemd/system/sshws.service
[Unit]
Description=WSenabler
Documentation=https://FranataSTORE.MY.ID

[Service]
Type=simple
ExecStart=/usr/bin/ssh-wsenabler
KillMode=process
Restart=on-failure
RestartSec=1s

[Install]
WantedBy=multi-user.target
EOF

fi

function start() {
        clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " ${COLBG1}            • WEBSOCKET MENU •          ${NC} "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m" 
wget -q -O /usr/bin/ssh-wsenabler "https://raw.githubusercontent.com/myridwan/VVIP/ipuk/ssh/sshws-true.sh" && chmod +x /usr/bin/ssh-wsenabler
systemctl daemon-reload >/dev/null 2>&1
systemctl enable sshws.service >/dev/null 2>&1
systemctl start sshws.service >/dev/null 2>&1
sed -i "/SSH Websocket/c\   - SSH Websocket           : $portsshws [ON]" /root/log-install.txt
echo -e "  [INFO] • ${green}SSH Websocket Started${NC}"
echo -e "  [INFO] • Restart is require for Changes"
echo -e "           to take effect"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
read -n 1 -s -r -p "  Press any key to back on menu"
sshwss 
}

function stop() {
        clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " ${COLBG1}            • WEBSOCKET MENU •          ${NC} "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m" 
systemctl stop sshws.service >/dev/null 2>&1
tmux kill-session -t sshws >/dev/null 2>&1
sed -i "/SSH Websocket/c\   - SSH Websocket           : $portsshws [OFF]" /root/log-install.txt
echo -e "  [INFO] • ${red}SSH Websocket Stopped${NC}"
echo -e "  [INFO] • Restart is require for Changes"
echo -e "           to take effect"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
read -n 1 -s -r -p "  Press any key to back on menu"
sshwss 
}

clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " ${COLBG1}           • WEBSOCKET MENU •           ${NC} "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
PID=`ps -ef |grep -v grep | grep sshws |awk '{print $2}'`
if [[ ! -z "${PID}" ]]; then
echo -e "   • Websocket Is ${COLOR1}Running$NC"
else
echo -e "   • Websocket Is ${red}Not Running$NC"
fi
echo -e ""  
echo -e " ${COLOR1}[01]${NC} • Enable SSH WS  "
echo -e " ${COLOR1}[02]${NC} • Disable SSH WS"
echo -e ""  
echo -e " ${COLOR1}[00]${NC} • GO BACK"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
read -p " Select menu :  "  opt
echo -e ""
case $opt in
01 | 1) clear ; start ;;
02 | 2) clear ; stop ;;
00 | 0) clear ; menu ;;
*) clear ; menu-set ;;
esac
}
function cekssh(){

clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " ${COLBG1}          • SSH ACTIVE USERS •          ${NC} "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""

if [ -e "/var/log/auth.log" ]; then
        LOG="/var/log/auth.log";
fi
if [ -e "/var/log/secure" ]; then
        LOG="/var/log/secure";
fi
               
data=( `ps aux | grep -i dropbear | awk '{print $2}'`);
cat $LOG | grep -i dropbear | grep -i "Password auth succeeded" > /tmp/login-db.txt;
for PID in "${data[@]}"
do
        cat /tmp/login-db.txt | grep "dropbear\[$PID\]" > /tmp/login-db-pid.txt;
        NUM=`cat /tmp/login-db-pid.txt | wc -l`;
        USER=`cat /tmp/login-db-pid.txt | awk '{print $10}'`;
        IP=`cat /tmp/login-db-pid.txt | awk '{print $12}'`;
        if [ $NUM -eq 1 ]; then
                echo "$PID - $USER - $IP";
        fi

done
echo " "
cat $LOG | grep -i sshd | grep -i "Accepted password for" > /tmp/login-db.txt
data=( `ps aux | grep "\[priv\]" | sort -k 72 | awk '{print $2}'`);

for PID in "${data[@]}"
do
        cat /tmp/login-db.txt | grep "sshd\[$PID\]" > /tmp/login-db-pid.txt;
        NUM=`cat /tmp/login-db-pid.txt | wc -l`;
        USER=`cat /tmp/login-db-pid.txt | awk '{print $9}'`;
        IP=`cat /tmp/login-db-pid.txt | awk '{print $11}'`;
        if [ $NUM -eq 1 ]; then
                echo "$PID - $USER - $IP";
        fi


done
if [ -f "/etc/openvpn/server/openvpn-tcp.log" ]; then
        echo " "

        cat /etc/openvpn/server/openvpn-tcp.log | grep -w "^CLIENT_LIST" | cut -d ',' -f 2,3,8 | sed -e 's/,/      /g' > /tmp/vpn-login-tcp.txt
        cat /tmp/vpn-login-tcp.txt
fi

if [ -f "/etc/openvpn/server/openvpn-udp.log" ]; then
        echo " "

        cat /etc/openvpn/server/openvpn-udp.log | grep -w "^CLIENT_LIST" | cut -d ',' -f 2,3,8 | sed -e 's/,/      /g' > /tmp/vpn-login-udp.txt
        cat /tmp/vpn-login-udp.txt
fi


rm -f /tmp/login-db-pid.txt
rm -f /tmp/login-db.txt
rm -f /tmp/vpn-login-tcp.txt
rm -f /tmp/vpn-login-udp.txt
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo "";
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ssh
}

function delssh(){
clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " ${COLBG1}           • SSH DELETE USERS •         ${NC} "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"    
echo "   USERNAME        EXP DATE        STATUS"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"  
while read expired
do
AKUN="$(echo $expired | cut -d: -f1)"
ID="$(echo $expired | grep -v nobody | cut -d: -f3)"
exp="$(chage -l $AKUN | grep "Account expires" | awk -F": " '{print $2}')"
status="$(passwd -S $AKUN | awk '{print $2}' )"
if [[ $ID -ge 1000 ]]; then
if [[ "$status" = "L" ]]; then
printf "%-17s %2s %-17s %2s \n" "   • $AKUN" "$exp     " "LOCKED"
else
printf "%-17s %2s %-17s %2s \n" "   • $AKUN" "$exp     " "UNLOCKED"
fi
fi
done < /etc/passwd
JUMLAH="$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | wc -l)"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"  
echo "   Total: $JUMLAH User"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
read -p "   Username : " Pengguna

if [ -z $Pengguna ]; then
echo -e "   [Error] Username cannot be empty "
else
if getent passwd $Pengguna > /dev/null 2>&1; then
userdel $Pengguna > /dev/null 2>&1
sed -i "s/$Pengguna//g" /etc/xray/ssh.txt
echo -e "   [INFO] User $Pengguna was removed."
else
echo -e "   [INFO] Failure: User $Pengguna Not Exist."
fi
fi
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ssh
}

function renewssh(){
clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " ${COLBG1}           • RENEW SSH ACCOUNT •        ${NC} "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"    
echo "   USERNAME        EXP DATE        STATUS"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"  
while read expired
do
AKUN="$(echo $expired | cut -d: -f1)"
ID="$(echo $expired | grep -v nobody | cut -d: -f3)"
exp="$(chage -l $AKUN | grep "Account expires" | awk -F": " '{print $2}')"
status="$(passwd -S $AKUN | awk '{print $2}' )"
if [[ $ID -ge 1000 ]]; then
if [[ "$status" = "L" ]]; then
printf "%-17s %2s %-17s %2s \n" "   • $AKUN" "$exp     " "LOCKED"
else
printf "%-17s %2s %-17s %2s \n" "   • $AKUN" "$exp     " "UNLOCKED"
fi
fi
done < /etc/passwd
JUMLAH="$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | wc -l)"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"  
echo "   Total: $JUMLAH User"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
read -p "   Username : " User

if getent passwd $User > /dev/null 2>&1; then
ok="ok"
else
echo -e "   [INFO] Failure: User $User Not Exist."
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu
fi

if [ -z $User ]; then
echo -e "   [Error] Username cannot be empty "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu
fi

egrep "^$User" /etc/passwd >/dev/null
if [ $? -eq 0 ]; then
read -p "Day Extend : " Days
if [ -z $Days ]; then
Days="1"
fi
Today=`date +%s`
Days_Detailed=$(( $Days * 86400 ))
Expire_On=$(($Today + $Days_Detailed))
Expiration=$(date -u --date="1970-01-01 $Expire_On sec GMT" +%Y/%m/%d)
Expiration_Display=$(date -u --date="1970-01-01 $Expire_On sec GMT" '+%d %b %Y')
passwd -u $User
usermod -e  $Expiration $User
egrep "^$User" /etc/passwd >/dev/null
echo -e "$Pass\n$Pass\n"|passwd $User &> /dev/null
clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " ${COLBG1}         • RENEW SSH ACCOUNT •          ${NC} "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "   Username   : $User"
echo -e "   Days Added : $Days Days"
echo -e "   Expires on : $Expiration_Display"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
else
clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " ${COLBG1}           • RENEW SSH ACCOUNT •        ${NC} "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "   Username Doesnt Exist      "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
fi
echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ssh
}


function memberssh(){
clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " ${COLBG1}          • MEMBER SSH ACCOUNT •        ${NC} "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"    
echo "   USERNAME        EXP DATE        STATUS"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"  
while read expired
do
AKUN="$(echo $expired | cut -d: -f1)"
ID="$(echo $expired | grep -v nobody | cut -d: -f3)"
exp="$(chage -l $AKUN | grep "Account expires" | awk -F": " '{print $2}')"
status="$(passwd -S $AKUN | awk '{print $2}' )"
if [[ $ID -ge 1000 ]]; then
if [[ "$status" = "L" ]]; then
printf "%-17s %2s %-17s %2s \n" "   • $AKUN" "$exp     " "LOCKED"
else
printf "%-17s %2s %-17s %2s \n" "   • $AKUN" "$exp     " "UNLOCKED"
fi
fi
done < /etc/passwd
JUMLAH="$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | wc -l)"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"  
echo "   Total: $JUMLAH User"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ssh
}

function trialssh(){
clear
domen=`cat /etc/xray/domain`
portsshws=`cat ~/log-install.txt | grep -w "SSH Websocket" | cut -d: -f2 | awk '{print $1}'`
wsssl=`cat /root/log-install.txt | grep -w "SSH SSL Websocket" | cut -d: -f2 | awk '{print $1}'`
clear
IP=$(curl -sS ifconfig.me);
ossl=`cat /root/log-install.txt | grep -w "OpenVPN" | cut -f2 -d: | awk '{print $6}'`
opensh=`cat /root/log-install.txt | grep -w "OpenSSH" | cut -f2 -d: | awk '{print $1}'`
db=`cat /root/log-install.txt | grep -w "Dropbear" | cut -f2 -d: | awk '{print $1,$2}'`
ssl="$(cat ~/log-install.txt | grep -w "Stunnel4" | cut -d: -f2)"
OhpSSH=`cat /root/log-install.txt | grep -w "OHP SSH" | cut -d: -f2 | awk '{print $1}'`
dnsdomain=$(cat /root/nsdomain)
dnskey=$(cat /etc/slowdns/server.pub)


Login=ssnvpn`</dev/urandom tr -dc X-Z0-9 | head -c4`
hari="1"
Pass=1
echo Ping Host &> /dev/null
echo Create Akun: $Login &> /dev/null
sleep 0.5
echo Setting Password: $Pass &> /dev/null
sleep 0.5
clear
useradd -e `date -d "$masaaktif days" +"%Y-%m-%d"` -s /bin/false -M $Login
exp="$(chage -l $Login | grep "Account expires" | awk -F": " '{print $2}')"
echo -e "$Pass\n$Pass\n"|passwd $Login &> /dev/null
PID=`ps -ef |grep -v grep | grep sshws |awk '{print $2}'`

if [[ ! -z "${PID}" ]]; then
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " ${COLBG1}         • SSH TRIAL ACCOUNT •          ${NC} "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "  Username   : $Login" 
echo -e "  Password   : $Pass"
echo -e "  Expired On : $exp" 
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "  IP         : $IP" 
echo -e "  Host       : $domen" 
echo -e "  OpenSSH    : $opensh"
echo -e "  Dropbear   : $db" 
echo -e "  SSH-WS     : $portsshws, 8880" 
echo -e "  SSH-SSL-WS : $wsssl" 
echo -e "  SSH-UDP    : 56-65545"
echo -e "  SSL/TLS    :$ssl" 
echo -e "  UDPGW      : 7100-7300" 
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "  GET wss://bug.com/ HTTP/1.1[crlf]Host: [host] [crlf]Upgrade: websocket[crlf][crlf]"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"

else

echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " ${COLBG1}         • SSH TRIAL ACCOUNT •          ${NC} "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "  Username   : $Login" 
echo -e "  Password   : $Pass"
echo -e "  Expired On : $exp" 
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "  IP         : $IP" 
echo -e "  Host       : $domen" 
echo -e "  OpenSSH    : $opensh"
echo -e "  Dropbear   : $db" 
echo -e "  SSH-WS     : $portsshws, 8880" 
echo -e "  SSH-SSL-WS : $wsssl" 
echo -e "  SSH-UDP    : 56-65545"
echo -e "  SSL/TLS    :$ssl" 
echo -e "  UDPGW      : 7100-7300" 
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "$COLOR1 ${NC}  GET wss://bug.com/ HTTP/1.1[crlf]Host: [host] [crlf]Upgrade: websocket[crlf][crlf]"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
fi
echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
menu-ssh
}
clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " \e[1;97;101m            MENU MANAGER SSH           \E[0m"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\033[1;93m〔⎆〕 ${grenbo}1.${NC} \033[0;36mCreating a SSH Account${NC}"
echo -e "\033[1;93m〔⎆〕 ${grenbo}2.${NC} \033[0;36mTriall a Trial Account${NC}"
echo -e "\033[1;93m〔⎆〕 ${grenbo}3.${NC} \033[0;36mUser SSH Online${NC}"
echo -e "\033[1;93m〔⎆〕 ${grenbo}4.${NC} \033[0;36mEnable Ws SSH${NC}"
echo -e "\033[1;93m〔⎆〕 ${grenbo}5.${NC} \033[0;36mDelete SSH Account${NC}"
echo -e "\033[1;93m〔⎆〕 ${grenbo}6.${NC} \033[0;36mRenew SSH${NC}"
echo -e "\033[1;93m〔⎆〕 ${grenbo}7.${NC} \033[0;36mCek Member SSH${NC}"
echo -e "\033[1;93m〔⎆〕 ${grenbo}8.${NC} \033[0;36mGo Back Menu${NC}"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
read -p " Select menu :  "  opt
echo -e ""
case $opt in
01 | 1) clear ; addssh ;;
02 | 2) clear ; trialssh ;;
03 | 3) clear ; cekssh ;;
04 | 4) clear ; sshwss ;;
05 | 5) clear ; delssh ;;
06 | 6) clear ; renewssh ;;
07 | 7) clear ; memberssh ;;
08 | 8) clear ; menu ;;
*) clear ; menu-ssh ;;
esac

       
