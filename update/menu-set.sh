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
green='\e[1;32m'
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
function status(){
clear
cek=$(service ssh status | grep active | cut -d ' ' -f5)
if [ "$cek" = "active" ]; then
stat=-f5
else
stat=-f7
fi
cekray=`cat /root/log-install.txt | grep -ow "XRAY" | sort | uniq`
if [ "$cekray" = "XRAY" ]; then
rekk='xray'
becek='XRAY'
else
rekk='v2ray'
becek='V2RAY'
fi

ssh=$(service ssh status | grep active | cut -d ' ' $stat)
if [ "$ssh" = "active" ]; then
ressh="${green}ONLINE${NC}"
else
ressh="${red}OFFLINE${NC}"
fi
sshstunel=$(service stunnel4 status | grep active | cut -d ' ' $stat)
if [ "$sshstunel" = "active" ]; then
resst="${green}ONLINE${NC}"
else
resst="${red}OFFLINE${NC}"
fi
sshws=$(service ws-dropbear status | grep active | cut -d ' ' $stat)
if [ "$sshws" = "active" ]; then
rews="${green}ONLINE${NC}"
else
rews="${red}OFFLINE${NC}"
fi

sshws2=$(service ws-stunnel status | grep active | cut -d ' ' $stat)
if [ "$sshws2" = "active" ]; then
rews2="${green}ONLINE${NC}"
else
rews2="${red}OFFLINE${NC}"
fi

db=$(service dropbear status | grep active | cut -d ' ' $stat)
if [ "$db" = "active" ]; then
resdb="${green}ONLINE${NC}"
else
resdb="${red}OFFLINE${NC}"
fi

slow=$(service client-sldns status | grep active | cut -d ' ' $stat)
if [ "$slow" = "active" ]; then
reslow="${green}ONLINE${NC}"
else
reslow="${red}OFFLINE${NC}"
fi
 
v2r=$(service $rekk status | grep active | cut -d ' ' $stat)
if [ "$v2r" = "active" ]; then
resv2r="${green}ONLINE${NC}"
else
resv2r="${red}OFFLINE${NC}"
fi
vles=$(service $rekk status | grep active | cut -d ' ' $stat)
if [ "$vles" = "active" ]; then
resvles="${green}ONLINE${NC}"
else
resvles="${red}OFFLINE${NC}"
fi
trj=$(service $rekk status | grep active | cut -d ' ' $stat)
if [ "$trj" = "active" ]; then
restr="${green}ONLINE${NC}"
else
restr="${red}OFFLINE${NC}"
fi

ningx=$(service nginx status | grep active | cut -d ' ' $stat)
if [ "$ningx" = "active" ]; then
resnx="${green}ONLINE${NC}"
else
resnx="${red}OFFLINE${NC}"
fi

squid=$(service squid status | grep active | cut -d ' ' $stat)
if [ "$squid" = "active" ]; then
ressq="${green}ONLINE${NC}"
else
ressq="${red}OFFLINE${NC}"
fi
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}               • SERVER STATUS •               ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e " $COLOR1┌───────────────────────────────────────────────┐${NC}"
echo -e " $COLOR1│${NC}  • SSH & VPN                        • $ressh"
echo -e " $COLOR1│${NC}  • SQUID                            • $ressq"
echo -e " $COLOR1│${NC}  • DROPBEAR                         • $resdb"
echo -e " $COLOR1│${NC}  • NGINX                            • $resnx"
echo -e " $COLOR1│${NC}  • SLOWDNS                          • $reslow"
echo -e " $COLOR1│${NC}  • WS DROPBEAR                      • $rews"
echo -e " $COLOR1│${NC}  • WS STUNNEL                       • $rews2"
echo -e " $COLOR1│${NC}  • STUNNEL                          • $resst"
echo -e " $COLOR1│${NC}  • XRAY-SS                          • $resv2r"
echo -e " $COLOR1│${NC}  • XRAY                             • $resv2r"
echo -e " $COLOR1│${NC}  • VLESS                            • $resvles"
echo -e " $COLOR1│${NC}  • TROJAN                           • $restr"
echo -e " $COLOR1└───────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo ""
read -n 1 -s -r -p "  Press any key to back on menu"
menu-set
}
function restart(){
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}               • SERVER STATUS •               ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e " $COLOR1┌───────────────────────────────────────────────┐${NC}"
systemctl daemon-reload
echo -e " $COLOR1│${NC}  [INFO] • Starting ...                        $COLOR1│${NC}"
sleep 1
systemctl restart ssh
echo -e " $COLOR1│${NC}  [INFO] • Restarting SSH Services             $COLOR1│${NC}"
sleep 1
systemctl restart squid
echo -e " $COLOR1│${NC}  [INFO] • Restarting Squid Services           $COLOR1│${NC}"
sleep 1
systemctl restart openvpn
systemctl restart nginx
echo -e " $COLOR1│${NC}  [INFO] • Restarting Nginx Services           $COLOR1│${NC}"
sleep 1
systemctl restart dropbear
echo -e " $COLOR1│${NC}  [INFO] • Restarting Dropbear Services        $COLOR1│${NC}"
sleep 1
systemctl restart ws-dropbear
echo -e " $COLOR1│${NC}  [INFO] • Restarting Ws-Dropbear Services     $COLOR1│${NC}"
sleep 1
systemctl restart ws-stunnel
echo -e " $COLOR1│${NC}  [INFO] • Restarting Ws-Stunnel Services      $COLOR1│${NC}"
sleep 1
systemctl restart stunnel4
echo -e " $COLOR1│${NC}  [INFO] • Restarting Stunnel4 Services        $COLOR1│${NC}"
sleep 1
systemctl restart xray
echo -e " $COLOR1│${NC}  [INFO] • Restarting Xray Services            $COLOR1│${NC}"
sleep 1
systemctl restart cron
echo -e " $COLOR1│${NC}  [INFO] • Restarting Cron Services            $COLOR1│${NC}"
echo -e " $COLOR1│${NC}  [INFO] • All Services Restates Successfully  $COLOR1│${NC}"
sleep 1
echo -e " $COLOR1└───────────────────────────────────────────────┘${NC}" 
echo -e "$COLOR1┌────────────────────── BY ───────────────────────┐${NC}"
echo -e "$COLOR1│${NC}                 • RstoreVPN •                 $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}" 
echo ""
read -n 1 -s -r -p "  Press any key to back on menu"
menu-set
}

[[ -f /etc/ontorrent ]] && sts="\033[0;32mON \033[0m" || sts="\033[1;31mOFF\033[0m"

enabletorrent() {
[[ ! -f /etc/ontorrent ]] && {
sudo iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
sudo iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
sudo iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
sudo iptables-save > /etc/iptables.up.rules
sudo iptables-restore -t < /etc/iptables.up.rules
sudo netfilter-persistent save >/dev/null 2>&1  
sudo netfilter-persistent reload >/dev/null 2>&1 
touch /etc/ontorrent
menu-set
} || {
sudo iptables -D FORWARD -m string --string "get_peers" --algo bm -j DROP
sudo iptables -D FORWARD -m string --string "announce_peer" --algo bm -j DROP
sudo iptables -D FORWARD -m string --string "find_node" --algo bm -j DROP
sudo iptables -D FORWARD -m string --algo bm --string "BitTorrent" -j DROP
sudo iptables -D FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
sudo iptables -D FORWARD -m string --algo bm --string "peer_id=" -j DROP
sudo iptables -D FORWARD -m string --algo bm --string ".torrent" -j DROP
sudo iptables -D FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
sudo iptables -D FORWARD -m string --algo bm --string "torrent" -j DROP
sudo iptables -D FORWARD -m string --algo bm --string "announce" -j DROP
sudo iptables -D FORWARD -m string --algo bm --string "info_hash" -j DROP
sudo iptables-save > /etc/iptables.up.rules
sudo iptables-restore -t < /etc/iptables.up.rules
sudo netfilter-persistent save >/dev/null 2>&1
sudo netfilter-persistent reload >/dev/null 2>&1 
rm -f /etc/ontorrent
menu-set
}
}

clear
echo -e "$PURPLE┌─────────────────────────────────────────────────┐${NC}"
echo -e "$PURPLE│ ${BLUE}                $NC•$BLUE SERVER RUNNING $NC•             $PURPLE │$NC"
echo -e "$PURPLE└─────────────────────────────────────────────────┘${NC}"
echo -e " $PURPLE┌───────────────────────────────────────────────┐${NC}"
echo -e " $PURPLE│${NC}  • SSH & VPN                        •${GREEN} $ressh"
echo -e " $PURPLE│${NC}  • SQUID                            •${GREEN} $ressq"
echo -e " $PURPLE│${NC}  • DROPBEAR                         •${GREEN} $resdb"
echo -e " $PURPLE│${NC}  • NGINX                            •${GREEN} $resnx"
echo -e " $PURPLE│${NC}  • SLOWDNS                          •${GREEN} $reslow"
echo -e " $PURPLE│${NC}  • WS DROPBEAR                      •${GREEN} $rews"
echo -e " $PURPLE│${NC}  • WS STUNNEL                       •${GREEN} $rews2"
echo -e " $PURPLE│${NC}  • STUNNEL                          •${GREEN} $resst"
echo -e " $PURPLE│${NC}  • XRAY-SS                          •${GREEN} $resv2r"
echo -e " $PURPLE│${NC}  • XRAY                             •${GREEN} $resv2r"
echo -e " $PURPLE│${NC}  • VLESS                            •${GREEN} $resvles"
echo -e " $PURPLE│${NC}  • TROJAN                           •${GREEN} $restr"
echo -e " $PURPLE└───────────────────────────────────────────────┘${NC}" 
echo -e "$PURPLE┌─────────────────────────────────────────────────┐${NC}"
echo -e "$PURPLE│ ${BLUE}                $NC•$BLUE VPS SETTING $NC•                $PURPLE │$NC"
echo -e "$PURPLE└─────────────────────────────────────────────────┘${NC}"

echo -e " $PURPLE┌───────────────────────────────────────────────┐${NC}"
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}01${NC}]  CEK RUNNING  "
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}02${NC}]  SET BANNER  "
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}03${NC}]  BANDWITH USAGE "
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}04${NC}]  ANTI TORRENT $sts"
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}05${NC}]  TCP TWEAK"
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}06${NC}]  RESTART ALL"
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}07${NC}]  AUTO REBOOT"
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}08${NC}]  SPEEDTEST "
echo -e " $PURPLE│$NC "
echo -e " $PURPLE│$NC   ${COLOR1}[${BLUE}00${NC}]  Go Back"
echo -e " $PURPLE└───────────────────────────────────────────────┘${NC}"
echo -e "$PURPLE┌──────────────────────${NC} BY $PURPLE───────────────────────┐${NC}"
echo -e "$PURPLE│${BLUE}                 $NC•$BLUE RstoreVPN $NC•                $PURPLE│$NC"
echo -e "$PURPLE└─────────────────────────────────────────────────┘${NC}" 
echo -e ""
read -p "  Select menu :  "  opt
echo -e   ""
case $opt in
01 | 1) clear ; status ;;
02 | 2) clear ; nano /etc/issue.net ;;
03 | 3) clear ; mbandwith ;;
04 | 4) clear ; enabletorrent ;;
05 | 5) clear ; menu-tcp ;;
06 | 6) clear ; restart ;;
07 | 7) clear ; autoboot ;;
08 | 8) clear ; mspeed ;;
00 | 0) clear ; menu ;;
*) clear ; menu-set ;;
esac

       
