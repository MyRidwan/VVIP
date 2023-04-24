#!/bin/bash
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
#########################

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
clear
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

[[ ! -f "/etc/IP" ]] && wget -qO- ipv4.icanhazip.com > /etc/IP
cekray=`cat /root/log-install.txt | grep -ow "XRAY" | sort | uniq`
if [ "$cekray" = "XRAY" ]; then
domen=`cat /etc/xray/domain`
raycheck='xray'
else
domen=`cat /etc/v2ray/domain`
raycheck='v2ray'
fi

PID=`ps -ef |grep -v grep | grep sshws |awk '{print $2}'`
if [[ ! -z ${PID} ]]; then
IPs="$domen"
else
IPs=$(cat /etc/IP)
fi
[[ ! -d /var/lib/scrz-prem ]] && exit 0
[[ ! -f /etc/.maAsiss/res_token ]] && touch /etc/.maAsiss/res_token
[[ ! -f /etc/.maAsiss/user_flood ]] && touch /etc/.maAsiss/user_flood
[[ ! -f /etc/.maAsiss/log_res ]] && touch /etc/.maAsiss/log_res
[[ ! -f /etc/.maAsiss/User_Generate_Token ]] && touch /etc/.maAsiss/User_Generate_Token
[[ ! -d /etc/.maAsiss/.cache ]] && mkdir /etc/.maAsiss/.cache
[[ ! -f /etc/.maAsiss/.cache/StatusDisable ]] && {
touch /etc/.maAsiss/.cache/StatusDisable
cat <<-EOF >/etc/.maAsiss/.cache/StatusDisable
SSH : [ON]
VMESS : [ON]
VLESS : [ON]
TROJAN : [ON]
TROJAN-GO : [ON]
WIREGUARD : [ON]
SHADOWSOCK: [ON]
SHADOWSOCKS-R : [ON]
EOF
}

source /root/ResBotAuth
source /etc/.maAsiss/.Shellbtsss
User_Active=/etc/.maAsiss/list_user
User_Token=/etc/.maAsiss/User_Generate_Token
Res_Token=/etc/.maAsiss/res_token
User_Flood=/etc/.maAsiss/user_flood

ShellBot.init --token $Toket --monitor --return map --flush
ShellBot.username
echo "Admin ID = $Admin_ID"
admin_bot_panel=$(grep -w "admin_panel" /etc/.maAsiss/bot.conf | awk '{print $NF}')
_limTotal=$(grep -w "limite_trial" /etc/.maAsiss/bot.conf | awk '{print $NF}')
nameStore=$(grep -w "store_name" /etc/.maAsiss/bot.conf | awk '{print $NF}')
rm -f /tmp/authToken 
rm -f /tmp/authAdmin

AUTOBLOCK() {
[[ "$(grep -wc ${message_chat_id[$id]} $User_Flood)" != '1' ]] && {
   Max=9
   [[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
   return 0
   } || [[ "$(grep -w "${message_from_id}" $User_Active | grep -wc 'reseller')" != '1' ]] && {
   echo $message_date + $Max | bc >> /etc/.maAsiss/.cache/$message_chat_id
   [[ "$(grep -wc "$message_date" "/etc/.maAsiss/.cache/$message_chat_id")" = '1' ]] && {
         echo "$message_chat_id" >> /etc/.maAsiss/user_flood
         rm -f /etc/.maAsiss/.cache/$message_chat_id
         ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
             --text "Youre flooding im sorry to block you\nThis ur ID: <code>${message_chat_id[$id]}</code>\n\nContact $admin_bot_panel to unblock" \
             --parse_mode html
         ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
         return 0
      }
    }
  }
}

Disable_Order() {
   [[ "${message_from_id[$id]}" == "$Admin_ID" ]] && {
     ShellBot.deleteMessage	--chat_id ${message_chat_id[$id]} \
              --message_id ${message_message_id[$id]}
              
     [[ "$(grep -wc "ssh" "/tmp/order")" = '1' ]] && {
         touch /etc/.maAsiss/.cache/DisableOrderSSH
         sed -i "/SSH/c\SSH : [OFF]" /etc/.maAsiss/.cache/StatusDisable
         ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
             --text "✅ Success Disabled SSH" \
             --parse_mode html
         [[ -f /tmp/msgid ]] && {
             dx=$(cat /tmp/msgid | tail -1)
             echo $dx + 1 | bc >> /tmp/msgid
         } || {
         echo ${message_message_id[$id]} + 1 | bc >> /tmp/msgid
         }
     }
     [[ "$(grep -wc "vmess" "/tmp/order")" = '1' ]] && {
         touch /etc/.maAsiss/.cache/DisableOrderVMESS
         sed -i "/VMESS/c\VMESS : [OFF]" /etc/.maAsiss/.cache/StatusDisable
         ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
             --text "✅ Success Disabled VMess" \
             --parse_mode html
         [[ -f /tmp/msgid ]] && {
             dx=$(cat /tmp/msgid | tail -1)
             echo $dx + 1 | bc >> /tmp/msgid
         } || {
         echo ${message_message_id[$id]} + 1 | bc >> /tmp/msgid
         }
     }
     [[ "$(grep -wc "vless" "/tmp/order")" = '1' ]] && {
         touch /etc/.maAsiss/.cache/DisableOrderVLESS
         sed -i "/VLESS/c\VLESS : [OFF]" /etc/.maAsiss/.cache/StatusDisable
         ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
             --text "✅ Success Disabled VLess" \
             --parse_mode html
         [[ -f /tmp/msgid ]] && {
             dx=$(cat /tmp/msgid | tail -1)
             echo $dx + 1 | bc >> /tmp/msgid
         } || {
         echo ${message_message_id[$id]} + 1 | bc >> /tmp/msgid
         }
     }
     [[ "$(grep -wc "trojan" "/tmp/order")" = '1' ]] && {
         touch /etc/.maAsiss/.cache/DisableOrderTROJAN
         sed -i "/TROJAN :/c\TROJAN : [OFF]" /etc/.maAsiss/.cache/StatusDisable
         ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
             --text "✅ Success Disabled Trojan" \
             --parse_mode html
         [[ -f /tmp/msgid ]] && {
             dx=$(cat /tmp/msgid | tail -1)
             echo $dx + 1 | bc >> /tmp/msgid
         } || {
         echo ${message_message_id[$id]} + 1 | bc >> /tmp/msgid
         }
     }
     [[ "$(grep -wc "trgo" "/tmp/order")" = '1' ]] && {
         touch /etc/.maAsiss/.cache/DisableOrderTROJANGO
         sed -i "/TROJAN-GO/c\TROJAN-GO : [OFF]" /etc/.maAsiss/.cache/StatusDisable
         ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
             --text "✅ Success Disabled Trojan-GO" \
             --parse_mode html
         [[ -f /tmp/msgid ]] && {
             dx=$(cat /tmp/msgid | tail -1)
             echo $dx + 1 | bc >> /tmp/msgid
         } || {
         echo ${message_message_id[$id]} + 1 | bc >> /tmp/msgid
         }
     }
     [[ "$(grep -wc "wg" "/tmp/order")" = '1' ]] && {
         touch /etc/.maAsiss/.cache/DisableOrderWG
         sed -i "/WIREGUARD/c\WIREGUARD : [OFF]" /etc/.maAsiss/.cache/StatusDisable
         ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
             --text "✅ Success Disabled Wireguard" \
             --parse_mode html
         [[ -f /tmp/msgid ]] && {
             dx=$(cat /tmp/msgid | tail -1)
             echo $dx + 1 | bc >> /tmp/msgid
         } || {
         echo ${message_message_id[$id]} + 1 | bc >> /tmp/msgid
         }
     }
     [[ "$(grep -wc "ss" "/tmp/order")" = '1' ]] && {
         touch /etc/.maAsiss/.cache/DisableOrderSS
         sed -i "/^SHADOWSOCK:/c\SHADOWSOCK: [OFF]" /etc/.maAsiss/.cache/StatusDisable
         ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
             --text "✅ Success Disabled Shadowsocks" \
             --parse_mode html
         [[ -f /tmp/msgid ]] && {
             dx=$(cat /tmp/msgid | tail -1)
             echo $dx + 1 | bc >> /tmp/msgid
         } || {
         echo ${message_message_id[$id]} + 1 | bc >> /tmp/msgid
         }
     }
     [[ "$(grep -wc "ssr" "/tmp/order")" = '1' ]] && {
         touch /etc/.maAsiss/.cache/DisableOrderSSR
         sed -i "/SHADOWSOCKS-R/c\SHADOWSOCKS-R : [OFF]" /etc/.maAsiss/.cache/StatusDisable
         ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
             --text "✅ Success Disabled Shadowsocks-R" \
             --parse_mode html
         [[ -f /tmp/msgid ]] && {
             dx=$(cat /tmp/msgid | tail -1)
             echo $dx + 1 | bc >> /tmp/msgid
         } || {
         echo ${message_message_id[$id]} + 1 | bc >> /tmp/msgid
         }
     }
     [[ -f /tmp/msgid ]] && {
     while read msg_id; do
         ShellBot.deleteMessage	--chat_id ${message_chat_id[$id]} \
              --message_id $msg_id
     done <<<"$(cat /tmp/msgid)"
     rm -f /tmp/msgid
     }
     [[ "$(grep -wc "off" "/tmp/order")" = '1' ]] && {
         rm -f /etc/.maAsiss/.cache/DisableOrderWG
         rm -f /etc/.maAsiss/.cache/DisableOrderSSH
         rm -f /etc/.maAsiss/.cache/DisableOrderVMESS
         rm -f /etc/.maAsiss/.cache/DisableOrderVLESS
         rm -f /etc/.maAsiss/.cache/DisableOrderTROJAN
         rm -f /etc/.maAsiss/.cache/DisableOrderTROJANGO
         rm -f /etc/.maAsiss/.cache/DisableOrderSS
         rm -f /etc/.maAsiss/.cache/DisableOrderSSR
         sed -i "s/\[OFF\]/\[ON\]/g" /etc/.maAsiss/.cache/StatusDisable
         bdx=$(echo ${message_message_id[$id]} + 1 | bc)
         ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
             --text "☑️ Successfully Enabled Order ☑️" \
             --parse_mode html
         sleep 1
         ShellBot.deleteMessage	--chat_id ${message_chat_id[$id]} \
              --message_id $bdx
     } 
  }
}

about_server() {
[[ "$(grep -wc ${message_chat_id[$id]} $User_Flood)" = '1' ]] && return 0 || AUTOBLOCK
ISP=`curl -sS ip-api.com | grep -w "isp" | awk '{print $3,$4,$5,$6,$7,$8,$9}' | cut -d'"' -f2 | cut -d',' -f1 | tee -a /etc/afak.conf`
CITY=`curl -sS ip-api.com | grep -w "city" | awk '{print $3}' | cut -d'"' -f2 | tee -a /etc/afak.conf`
WKT=`curl -sS ip-api.com | grep -w "timezone" | awk '{print $3}' | cut -d'"' -f2 | tee -a /etc/afak.conf`
IPVPS=`curl -sS ip-api.com | grep -w "query" | awk '{print $3}' | cut -d'"' -f2 | tee -a /etc/afak.conf`

    local msg
    msg="<b>Server Information</b>\n\n"
    msg+="<code>ISP  : $ISP\n"
    msg+="CITY : $CITY\n"
    msg+="TIME : $WKT\n"
    msg+="IP.  : $IPVPS</code>\n"
    ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
        --text "$msg" \
        --parse_mode html
    return 0
}

msg_welcome() {
[[ "$(grep -wc ${message_chat_id[$id]} $User_Flood)" = '1' ]] && return 0 || AUTOBLOCK
[[ "$(grep -wc ${message_chat_id[$id]} $User_Token)" = '0' ]] && {
r1=$(tr -dc A-Za-z </dev/urandom | head -c 4)
r2=$(tr -dc A-Za-z </dev/urandom | head -c 2)
r3=$(tr -dc A-Za-z </dev/urandom | head -c 3)
r4=$(tr -dc A-Za-z </dev/urandom | head -c 1)
r5=$(tr -dc A-Za-z </dev/urandom | head -c 5)
r6=$(tr -dc A-Za-z </dev/urandom | head -c 2)
r7=$(tr -dc A-Za-z </dev/urandom | head -c 4)
r8=$(tr -dc A-Za-z </dev/urandom | head -c 2)
r9=$(tr -dc A-Za-z </dev/urandom | head -c 4)
fcm=$(echo ${message_from_id[$id]} | sed 's/\([0-9]\{2,\}\)\([0-9]\)\([0-9]\)\([0-9]\)\([0-9]\)\([0-9]\)\([0-9]\)\([0-9]\)/\1'$r1'\2'$r2'\3'$r3'\4'$r4'\5'$r5'\6'$r6'\7'$r7'\8'$r8'/ig' | rev)
echo "ID_User : ${message_chat_id[$id]} Token : $fcm" >> /etc/.maAsiss/User_Generate_Token
} || {
fcm=$(grep -w ${message_chat_id[$id]} $User_Token | awk '{print $NF}')
}

local msg
msg="===========================\n"
msg+="Welcome <b>${message_from_first_name[$id]}</b>\n\n"
msg+="To access the menu [ /menu ]\n"
msg+="To see server information [ /info ]\n"
msg+="for free account [ /free ]\n\n"
msg+="===========================\n"
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
msg+="<b>Acces Token:</b>\n"
msg+="<code>$fcm</code>\n"
msg+="===========================\n"
} 
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
     --text "$(echo -e $msg)" \
     --parse_mode html
return 0
}

menu_func() {
[[ "$(grep -wc ${message_chat_id[$id]} $User_Flood)" = '1' ]] && return 0 || AUTOBLOCK
hargassh=$(grep -w "Price SSH" /etc/.maAsiss/price | awk '{print $NF}')
hargavmess=$(grep -w "Price VMess" /etc/.maAsiss/price | awk '{print $NF}')
hargavless=$(grep -w "Price VLess" /etc/.maAsiss/price | awk '{print $NF}')
hargatrojan=$(grep -w "Price Trojan :" /etc/.maAsiss/price | awk '{print $NF}')
hargatrgo=$(grep -w "Price Trojan-GO" /etc/.maAsiss/price | awk '{print $NF}')
hargawg=$(grep -w "Price Wireguard" /etc/.maAsiss/price | awk '{print $NF}')
hargass=$(grep -w "Price Shadowsocks :" /etc/.maAsiss/price | awk '{print $NF}')
hargassr=$(grep -w "Price Shadowsocks-R" /etc/.maAsiss/price | awk '{print $NF}')
hargasstp=$(grep -w "Price SSTP" /etc/.maAsiss/price | awk '{print $NF}')
hargal2tp=$(grep -w "Price L2TP" /etc/.maAsiss/price | awk '{print $NF}')
hargapptp=$(grep -w "Price PPTP" /etc/.maAsiss/price | awk '{print $NF}')
hargaxray=$(grep -w "Price Xray" /etc/.maAsiss/price | awk '{print $NF}')

    [[ "${message_from_id[$id]}" == "$Admin_ID" ]] && {
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n\n"
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} --text "$env_msg" \
            --reply_markup "$keyboard1" \
            --parse_mode html
        return 0
    }
    if [[ "$(grep -w "${message_from_id}" $User_Active | grep -wc 'reseller')" != '0' ]]; then
        _SaldoTotal=$(grep -w 'Saldo_Reseller' /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="💲Price List :💲\n"
        env_msg+="<code>SSH            : $hargassh\n"
        env_msg+="VMess          : $hargavmess\n"
        env_msg+="VLess          : $hargavless\n"
        env_msg+="Trojan         : $hargatrojan\n"
        env_msg+="Trojan-Go      : $hargatrgo\n"
        env_msg+="Wireguard      : $hargawg\n"
        env_msg+="Shadowsocks    : $hargass\n"
        env_msg+="Shadowsocks-R  : $hargassr\n"
        env_msg+="SSTP           : $hargasstp\n"
        env_msg+="PPTP           : $hargapptp\n"
        env_msg+="L2TP           : $hargal2tp\n"
        env_msg+="XRAY           : $hargaxray</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="🤵 Admin Panel : $admin_bot_panel 🤵\n"
        env_msg+="💡 Limit Trial : $_limTotal users 💡\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="💰 Current Balance : $_SaldoTotal 💰\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n\n"
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} --text "$env_msg" \
            --reply_markup "$menu_re_main_updater1" \
            --parse_mode html
        return 0
    else
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "===========================\n⛔ ACCESS DENIED ⛔\n===========================\n\nfor register to be a reseller contact : $admin_bot_panel\n\n===========================\nBot Panel By : @Kytxz\n===========================\n"
        return 0
    fi
}

menu_func_cb() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] && {
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n\n"
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu')"
        return 0
    }
    if [[ "$(grep -w "${message_from_id}" $User_Active | grep -wc 'reseller')" != '0' ]]; then
        _SaldoTotal=$(grep -w 'Saldo_Reseller' /etc/.maAsiss/db_reseller/${callback_query_from_id}/${callback_query_from_id} | awk '{print $NF}')       

[[ ! -f "/etc/.maAsiss/update-info" ]] && {
   local env_msg
   env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
   env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
   env_msg+="━━━━━━━━━━━━━━━━━━━━━\n\n"
} || {
   inf=$(cat /etc/.maAsiss/update-info)
   local env_msg
   env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
   env_msg+="🏷 Information for reseller :\n\n"
   env_msg+="$inf\n\n"
   env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
}
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_re_main')"
        return 0
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

info_port() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        portssh=$(grep -w "OpenSSH" /root/log-install.txt | awk '{print $NF}')
        portsshws=$(grep -w "SSH Websocket" /root/log-install.txt | awk '{print $5,$6}')
        portovpn=$(grep -w " OpenVPN" /root/log-install.txt | awk '{print $4,$5,$6,$7,$8,$9,$10}')
        portssl=$(grep -w "Stunnel4" /root/log-install.txt | awk '{print $4,$5,$6,$7}')
        portdb=$(grep -w "Dropbear" /root/log-install.txt | awk '{print $4,$5,$6,$7}')
        portsqd=$(grep -w "Squid Proxy" /root/log-install.txt | awk '{print $5,$6}')
        portudpgw=$(grep -w "Badvpn" /root/log-install.txt | awk '{print $4}')
        portnginx=$(grep -w "Nginx" /root/log-install.txt | awk '{print $NF}')
        portwstls=$(grep -w "Vmess TLS" /root/log-install.txt | awk '{print $NF}')
        portws=$(grep -w "Vmess None TLS" /root/log-install.txt | awk '{print $NF}')
        portvlesstls=$(grep -w "Vless TLS" /root/log-install.txt | awk '{print $NF}')
        portvless=$(grep -w "Vless None TLS" /root/log-install.txt | awk '{print $NF}')
        porttr=$(grep -w "Trojan " /root/log-install.txt | awk '{print $NF}')
        porttrgo=$(grep -w "Trojan Go" /root/log-install.txt | awk '{print $NF}')
        portwg=$(grep -w "Wireguard" /root/log-install.txt | awk '{print $NF}')
        portsstp=$(grep -w "SSTP VPN" /root/log-install.txt | awk '{print $NF}')
        portl2tp=$(grep -w "L2TP/IPSEC VPN" /root/log-install.txt | awk '{print $NF}')
        portpptp=$(grep -w "PPTP VPN" /root/log-install.txt | awk '{print $NF}')
        portsstls=$(grep -w "SS-OBFS TLS" /root/log-install.txt | awk '{print $NF}')
        portss=$(grep -w "SS-OBFS HTTP" /root/log-install.txt | awk '{print $NF}')
        portssR=$(grep -w "Shadowsocks-R" /root/log-install.txt | awk '{print $NF}')
        OhpSSH=`cat /root/log-install.txt | grep -w "OHP SSH" | cut -d: -f2 | awk '{print $1}'`
        OhpDB=`cat /root/log-install.txt | grep -w "OHP DBear" | cut -d: -f2 | awk '{print $1}'`
        OhpOVPN=`cat /root/log-install.txt | grep -w "OHP OpenVPN" | cut -d: -f2 | awk '{print $1}'`
        wsssl=`cat /root/log-install.txt | grep -w "SSH SSL Websocket" | cut -d: -f2 | awk '{print $1}'`
                        
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="OpenSSH : $portssh\n"
        env_msg+="SSH-WS : $portsshws\n"
        env_msg+="SSH-WS-SSL : $wsssl\n"
        env_msg+="OHP SSH : $OhpSSH\n"
        env_msg+="OHP Dropbear : $OhpDB\n"
        env_msg+="OHP OpenVPN : $OhpOVPN\n"
        env_msg+="OpenVPN : $portovpn\n"
        env_msg+="Stunnel : $portssl\n"
        env_msg+="Dropbear : $portdb\n"
        env_msg+="Squid Proxy : $portsqd\n"
        env_msg+="Badvpn : $portudpgw\n"
        env_msg+="Nginx : $portnginx\n"
        env_msg+="Vmess TLS : $portwstls\n"
        env_msg+="Vmess HTTP : $portws\n"
        env_msg+="Vless TLS : $portvlesstls\n"
        env_msg+="Vless HTTP : $portvless\n"
        env_msg+="Trojan : $porttr\n"
        env_msg+="Trojan-GO : $porttrgo\n"
        env_msg+="Wireguard : $portwg\n"
        env_msg+="SSTP VPN: $portsstp\n"
        env_msg+="L2TP VPN : $portl2tp\n"
        env_msg+="PPTP VPN : $portpptp\n"
        env_msg+="SS-OBFS TLS : $portsstls\n"
        env_msg+="SS-OBFS HTTP : $portss\n"
        env_msg+="Shadowsocks-R : $portssR\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'back_menu')"
        return 0
    } || {
  ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ ACCESS DENIED ⛔"
         return 0
  }
}

admin_price_see() {
hargassh=$(grep -w "Price SSH" /etc/.maAsiss/price | awk '{print $NF}')
hargavmess=$(grep -w "Price VMess" /etc/.maAsiss/price | awk '{print $NF}')
hargavless=$(grep -w "Price VLess" /etc/.maAsiss/price | awk '{print $NF}')
hargatrojan=$(grep -w "Price Trojan :" /etc/.maAsiss/price | awk '{print $NF}')
hargatrgo=$(grep -w "Price Trojan-GO" /etc/.maAsiss/price | awk '{print $NF}')
hargawg=$(grep -w "Price Wireguard" /etc/.maAsiss/price | awk '{print $NF}')
hargass=$(grep -w "Price Shadowsocks :" /etc/.maAsiss/price | awk '{print $NF}')
hargassr=$(grep -w "Price Shadowsocks-R" /etc/.maAsiss/price | awk '{print $NF}')
hargasstp=$(grep -w "Price SSTP" /etc/.maAsiss/price | awk '{print $NF}')
hargal2tp=$(grep -w "Price L2TP" /etc/.maAsiss/price | awk '{print $NF}')
hargapptp=$(grep -w "Price PPTP" /etc/.maAsiss/price | awk '{print $NF}')
hargaxray=$(grep -w "Price Xray" /etc/.maAsiss/price | awk '{print $NF}')

[[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="💲Price List :💲\n"
        env_msg+="<code>SSH            : $hargassh\n"
        env_msg+="VMess          : $hargavmess\n"
        env_msg+="VLess          : $hargavless\n"
        env_msg+="Trojan         : $hargatrojan\n"
        env_msg+="Trojan-Go      : $hargatrgo\n"
        env_msg+="Wireguard      : $hargawg\n"
        env_msg+="Shadowsocks    : $hargass\n"
        env_msg+="Shadowsocks-R  : $hargassr\n"
        env_msg+="SSTP           : $hargasstp\n"
        env_msg+="PPTP           : $hargapptp\n"
        env_msg+="L2TP           : $hargal2tp\n"
        env_msg+="XRAY           : $hargal2tp</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'back_menu_admin')"
        return 0
    } || {
  ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ ACCESS DENIED ⛔"
         return 0
  }
}

admin_service_see() {
[[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_adm_ser')"
        return 0
    } || {
  ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ ACCESS DENIED ⛔"
         return 0
  }
}

menu_reserv() {
        stsSSH=$(grep -w "SSH" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        stsVMESS=$(grep -w "VMESS" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        stsVLESS=$(grep -w "VLESS" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        stsTROJAN=$(grep -w "TROJAN :" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        stsTROJANGO=$(grep -w "TROJAN-GO" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        stsWG=$(grep -w "WIREGUARD" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        stsSS=$(grep -w "SHADOWSOCK:" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        stsSSR=$(grep -w "SHADOWSOCKS-R" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="🟢 Status Order : \n\n"
        env_msg+="<code>SSH            : $stsSSH\n"
        env_msg+="VMess          : $stsVMESS\n"
        env_msg+="VLess          : $stsVLESS\n"
        env_msg+="Trojan         : $stsTROJAN\n"
        env_msg+="Trojan-Go      : $stsTROJANGO\n"
        env_msg+="Wireguard      : $stsWG\n"
        env_msg+="Shadowsocks    : $stsSS\n"
        env_msg+="Shadowsocks-R  : $stsSSR</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

[[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_re_ser')"
        return 0
    } || {
  ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ ACCESS DENIED ⛔"
         return 0
  }
}

status_order() {
        stsSSH=$(grep -w "SSH" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        stsVMESS=$(grep -w "VMESS" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        stsVLESS=$(grep -w "VLESS" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        stsTROJAN=$(grep -w "TROJAN :" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        stsTROJANGO=$(grep -w "TROJAN-GO" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        stsWG=$(grep -w "WIREGUARD" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        stsSS=$(grep -w "SHADOWSOCK:" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        stsSSR=$(grep -w "SHADOWSOCKS-R" /etc/.maAsiss/.cache/StatusDisable | awk '{print $NF}')
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="🟢 Status Order : \n\n"
        env_msg+="<code>SSH            : $stsSSH\n"
        env_msg+="VMess          : $stsVMESS\n"
        env_msg+="VLess          : $stsVLESS\n"
        env_msg+="Trojan         : $stsTROJAN\n"
        env_msg+="Trojan-Go      : $stsTROJANGO\n"
        env_msg+="Wireguard      : $stsWG\n"
        env_msg+="Shadowsocks    : $stsSS\n"
        env_msg+="Shadowsocks-R  : $stsSSR</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'status_disable')" \
        return 0
    } || {
  ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ ACCESS DENIED ⛔"
         return 0
  }
}

how_to_order() {
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="💡 How to use : [code] \n\n"
        env_msg+="<code>SSH            : ssh\n"
        env_msg+="VMess          : vmess\n"
        env_msg+="VLess          : vless\n"
        env_msg+="Trojan         : trojan\n"
        env_msg+="Trojan-Go      : trgo\n"
        env_msg+="Wireguard      : wg\n"
        env_msg+="Shadowsocks    : ss\n"
        env_msg+="Shadowsocks-R  : ssr</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="usage: /disable[space][code]\n"
        env_msg+="example: <code>/disable ssh</code>\n\n"
        env_msg+="note: you can use multiple args\n"
        env_msg+="example: <code>/disable ssh ssr trojan trgo</code>\n\n"
        env_msg+="usage: /disable[space][off] to turn off\n"
        env_msg+="example: <code>/disable off</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'status_how_to')" \
        return 0
    } || {
  ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ ACCESS DENIED ⛔"
         return 0
  }
}

see_log() {
    beha=$(cat /etc/.maAsiss/log_res)
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<code>$beha</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
    [[ "$(cat /etc/.maAsiss/log_res | wc -l)" = '0' ]] && {
    ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ No Information Available ⛔"
         return 0
    } || {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'back_menu_admin')" \
        return 0
    }
  } || {
  ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ ACCESS DENIED ⛔"
         return 0
  }
}

res_opener() {
[[ ! -f "/etc/.maAsiss/update-info" ]] && {
   local env_msg
   env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
   env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
   env_msg+="━━━━━━━━━━━━━━━━━━━━━\n\n"
} || {
   inf=$(cat /etc/.maAsiss/update-info)
   local env_msg
   env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
   env_msg+="🏷 Information for reseller :\n\n"
   env_msg+="$inf\n\n"
   env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
}

    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_re_main')"
        return 0
    } || {
    ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

res_closer() {
hargassh=$(grep -w "Price SSH" /etc/.maAsiss/price | awk '{print $NF}')
hargavmess=$(grep -w "Price VMess" /etc/.maAsiss/price | awk '{print $NF}')
hargavless=$(grep -w "Price VLess" /etc/.maAsiss/price | awk '{print $NF}')
hargatrojan=$(grep -w "Price Trojan :" /etc/.maAsiss/price | awk '{print $NF}')
hargatrgo=$(grep -w "Price Trojan-GO" /etc/.maAsiss/price | awk '{print $NF}')
hargawg=$(grep -w "Price Wireguard" /etc/.maAsiss/price | awk '{print $NF}')
hargass=$(grep -w "Price Shadowsocks :" /etc/.maAsiss/price | awk '{print $NF}')
hargassr=$(grep -w "Price Shadowsocks-R" /etc/.maAsiss/price | awk '{print $NF}')
hargasstp=$(grep -w "Price SSTP" /etc/.maAsiss/price | awk '{print $NF}')
hargal2tp=$(grep -w "Price L2TP" /etc/.maAsiss/price | awk '{print $NF}')
hargapptp=$(grep -w "Price PPTP" /etc/.maAsiss/price | awk '{print $NF}')
hargaxray=$(grep -w "Price Xray" /etc/.maAsiss/price | awk '{print $NF}')

    if [[ "$(grep -w "${message_from_id}" $User_Active | grep -wc 'reseller')" != '0' ]]; then
        _SaldoTotal=$(grep -w 'Saldo_Reseller' /etc/.maAsiss/db_reseller/${callback_query_from_id}/${callback_query_from_id} | awk '{print $NF}')       
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="💲Price List :💲\n"
        env_msg+="<code>SSH            : $hargassh\n"
        env_msg+="VMess          : $hargavmess\n"
        env_msg+="VLess          : $hargavless\n"
        env_msg+="Trojan         : $hargatrojan\n"
        env_msg+="Trojan-Go      : $hargatrgo\n"
        env_msg+="Wireguard      : $hargawg\n"
        env_msg+="Shadowsocks    : $hargass\n"
        env_msg+="Shadowsocks-R  : $hargassr\n"
        env_msg+="SSTP           : $hargasstp\n"
        env_msg+="PPTP           : $hargapptp\n"
        env_msg+="L2TP           : $hargal2tp\n"
        env_msg+="XRAY           : $hargaxray</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="🤵 Admin Panel : $admin_bot_panel 🤵\n"
        env_msg+="💡 Limit Trial : $_limTotal users💡\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="💰 Current Balance : $_SaldoTotal 💰\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n\n"
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_re_main_updater')"
        return 0
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
         --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

user_already_exist() {
    userna=$1
   if [[ "${message_from_id[$id]}" = "$Admin_ID" ]]; then
        datata=$(find /etc/.maAsiss/ -name $userna | sort | uniq | wc -l)
        for accc in "${datata[@]}"
        do
             _resl=$accc
        done  
        _results=$(echo $_resl)
    elif [[ "${message_from_id[$id]}" != "$Admin_ID" ]]; then
        datata=$(find /etc/.maAsiss/ -name $userna | sort | uniq | wc -l)
        for accc in "${datata[@]}"
        do
             _resl=$accc
        done  
        _results=$(echo $_resl)
      fi
      [[ "$_results" != "0" ]] && {
         ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ User $userna already exist , try other username " \
                --parse_mode html
         ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "Func Error Do Nothing" \
                --reply_markup "$(ShellBot.ForceReply)"
         return 0
      }   
}

adduser_ssh() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE USER 👤\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

cret_user() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderSSH ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Disable Order SSH" \
                --parse_mode html
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
               --text "Func Error Do Nothing" \
               --reply_markup "$(ShellBot.ForceReply)"
        return 0
    }
}
    file_user=$1
    userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
    passw=$(sed -n '2 p' $file_user | cut -d' ' -f2)
    data=$(sed -n '3 p' $file_user | cut -d' ' -f2)
    exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)

    if /usr/sbin/useradd -M -N -s /bin/false $userna -e $exp; then
        (echo "${passw}";echo "${passw}") | passwd "${userna}"
    else
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ ERROR CREATING USER" \
                --parse_mode html
        return 0
    fi
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
        pricessh=$(grep -w "Price SSH" /etc/.maAsiss/price | awk '{print $NF}')
        saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
        if [ "$saldores" -lt "$pricessh" ]; then
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Your Balance Not Enough" \
                --parse_mode html
            return 0
        else
            echo "$userna:$passw:$info_data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna
            echo "$userna:$passw:$info_data" >/etc/.maAsiss/info-users/$userna
            _CurrSal=$(echo $saldores - $pricessh | bc)
            sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
            sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active
            echo "$userna:$passw 30Days SSH | ${message_from_username}" >> /etc/.maAsiss/log_res
        fi
    }
}

2month_user() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderSSH ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Disable Order SSH" \
                --parse_mode html
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
               --text "Func Error Do Nothing" \
               --reply_markup "$(ShellBot.ForceReply)"
        return 0
    }
}
    file_user=$1
    userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
    passw=$(sed -n '2 p' $file_user | cut -d' ' -f2)
    data=$(sed -n '3 p' $file_user | cut -d' ' -f2)
    exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)
   
     if /usr/sbin/useradd -M -N -s /bin/false $userna -e $exp; then
        (echo "${passw}";echo "${passw}") | passwd "${userna}"
    else
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "⛔ ERROR CREATING USER")" \
                --parse_mode html
        return 0
    fi

    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
        pricessh=$(grep -w "Price SSH" /etc/.maAsiss/price | awk '{print $NF}')
        saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
        urday=$(echo $pricessh * 2 | bc)
        if [ "$saldores" -lt "$urday" ]; then
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Your Balance Not Enough " \
                --parse_mode html
            return 0
        else
            echo "$userna:$passw:$info_data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna
            echo "$userna:$passw:$info_data" >/etc/.maAsiss/info-users/$userna
            _CurrSal=$(echo $saldores - $urday | bc)
            sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
            sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active
            echo "$userna:$passw 60Days SSH | ${message_from_username}" >> /etc/.maAsiss/log_res
        fi
    }
}

del_ssh() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🗑 REMOVE USER 🗑\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_del_ssh() {
    userna=$1
    [[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
        userdel --force "$userna" 2>/dev/null
        kill-by-user $userna
rm /root/login-db.txt > /dev/null 2>&1
rm /root/login-db-pid.txt > /dev/null 2>&1
    } || {
        [[ ! -e /etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "⛔ THE USER DOES NOT EXIST ⛔")" \
                --parse_mode html
            _erro='1'
            return 0
        }
        userdel --force "$userna" 2>/dev/null
        rm /etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna
        rm /etc/.maAsiss/info-users/$userna
        kill-by-user $userna
        
rm /root/login-db.txt > /dev/null 2>&1
rm /root/login-db-pid.txt > /dev/null 2>&1
    }
}

info_users_ssh() {
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        arq_info=/tmp/$(echo $RANDOM)
        fun_infu() {
            local info
            for user in $(cat /etc/passwd | awk -F : '$3 >= 1000 {print $1}' | grep -v nobody); do
                info='━━━━━━━━━━━━━━━━━━━━━\n'
                datauser=$(chage -l $user | grep -i co | awk -F : '{print $2}')
                [[ $datauser = ' never' ]] && {
                    data="Never"
                } || {
                    databr="$(date -d "$datauser" +"%Y%m%d")"
                    hoje="$(date -d today +"%Y%m%d")"
                    [[ $hoje -ge $databr ]] && {
                        data="Expired"
                    } || {
                        dat="$(date -d"$datauser" '+%Y-%m-%d')"
                        data=$(echo -e "$((($(date -ud $dat +%s) - $(date -ud $(date +%Y-%m-%d) +%s)) / 86400)) Days")
                    }
                }
                info+="$user • $data"
                echo -e "$info"
            done
        }
        fun_infu >$arq_info
        while :; do
            ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
            ShellBot.sendMessage --chat_id $Admin_ID \
                --text "$(while read line; do echo $line; done < <(sed '1,30!d' $arq_info))" \
                --parse_mode html
            sed -i 1,30d $arq_info
            [[ $(cat $arq_info | wc -l) = '0' ]] && rm $arq_info && break
        done
    elif [[ "$(grep -wc "${callback_query_from_id}" $User_Active)" != '0' ]]; then
        [[ $(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_by_res | wc -l) == '0' ]] && {
            ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "YOU HAVE NOT CREATED A USER YET!"
            return 0
        }
        arq_info=/tmp/$(echo $RANDOM)
        fun_infu() {
            local info
            for user in $(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_by_res); do
                info='━━━━━━━━━━━━━━━━━━━━━\n'
                datauser=$(chage -l $user | grep -i co | awk -F : '{print $2}')
                [[ $datauser = ' never' ]] && {
                    data="Never"
                } || {
                    databr="$(date -d "$datauser" +"%Y%m%d")"
                    hoje="$(date -d today +"%Y%m%d")"
                    [[ $hoje -ge $databr ]] && {
                        data="Expired"
                    } || {
                        dat="$(date -d"$datauser" '+%Y-%m-%d')"
                        data=$(echo -e "$((($(date -ud $dat +%s) - $(date -ud $(date +%Y-%m-%d) +%s)) / 86400)) Days")
                    }
                }
                info+="$user • $data"
                echo -e "$info"
            done
        }
        fun_infu >$arq_info
        while :; do
            ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "$(while read line; do echo $line; done < <(sed '1,30!d' $arq_info))" \
                --parse_mode html
            sed -i 1,30d $arq_info
            [[ $(cat $arq_info | wc -l) = '0' ]] && rm $arq_info && break
        done
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

renew_ssh() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "⏳ Renew SSH ⏳\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_renew_ssh() {
    userna=$1
    inputdate=$2
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        [[ "$(echo -e "$inputdate" | sed -e 's/[^/]//ig')" != '//' ]] && {
            udata=$(date "+%d/%m/%Y" -d "+$inputdate days")
            sysdate="$(echo "$udata" | awk -v FS=/ -v OFS=- '{print $3,$2,$1}')"
        } || {
            udata=$(echo -e "$inputdate")
            sysdate="$(echo -e "$inputdate" | awk -v FS=/ -v OFS=- '{print $3,$2,$1}')"
            today="$(date -d today +"%Y%m%d")"
            timemachine="$(date -d "$sysdate" +"%Y%m%d")"
            [ $today -ge $timemachine ] && {
                verify='1'
                ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Date Invalid" \
                    --parse_mode html
                _erro='1'
                return 0
            }
        }
        chage -E $sysdate $userna
        [[ -e /etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna ]] && {
            data2=$(cat /etc/.maAsiss/info-users/$userna | awk -F : {'print $3'})
            sed -i "s;$data2;$udata;" /etc/.maAsiss/info-users/$userna
            echo $userna $udata ${message_from_id}
            sed -i "s;$data2;$udata;" /etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna
        }
    elif [[ "$(grep -wc "${callback_query_from_id}" $User_Active)" != '0' ]]; then
        [[ "$(echo -e "$inputdate" | sed -e 's/[^/]//ig')" != '//' ]] && {
            udata=$(date "+%d/%m/%Y" -d "+$inputdate days")
            sysdate="$(echo "$udata" | awk -v FS=/ -v OFS=- '{print $3,$2,$1}')"
         } || {
            udata=$(echo -e "$inputdate")
            sysdate="$(echo -e "$inputdate" | awk -v FS=/ -v OFS=- '{print $3,$2,$1}')"
            today="$(date -d today +"%Y%m%d")"
            timemachine="$(date -d "$sysdate" +"%Y%m%d")"
            [ $today -ge $timemachine ] && {
                verify='1'
                ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Date Invalid" \
                    --parse_mode html
                _erro='1'
                return 0
            }
         }
         chage -E $sysdate $userna
         [[ -e /etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna ]] && {
            pricessh=$(grep -w "Price SSH" /etc/.maAsiss/price | awk '{print $NF}')
            saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
            if [ "$saldores" -lt "$pricessh" ]; then
                ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Your Balance Not Enough ⛔" \
                    --parse_mode html
                return 0
            else
                data2=$(cat /etc/bot/info-users/$userna | awk -F : {'print $3'})
                sed -i "s;$data2;$udata;" /etc/.maAsiss/info-users/$userna
                echo $userna $udata ${message_from_id}
                sed -i "s;$data2;$udata;" /etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna
                _CurrSal=$(echo $saldores - $pricessh | bc)
                sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
                sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active
            fi
         }
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

add_ssh_trial() {
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE TRIAL SSH 👤\n\nHow many hours should it last ? EX: 1:" \
            --reply_markup "$(ShellBot.ForceReply)"
    elif [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]]; then
            ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "👤 CREATE TRIAL SSH 👤\n\nHow many hours should it last ? EX: 1:" \
                --reply_markup "$(ShellBot.ForceReply)"       
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

func_add_ssh_trial() {
    mkdir -p /etc/.maAsiss/info-users
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderSSH ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Disable Order SSH" \
                --parse_mode html
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
               --text "Func Error Do Nothing" \
               --reply_markup "$(ShellBot.ForceReply)"
        return 0
    }
}
    userna=$(echo Trial`</dev/urandom tr -dc A-Z0-9 | head -c4`)
    password='1'
    t_time=$1
    ex_date=$(date '+%d/%m/%C%y' -d " +2 days")
    tuserdate=$(date '+%C%y/%m/%d' -d " +2 days")
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold
    }
    [[ -z $t_time ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e "⛔ error try again")" \
            --parse_mode html
        return 0
        _erro='1'
    }
    /usr/sbin/useradd -M -N -s /bin/false $userna -e $tuserdate >/dev/null 2>&1
    (
        echo "$password"
        echo "$password"
    ) | passwd $userna >/dev/null 2>&1
    echo "$password" >/etc/.maAsiss/$userna
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
        echo "$userna:$password:$ex_date" >/etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna
        echo "$userna:$password:$ex_date" >/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna
    }
dir_teste="/etc/.maAsiss/db_reseller/${message_from_id}/user_by_res/$userna"
dir_teste2="/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna"
dates=`date`
cat <<-EOF >/etc/.maAsiss/$userna.sh
#!/bin/bash
# USER TRIAL SSH by ${message_from_id} $dates
kill-by-user $userna
userdel --force $userna
[[ -e $dir_teste ]] && rm $dir_teste
[[ -e $dir_teste2 ]] && rm $dir_teste2

rm /root/login-db.txt > /dev/null 2>&1
rm /root/login-db-pid.txt > /dev/null 2>&1
rm -f /etc/.maAsiss/$userna
rm -f /etc/.maAsiss/$userna.sh
EOF
    chmod +x /etc/.maAsiss/$userna.sh
    echo "/etc/.maAsiss/$userna.sh" | at now + $t_time hour >/dev/null 2>&1
    [[ "$t_time" == '1' ]] && hrs="hour" || hrs="hours"
        ossl=`cat /root/log-install.txt | grep -w " OpenVPN" | cut -f2 -d: | awk '{print $6}'`
        opensh=`cat /root/log-install.txt | grep -w "OpenSSH" | cut -f2 -d: | awk '{print $1}'`
        db=`cat /root/log-install.txt | grep -w "Dropbear" | cut -f2 -d: | awk '{print $1,$2}'`
        ssl="$(cat /root/log-install.txt | grep -w "Stunnel4" | cut -d: -f2)"
        sqd="$(cat /root/log-install.txt | grep -w "Squid" | cut -d: -f2)"
        ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
        ovpn2="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
        portsshws=`cat /root/log-install.txt | grep -w "SSH Websocket" | cut -d: -f2 | awk '{print $1}'`
        wsssl=`cat /root/log-install.txt | grep -w "SSH SSL Websocket" | cut -d: -f2 | awk '{print $1}'`
        OhpSSH=`cat /root/log-install.txt | grep -w "OHP SSH" | cut -d: -f2 | awk '{print $1}'`
        OhpDB=`cat /root/log-install.txt | grep -w "OHP DBear" | cut -d: -f2 | awk '{print $1}'`
        OhpOVPN=`cat /root/log-install.txt | grep -w "OHP OpenVPN" | cut -d: -f2 | awk '{print $1}'`

        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>    🔸 TRIAL SSH ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="Host : $IPs \n"
        env_msg+="Username: <code>$userna</code>\n"
        env_msg+="Password: 1\n"
        env_msg+="Expired On: $t_time $hrs ⏳\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="OpenSSH : $opensh\n"
        env_msg+="Dropbear : $db\n"
        env_msg+="SSH-WS : $portsshws\n"
        env_msg+="SSH-WS-SSL : $wsssl\n"
        env_msg+="SSL/TLS : $ssl\n"
        env_msg+="Port Squid : $sqd\n"
        env_msg+="OHP SSH : $OhpSSH\n"
        env_msg+="OHP Dropbear : $OhpDB\n"
        env_msg+="OHP OpenVPN : $OhpOVPN\n"
        env_msg+="UDPGW : 7100-7300 \n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="OpenVPN Config : http://$IPs:81/\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="Payload WS : \n\n"
        env_msg+="<code>GET / HTTP/1.1[crlf]Host: $IPs [crlf]Upgrade: websocket[crlf][crlf]</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$env_msg" \
            --parse_mode html
        return 0
}

fun_drop() {
    port_dropbear=$(ps aux | grep dropbear | awk NR==1 | awk '{print $17;}')
    log=/var/log/auth.log
    loginsukses='Password auth succeeded'
    pids=$(ps ax | grep dropbear | grep " $port_dropbear" | awk -F" " '{print $1}')
    for pid in $pids; do
        pidlogs=$(grep $pid $log | grep "$loginsukses" | awk -F" " '{print $3}')
        i=0
        for pidend in $pidlogs; do
            let i=i+1
        done
        if [ $pidend ]; then
            login=$(grep $pid $log | grep "$pidend" | grep "$loginsukses")
            PID=$pid
            user=$(echo $login | awk -F" " '{print $10}' | sed -r "s/'/ /g")
            waktu=$(echo $login | awk -F" " '{print $2"-"$1,$3}')
            while [ ${#waktu} -lt 13 ]; do
                waktu=$waktu" "
            done
            while [ ${#user} -lt 16 ]; do
                user=$user" "
            done
            while [ ${#PID} -lt 8 ]; do
                PID=$PID" "
            done
            echo "$user $PID $waktu"
        fi
    done
}

user_online_ssh() {
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        cad_onli=/tmp/$(echo $RANDOM)
        fun_online() {
            local info2
            for user in $(cat /etc/passwd | awk -F : '$3 >= 1000 {print $1}' | grep -v nobody); do
                [[ $(netstat -nltp | grep 'dropbear' | wc -l) != '0' ]] && drop="$(fun_drop | grep "$user" | wc -l)" || drop=0
                [[ -e /etc/openvpn/openvpn-status.log ]] && ovp="$(cat /etc/openvpn/openvpn-status.log | grep -E ,"$user", | wc -l)" || ovp=0
                sqd="$(ps -u $user | grep sshd | wc -l)"
                _cont=$(($drop + $ovp))
                conex=$(($_cont + $sqd))
                [[ $conex -gt '0' ]] && {
                    timerr="$(ps -o etime $(ps -u $user | grep sshd | awk 'NR==1 {print $1}') | awk 'NR==2 {print $1}')"
                    info2+="━━━━━━━━━━━━━━━━━━━━━\n"
                    info2+="<code>🟢 $user      ⃣ $conex      ⏳ $timerr</code>\n"
                }
            done
            echo -e "$info2"
        }
        fun_online >$cad_onli
        [[ $(cat $cad_onli | wc -w) != '0' ]] && {
            while :; do
                ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
                     --message_id ${callback_query_message_message_id[$id]}
                ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                    --text "$(while read line; do echo $line; done < <(sed '1,30!d' $cad_onli))" \
                    --parse_mode html
                sed -i 1,30d $cad_onli
                [[ "$(cat $cad_onli | wc -l)" = '0' ]] && {
                    rm $cad_onli
                    break
                }
            done
        } || {
            ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "No users online" \
                --parse_mode html
            return 0
        }
    elif [[ "$(grep -wc "${callback_query_from_id}" $User_Active)" != '0' ]]; then
        [[ $(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_by_res | wc -l) == '0' ]] && {
            ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "YOU HAVE NOT CREATED A USER YET!"
            return 0
        }
        cad_onli=/tmp/$(echo $RANDOM)
        fun_online() {
            local info2
            for user in $(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_by_res); do
                [[ $(netstat -nltp | grep 'dropbear' | wc -l) != '0' ]] && drop="$(fun_drop | grep "$user" | wc -l)" || drop=0
                [[ -e /etc/openvpn/openvpn-status.log ]] && ovp="$(cat /etc/openvpn/openvpn-status.log | grep -E ,"$user", | wc -l)" || ovp=0
                sqd="$(ps -u $user | grep sshd | wc -l)"
                conex=$(($sqd + $ovp + $drop))
                [[ $conex -gt '0' ]] && {
                    timerr="$(ps -o etime $(ps -u $user | grep sshd | awk 'NR==1 {print $1}') | awk 'NR==2 {print $1}')"
                    info2+="━━━━━━━━━━━━━━━━━━━━━\n"
                    info2+="<code>👤 $user      ⃣ $conex      ⏳ $timerr</code>\n"
                }
            done
            echo -e "$info2"
        }
        fun_online >$cad_onli
        [[ $(cat $cad_onli | wc -w) != '0' ]] && {
            while :; do
                ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
                    --message_id ${callback_query_message_message_id[$id]}
                ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                    --text "<code>$(while read line; do echo $line; done < <(sed '1,30!d' $cad_onli))</code>" \
                    --parse_mode html
                sed -i 1,30d $cad_onli
                [[ "$(cat $cad_onli | wc -l)" = '0' ]] && {
                    rm $cad_onli
                    break
                }
            done
        } || {
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "No users online" \
                --parse_mode html
            return 0
        }
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

Saldo_CheckerSSH() {
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
        pricessh=$(grep -w "Price SSH" /etc/.maAsiss/price | awk '{print $NF}')
        saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
        if [ "$saldores" -lt "$pricessh" ]; then
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Your Balance Not Enough ⛔" \
                --parse_mode html
            _erro="1"
            return 0
        else
            echo
        fi
    }
}

Saldo_CheckerSSH2Month() {
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
        pricessh=$(grep -w "Price SSH" /etc/.maAsiss/price | awk '{print $NF}')
        saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
        urday=$(echo $pricessh * 2 | bc)
        if [ "$saldores" -lt "$urday" ]; then
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Your Balance Not Enough ⛔" \
                --parse_mode html
            _erro="1"
            return 0
        else
            echo
        fi
    }
}

verifica_acesso() {
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
        [[ "$(grep -wc ${message_from_id} $User_Active)" == '0' ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "WTF !! Whooo Are You ???")" \
                            --parse_mode html
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
            return 0
        }
    }
}

ssh_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu1')"
        return 0
    }
}

add_res(){
        gg=$(cat $Res_Token | awk '{print $2}')
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> List name reseller</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<code>$gg</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
                --message_id ${callback_query_message_message_id[$id]} \
                --text "$env_msg" \
                --parse_mode html 
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👥 ADD Reseller 👥\n\nEnter the name:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

cret_res() {
    file_res=$1
    [[ -z "$file_res" ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e Error)"
        _erro='1'
        break
    }
    name_res=$(sed -n '1 p' $file_res | cut -d' ' -f2)
    uname_res=$(sed -n '2 p' $file_res | cut -d' ' -f2)
    saldo_res=$(sed -n '3 p' $file_res | cut -d' ' -f2)
    [[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
        t_res='reseller'
    }
    Token=$(cat /tmp/scvpsss)
    mkdir -p /etc/.maAsiss/db_reseller/"$uname_res"
    mkdir -p /etc/.maAsiss/db_reseller/"$uname_res"/user_by_res
    mkdir -p /etc/.maAsiss/db_reseller/"$uname_res"/trial-fold
    mkdir -p /etc/.maAsiss/db_reseller/"$uname_res"/user_ray
    mkdir -p /etc/.maAsiss/db_reseller/"$uname_res"/user_vless
    mkdir -p /etc/.maAsiss/db_reseller/"$uname_res"/user_trojan
    mkdir -p /etc/.maAsiss/db_reseller/"$uname_res"/user_wg
    mkdir -p /etc/.maAsiss/db_reseller/"$uname_res"/user_ss
    mkdir -p /etc/.maAsiss/db_reseller/"$uname_res"/user_ssr
    mkdir -p /etc/.maAsiss/db_reseller/"$uname_res"/user_sstp
    mkdir -p /etc/.maAsiss/db_reseller/"$uname_res"/user_l2tp
    mkdir -p /etc/.maAsiss/db_reseller/"$uname_res"/user_pptp
    mkdir -p /etc/.maAsiss/db_reseller/"$uname_res"/user_trgo
    mkdir -p /etc/.maAsiss/db_reseller/"$uname_res"/user_xray
    touch /etc/.maAsiss/db_reseller/"$uname_res"/$uname_res
    echo -e "USER: $uname_res SALDO: $saldo_res TYPE: $t_res" >>$User_Active
    echo -e "Name: $name_res TOKEN: $Token" >> $Res_Token
    echo -e "=========================\nSaldo_Reseller: $saldo_res\n=========================\n" >/etc/.maAsiss/db_reseller/"$uname_res"/$uname_res
    sed -i '$d' $file_res
    
    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
           --text "✅ Successfully Added Reseller. ✅\n\n<b>Name </b>: $name_res\n<b>Token </b>: $Token\n<b>Saldo </b>: $saldo_res\n\n<b>BOT </b>: @${message_reply_to_message_from_username}" \
           --parse_mode html
    return 0
}

del_res() {
    gg=$(cat $Res_Token | awk '{print $2}')
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> List name reseller</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<code>$gg</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
                --message_id ${callback_query_message_message_id[$id]} \
                --text "$env_msg" \
                --parse_mode html 
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🗑 REMOVE Reseller 🗑\n\nInput Name of Reseller:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_del_res() {
    _cli_rev=$1
    [[ -z "$_cli_rev" ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e "Error")"
        return 0
    }
    cek_res_token=$(grep -w "$_cli_rev" "$Res_Token" | awk '{print $NF}' | sed -e 's/[^0-9]//ig'| rev)
    [[ "${message_from_id[$id]}" == "$Admin_ID" ]] && {
        [[ "$(grep -wc "$cek_res_token" $User_Active)" != '0' ]] && {
            [[ -e "/etc/.maAsiss/db_reseller/$cek_res_token/$cek_res_token" ]] && _dirsts='db_reseller' || _dirsts='suspensos'
            [[ "$(ls /etc/.maAsiss/$_dirsts/$cek_res_token/user_by_res | wc -l)" != '0' ]] && {
                for _user in $(ls /etc/.maAsiss/$_dirsts/$cek_res_token/user_by_res); do
                    userdel --force "$_user" 2>/dev/null
                    kill-by-user $_user
                done
            }
            
            rm /root/login-db.txt > /dev/null 2>&1
            rm /root/login-db-pid.txt > /dev/null 2>&1
            sed -i "/\b$_cli_rev\b/d" $Res_Token
            [[ -d /etc/.maAsiss/$_dirsts/$cek_res_token ]] && rm -rf /etc/.maAsiss/$_dirsts/$cek_res_token >/dev/null 2>&1
            sed -i "/\b$cek_res_token\b/d" $User_Active
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "✅ SUCCESSFULLY REMOVED ✅")" \
                --parse_mode html
            return 0
        } || {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e ⛔ Reseller DOES NOT EXIST ⛔)"
            return 0
        }
    }
}

reset_saldo_res() {
    gg=$(cat $Res_Token | awk '{print $2}')
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> List </b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<code>$gg</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
                --message_id ${callback_query_message_message_id[$id]} \
                --text "$env_msg" \
                --parse_mode html 
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🌀 Reset Saldo Reseller 🌀\n\nInput Name of Reseller:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_reset_saldo_res() {
    _cli_rev=$(cat /tmp/resSaldo | awk '{print $NF}' | sed -e 's/[^0-9]//ig'| rev)
    [[ -z "$_cli_rev" ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e "Error")"
        return 0
    }
    cek_res_token=$(grep -ow "$_cli_rev" "$User_Active")
    [[ "${message_from_id[$id]}" == "$Admin_ID" ]] && {
       [[ "$(grep -wc "$cek_res_token" $User_Active)" != '0' ]] && {
            sed -i "/Saldo_Reseller/c\Saldo_Reseller: 0" /etc/.maAsiss/db_reseller/"$cek_res_token"/$cek_res_token
            sed -i "/$cek_res_token/c\USER: $cek_res_token SALDO: 0 TYPE: reseller" $User_Active
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "✅ Succesfully Reset Saldo 0 ✅")" \
                --parse_mode html
            rm -f /tmp/resSaldo
            return 0
    
    } || {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e ⛔ Reseller DOES NOT EXIST ⛔)"
        return 0
    }
  }
}

# {name0}](tg://user?id={uid})
func_list_res() {
    if [[ "${callback_query_from_id[$id]}" = "$Admin_ID" ]]; then
        local msg1
        msg1="━━━━━━━━━━━━━━━━━━━━━\n📃 List Reseller !\n━━━━━━━━━━━━━━━━━━━━━\n"
        cek_res_token=$(cat $Res_Token | awk '{print $NF}' | sed -e 's/[^0-9]//ig'| rev)
        gg=$(cat $Res_Token | awk '{print $NF}')
        [[ "$(cat /etc/.maAsiss/res_token | wc -l)" != '0' ]] && {
            while read _atvs; do
                _uativ="$(echo $_atvs | awk '{print $2}')"
                _cursald="$(echo $_atvs | awk '{print $4}')"
                msg1+="• [Reseller](tg://user?id=$_uativ) | • $_cursald \n"
            done <<<"$(grep -w "$cek_res_token" "$User_Active")"
            ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
                --message_id ${callback_query_message_message_id[$id]} \
                --text "$(echo -e "$msg1")" \
                --parse_mode markdown \
                --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'list_bck_adm')" \
            return 0
        } || {
            ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "YOU DO NOT HAVE RESELLERS"
            return 0
        }
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

topup_res() {
        gg=$(cat $Res_Token | awk '{print $2}')
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> List name reseller</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<code>$gg</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
                --message_id ${callback_query_message_message_id[$id]} \
                --text "$env_msg" \
                --parse_mode html 
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "💸 Topup Saldo 💸\n\nName reseller:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_topup_res() {
    userna=$1
    saldo=$2
    _SaldoTotal=$(grep -w 'Saldo_Reseller' /etc/.maAsiss/db_reseller/$userna/$userna | awk '{print $NF}')
    _TopUpSal=$(echo $_SaldoTotal + $saldo | bc)
    sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_TopUpSal" /etc/.maAsiss/db_reseller/$userna/$userna
    sed -i "/$userna/c\USER: $userna SALDO: $_TopUpSal TYPE: reseller" $User_Active
}

func_verif_limite_res() {
    userna=$1
    [[ "$(grep -w "$userna" $User_Active | awk '{print $NF}')" == 'reseller' ]] && {
        echo $_userrev
        _result=$(ls /etc/.maAsiss/db_reseller/$userna/trial-fold | wc -l)       
    }
}

func_limit_publik() {
   getMes=$1
   getLimits=$(grep -w "MAX_USERS" "/etc/.maAsiss/public_mode/settings" | awk '{print $NF}')
   _result=$(ls /etc/.maAsiss/public_mode/$getMes | wc -l)
   [[ ! -d /etc/.maAsiss/public_mode ]] && {
       ShellBot.sendMessage --chat_id ${callback_query_from_id[$id]} \
                    --text "⛔ Public mode is off" \
                    --parse_mode html
                ShellBot.sendMessage --chat_id
                return 0
   }
   _result2=$(ls /etc/.maAsiss/public_mode --ignore='settings' | wc -l)
   [[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]] && {
       [[ "$_result2" -ge "$getLimits" ]] && {
            ShellBot.sendMessage --chat_id ${callback_query_from_id[$id]} \
                    --text "⛔ Max $getLimits Users" \
                    --parse_mode html
                ShellBot.sendMessage --chat_id
                return 0
       }
       [[ "$_result" -ge "1" ]] && {
            ShellBot.sendMessage --chat_id ${callback_query_from_id[$id]} \
                    --text "⛔ Max Limit Create only 1 Users" \
                    --parse_mode html
                ShellBot.sendMessage --chat_id
                return 0
       }
   }
}

res_ssh_menu() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_re')"
        return 0
    }
}

unset menu_re
menu_re=''
ShellBot.InlineKeyboardButton --button 'menu_re' --line 1 --text '➕ Add SSH ➕' --callback_data '_add_res_ssh'
ShellBot.InlineKeyboardButton --button 'menu_re' --line 2 --text '🟢 List Member SSH 🟢' --callback_data '_member_res_ssh'
ShellBot.InlineKeyboardButton --button 'menu_re' --line 3 --text '⏳ Create Trial SSH ⏳' --callback_data '_trial_res_ssh'
ShellBot.InlineKeyboardButton --button 'menu_re' --line 4 --text '🔙 Back 🔙' --callback_data '_goback'
ShellBot.regHandleFunction --function adduser_ssh --callback_data _add_res_ssh
ShellBot.regHandleFunction --function info_users_ssh --callback_data _member_res_ssh
ShellBot.regHandleFunction --function add_ssh_trial --callback_data _trial_res_ssh
ShellBot.regHandleFunction --function menu_reserv --callback_data _goback
unset menu_re1
menu_re1="$(ShellBot.InlineKeyboardMarkup -b 'menu_re')"

unset menu1
menu1=''
ShellBot.InlineKeyboardButton --button 'menu1' --line 1 --text 'Add SSH' --callback_data '_add_ssh'
ShellBot.InlineKeyboardButton --button 'menu1' --line 1 --text 'Del SSH' --callback_data '_del_ssh'
ShellBot.InlineKeyboardButton --button 'menu1' --line 2 --text 'Renew SSH' --callback_data '_renew_ssh'
ShellBot.InlineKeyboardButton --button 'menu1' --line 3 --text 'Member SSH' --callback_data '_member_ssh'
ShellBot.InlineKeyboardButton --button 'menu1' --line 3 --text 'User Online' --callback_data '_online_ssh'
ShellBot.InlineKeyboardButton --button 'menu1' --line 4 --text 'Create Trial SSH' --callback_data '_trial_ssh'
ShellBot.InlineKeyboardButton --button 'menu1' --line 5 --text '🔙 Back 🔙' --callback_data '_goback1'
ShellBot.regHandleFunction --function adduser_ssh --callback_data _add_ssh
ShellBot.regHandleFunction --function del_ssh --callback_data _del_ssh
ShellBot.regHandleFunction --function renew_ssh --callback_data _renew_ssh
ShellBot.regHandleFunction --function info_users_ssh --callback_data _member_ssh
ShellBot.regHandleFunction --function user_online_ssh --callback_data _online_ssh
ShellBot.regHandleFunction --function add_ssh_trial --callback_data _trial_ssh
ShellBot.regHandleFunction --function admin_service_see --callback_data _goback1
unset keyboard2
keyboard2="$(ShellBot.InlineKeyboardMarkup -b 'menu1')"


#====== ALL ABOUT V2RAY =======#

res_v2ray_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'res_menu_vray')"
        return 0
    }
}
v2ray_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_vray')"
        return 0
    }
}

add_ray() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE USER VMess 👤\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_add_ray() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderVMESS ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Disable Order VMESS" \
                    --parse_mode html
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                   --text "Func Error Do Nothing" \
                   --reply_markup "$(ShellBot.ForceReply)"
            return 0
    }
}

file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
data=$(sed -n '2 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)
        
domain=$(cat /etc/$raycheck/domain)
tls="$(cat /root/log-install.txt | grep -w "Vmess TLS" | cut -d: -f2|sed 's/ //g')"
none="$(cat /root/log-install.txt | grep -w "Vmess None TLS" | cut -d: -f2|sed 's/ //g')"

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-v2ray
echo "$userna:$data" >/etc/.maAsiss/info-user-v2ray/$userna
uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vmessWSTLS$/a\### '"$userna $exp"'\
},{"id": "'""$uuid""'","alterId": '"64"',"email": "'""$userna""'"' /etc/$raycheck/config.json
sed -i '/#vmessWS$/a\### '"$userna $exp"'\
},{"id": "'""$uuid""'","alterId": '"64"',"email": "'""$userna""'"' /etc/$raycheck/config.json
            
cat> /etc/$raycheck/$userna-tls.json <<-EOF
{
"v": "2",
"ps": "${userna}",
"add": "${domain}",
"port": "${tls}",
"id": "${uuid}",
"aid": "64",
"net": "ws",
"path": "/${raycheck}ws",
"type": "none",
"host": "",
"tls": "tls"
}
EOF
cat> /etc/$raycheck/$userna-none.json <<-EOF
{
"v": "2",
"ps": "${userna}",
"add": "${domain}",
"port": "${none}",
"id": "${uuid}",
"aid": "64",
"net": "ws",
"path": "/${raycheck}ws",
"type": "none",
"host": "",
"tls": "none"
}
EOF
            
vmess_base641=$( base64 -w 0 <<< $vmess_json1)
vmess_base642=$( base64 -w 0 <<< $vmess_json2)
vmesslink1="vmess://$(base64 -w 0 /etc/$raycheck/$userna-tls.json)"
vmesslink2="vmess://$(base64 -w 0 /etc/$raycheck/$userna-none.json)"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>      🔸 VMESS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Domain : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data 📆\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TLS : $tls\n"
env_msg+="Port None TLS : $none\n"
env_msg+="ID : $uuid\n"
env_msg+="AlterID : 64\n"
env_msg+="Security : auto\n"
env_msg+="Network : websocket/ws\n"
env_msg+="Path : /${raycheck}ws\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TLS : \n<code>$vmesslink1</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link None TLS : \n<code>$vmesslink2</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
rm /etc/$raycheck/$userna-tls.json > /dev/null 2>&1
rm /etc/$raycheck/$userna-none.json > /dev/null 2>&1

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart $raycheck > /dev/null 2>&1
return 0
}

pricevmess=$(grep -w "Price VMess" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
if [ "$saldores" -lt "$pricevmess" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-v2ray
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_ray
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_ray/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-v2ray/$userna
_CurrSal=$(echo $saldores - $pricevmess | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active
            
uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vmessWSTLS$/a\### '"$userna $exp"'\
},{"id": "'""$uuid""'","alterId": '"64"',"email": "'""$userna""'"' /etc/$raycheck/config.json
sed -i '/#vmessWS$/a\### '"$userna $exp"'\
},{"id": "'""$uuid""'","alterId": '"64"',"email": "'""$userna""'"' /etc/$raycheck/config.json
            
cat> /etc/$raycheck/$userna-tls.json <<-EOF
{
"v": "2",
"ps": "${userna}",
"add": "${domain}",
"port": "${tls}",
"id": "${uuid}",
"aid": "64",
"net": "ws",
"path": "/${raycheck}ws",
"type": "none",
"host": "",
"tls": "tls"
}
EOF
cat> /etc/$raycheck/$userna-none.json <<-EOF
{
"v": "2",
"ps": "${userna}",
"add": "${domain}",
"port": "${none}",
"id": "${uuid}",
"aid": "64",
"net": "ws",
"path": "/${raycheck}ws",
"type": "none",
"host": "",
"tls": "none"
}
EOF
            
vmess_base641=$( base64 -w 0 <<< $vmess_json1)
vmess_base642=$( base64 -w 0 <<< $vmess_json2)
vmesslink1="vmess://$(base64 -w 0 /etc/$raycheck/$userna-tls.json)"
vmesslink2="vmess://$(base64 -w 0 /etc/$raycheck/$userna-none.json)"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>      🔸 VMESS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Domain : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TLS : $tls\n"
env_msg+="Port None TLS : $none\n"
env_msg+="ID : $uuid\n"
env_msg+="AlterID : 64\n"
env_msg+="Security : auto\n"
env_msg+="Network : websocket/ws\n"
env_msg+="Path : /${raycheck}ws\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TLS : \n<code>$vmesslink1</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link None TLS : \n<code>$vmesslink2</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
rm /etc/$raycheck/$userna-tls.json > /dev/null 2>&1
rm /etc/$raycheck/$userna-none.json > /dev/null 2>&1
echo "$userna 30Days VMESS | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart $raycheck > /dev/null 2>&1
return 0
fi
}

func_add_ray2() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderVMESS ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Disable Order VMESS" \
                    --parse_mode html
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                   --text "Func Error Do Nothing" \
                   --reply_markup "$(ShellBot.ForceReply)"
            return 0
    }
}
file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
data=$(sed -n '2 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)
        
domain=$(cat /etc/$raycheck/domain)
tls="$(cat /root/log-install.txt | grep -w "Vmess TLS" | cut -d: -f2|sed 's/ //g')"
none="$(cat /root/log-install.txt | grep -w "Vmess None TLS" | cut -d: -f2|sed 's/ //g')"

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-v2ray
echo "$userna:$data" >/etc/.maAsiss/info-user-v2ray/$userna
uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vmessWSTLS$/a\### '"$userna $exp"'\
},{"id": "'""$uuid""'","alterId": '"64"',"email": "'""$userna""'"' /etc/$raycheck/config.json
sed -i '/#vmessWS$/a\### '"$userna $exp"'\
},{"id": "'""$uuid""'","alterId": '"64"',"email": "'""$userna""'"' /etc/$raycheck/config.json
            
cat> /etc/$raycheck/$userna-tls.json <<-EOF
{
"v": "2",
"ps": "${userna}",
"add": "${domain}",
"port": "${tls}",
"id": "${uuid}",
"aid": "64",
"net": "ws",
"path": "/${raycheck}ws",
"type": "none",
"host": "",
"tls": "tls"
}
EOF
cat> /etc/$raycheck/$userna-none.json <<-EOF
{
"v": "2",
"ps": "${userna}",
"add": "${domain}",
"port": "${none}",
"id": "${uuid}",
"aid": "64",
"net": "ws",
"path": "/${raycheck}ws",
"type": "none",
"host": "",
"tls": "none"
}
EOF
            
vmess_base641=$( base64 -w 0 <<< $vmess_json1)
vmess_base642=$( base64 -w 0 <<< $vmess_json2)
vmesslink1="vmess://$(base64 -w 0 /etc/$raycheck/$userna-tls.json)"
vmesslink2="vmess://$(base64 -w 0 /etc/$raycheck/$userna-none.json)"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>      🔸 VMESS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Domain : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TLS : $tls\n"
env_msg+="Port None TLS : $none\n"
env_msg+="ID : $uuid\n"
env_msg+="AlterID : 64\n"
env_msg+="Security : auto\n"
env_msg+="Network : websocket/ws\n"
env_msg+="Path : /${raycheck}ws\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TLS : \n<code>$vmesslink1</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link None TLS : \n<code>$vmesslink2</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
rm /etc/$raycheck/$userna-tls.json > /dev/null 2>&1
rm /etc/$raycheck/$userna-none.json > /dev/null 2>&1

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart $raycheck > /dev/null 2>&1
return 0
}

pricevmess=$(grep -w "Price VMess" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
urday=$(echo $pricevmess * 2 | bc)
if [ "$saldores" -lt "$urday" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-v2ray
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_ray
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_ray/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-v2ray/$userna
_CurrSal=$(echo $saldores - $urday | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active
            
uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vmessWSTLS$/a\### '"$userna $exp"'\
},{"id": "'""$uuid""'","alterId": '"64"',"email": "'""$userna""'"' /etc/$raycheck/config.json
sed -i '/#vmessWS$/a\### '"$userna $exp"'\
},{"id": "'""$uuid""'","alterId": '"64"',"email": "'""$userna""'"' /etc/$raycheck/config.json
            
cat> /etc/$raycheck/$userna-tls.json <<-EOF
{
"v": "2",
"ps": "${userna}",
"add": "${domain}",
"port": "${tls}",
"id": "${uuid}",
"aid": "64",
"net": "ws",
"path": "/${raycheck}ws",
"type": "none",
"host": "",
"tls": "tls"
}
EOF
cat> /etc/$raycheck/$userna-none.json <<-EOF
{
"v": "2",
"ps": "${userna}",
"add": "${domain}",
"port": "${none}",
"id": "${uuid}",
"aid": "64",
"net": "ws",
"path": "/${raycheck}ws",
"type": "none",
"host": "",
"tls": "none"
}
EOF
            
vmess_base641=$( base64 -w 0 <<< $vmess_json1)
vmess_base642=$( base64 -w 0 <<< $vmess_json2)
vmesslink1="vmess://$(base64 -w 0 /etc/$raycheck/$userna-tls.json)"
vmesslink2="vmess://$(base64 -w 0 /etc/$raycheck/$userna-none.json)"
systemctl restart $raycheck > /dev/null 2>&1

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>      🔸 VMESS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Domain : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TLS : $tls\n"
env_msg+="Port None TLS : $none\n"
env_msg+="ID : $uuid\n"
env_msg+="AlterID : 64\n"
env_msg+="Security : auto\n"
env_msg+="Network : websocket/ws\n"
env_msg+="Path : /${raycheck}ws\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TLS : \n<code>$vmesslink1</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link None TLS : \n<code>$vmesslink2</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
rm /etc/$raycheck/$userna-tls.json > /dev/null 2>&1
rm /etc/$raycheck/$userna-none.json > /dev/null 2>&1
echo "$userna 60Days VMESS | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
return 0
fi
}

del_ray() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🗑 REMOVE USER V2RAY 🗑\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_del_ray() {
    userna=$1
    [[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
        exp=$(grep -wE "^### $userna" "/etc/$raycheck/config.json" | cut -d ' ' -f 3 | sort | uniq)
        sed -i "/^### $userna $exp/,/^},{/d" /etc/$raycheck/config.json
        datata=$(find /etc/.maAsiss/ -name $userna)
        for accc in "${datata[@]}"
        do
        rm $accc
        done
        systemctl restart $raycheck > /dev/null 2>&1
    } || {
        [[ ! -e /etc/.maAsiss/db_reseller/${message_from_id}/user_ray/$userna ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "⛔ THE USER DOES NOT EXIST ⛔")" \
                --parse_mode html
            _erro='1'      
            ShellBot.sendMessage --chat_id ${callack_query_message_chat_id[$id]} \
                 --text "Func Error Do Nothing" \
                 --reply_markup "$(ShellBot.ForceReply)"
            return 0
        }
        exp=$(grep -wE "^### $userna" "/etc/$raycheck/config.json" | cut -d ' ' -f 3 | sort | uniq)
        sed -i "/^### $userna $exp/,/^},{/d" /etc/$raycheck/config.json
        rm /etc/.maAsiss/db_reseller/${message_from_id}/user_ray/$userna
        rm /etc/.maAsiss/info-user-v2ray/$userna
        systemctl restart $raycheck > /dev/null 2>&1
    }
}

add_ray_trial() {
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE TRIAL VMess 👤\n\nHow many hours should it last ? EX: 1:" \
            --reply_markup "$(ShellBot.ForceReply)"
    elif [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]]; then
            ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "👤 CREATE TRIAL VMess 👤\n\nHow many hours should it last ? EX: 1:" \
                --reply_markup "$(ShellBot.ForceReply)"       
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

func_add_ray_trial() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderVMESS ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Disable Order VMESS" \
                    --parse_mode html
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                   --text "Func Error Do Nothing" \
                   --reply_markup "$(ShellBot.ForceReply)"
            return 0
    }
}
    mkdir -p /etc/.maAsiss/info-user-v2ray
    userna=$(echo Trial`</dev/urandom tr -dc A-Z0-9 | head -c4`)
    t_time=$1
    domain=$(cat /etc/$raycheck/domain)
    tls="$(cat /root/log-install.txt | grep -w "Vmess TLS" | cut -d: -f2|sed 's/ //g')"
    none="$(cat /root/log-install.txt | grep -w "Vmess None TLS" | cut -d: -f2|sed 's/ //g')"

    exp=`date -d "2 days" +"%Y-%m-%d"`
    tuserdate=$(date '+%C%y/%m/%d' -d " +2 days")
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
       mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold
    }
    [[ -z $t_time ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e "⛔ error try again")" \
            --parse_mode html
        return 0
        _erro='1'
    }

echo "$userna:$exp" >/etc/.maAsiss/info-user-v2ray/$userna
uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vmessWSTLS$/a\### '"$userna $exp"'\
},{"id": "'""$uuid""'","alterId": '"64"',"email": "'""$userna""'"' /etc/$raycheck/config.json
sed -i '/#vmessWS$/a\### '"$userna $exp"'\
},{"id": "'""$uuid""'","alterId": '"64"',"email": "'""$userna""'"' /etc/$raycheck/config.json
            
cat> /etc/$raycheck/$userna-tls.json <<-EOF
{
"v": "2",
"ps": "${userna}",
"add": "${domain}",
"port": "${tls}",
"id": "${uuid}",
"aid": "64",
"net": "ws",
"path": "/${raycheck}ws",
"type": "none",
"host": "",
"tls": "tls"
}
EOF
cat> /etc/$raycheck/$userna-none.json <<-EOF
{
"v": "2",
"ps": "${userna}",
"add": "${domain}",
"port": "${none}",
"id": "${uuid}",
"aid": "64",
"net": "ws",
"path": "/${raycheck}ws",
"type": "none",
"host": "",
"tls": "none"
}
EOF
  
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    echo "$userna:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/user_ray/$userna
    echo "$userna:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna
}
dir_teste="/etc/.maAsiss/db_reseller/${message_from_id}/user_ray/$userna"
dir_teste2="/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna"
dates=`date`
cat <<-EOF >/etc/.maAsiss/$userna.sh
#!/bin/bash
# USER TRIAL VMESS by ${message_from_id} $dates
exp=\$(grep -wE "^### $userna" "/etc/$raycheck/config.json" | cut -d ' ' -f 3 | sort | uniq)
sed -i "/^### $userna $exp/,/^},{/d" /etc/$raycheck/config.json
systemctl restart $raycheck > /dev/null 2>&1
rm /etc/.maAsiss/db_reseller/${message_from_id}/user_ray/$userna
rm /etc/.maAsiss/info-user-v2ray/$userna
[[ -e $dir_teste ]] && rm $dir_teste
[[ -e $dir_teste2 ]] && rm $dir_teste2
rm -f /etc/.maAsiss/$userna
rm -f /etc/.maAsiss/$userna.sh
EOF
chmod +x /etc/.maAsiss/$userna.sh
echo "/etc/.maAsiss/$userna.sh" | at now + $t_time hour >/dev/null 2>&1
[[ "$t_time" == '1' ]] && hrs="hour" || hrs="hours"          
vmess_base641=$( base64 -w 0 <<< $vmess_json1)
vmess_base642=$( base64 -w 0 <<< $vmess_json2)
vmesslink1="vmess://$(base64 -w 0 /etc/$raycheck/$userna-tls.json)"
vmesslink2="vmess://$(base64 -w 0 /etc/$raycheck/$userna-none.json)"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>      🔸 VMESS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Domain : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $t_time $hrs ⏳ \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TLS : $tls\n"
env_msg+="Port None TLS : $none\n"
env_msg+="ID : $uuid\n"
env_msg+="AlterID : 64\n"
env_msg+="Security : auto\n"
env_msg+="Network : websocket/ws\n"
env_msg+="Path : /${raycheck}ws\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TLS : \n<code>$vmesslink1</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link None TLS : \n<code>$vmesslink2</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
rm /etc/$raycheck/$userna-tls.json > /dev/null 2>&1
rm /etc/$raycheck/$userna-none.json > /dev/null 2>&1

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart $raycheck > /dev/null 2>&1
return 0

}

list_member_ray() {
   if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
      _result=$(grep -E "^### " "/etc/$raycheck/config.json" | cut -d ' ' -f 2 | column -t | sort | uniq | wc -l)
      _results=$(grep -E "^### " "/etc/$raycheck/config.json" | cut -d ' ' -f 2 | column -t | sort | uniq )
   elif [[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]]; then
      _result=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_ray | wc -l)
      _results=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_ray )
   else
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ ACCESS DENIED ⛔" \
                --parse_mode html
      return 0
   fi
   if [ "$_result" = "0" ]; then
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ YOU DONT HAVE ANY USER YET ⛔" \
                --parse_mode html
      return 0
   else
      ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
      ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
         --text "━━━━━━━━━━━━━━━━━━━━━\n 🏁 VMESS MEMBER LIST 🏁 \n━━━━━━━━━━━━━━━━━━━━━\n\n$_results\n\n━━━━━━━━━━━━━━━━━━━━━\n" \
         --parse_mode html
      return 0
   fi
}

check_login_ray(){
if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
echo -n > /tmp/other.txt
data=( `cat /etc/$raycheck/config.json | grep '^###' | cut -d ' ' -f 2 | sort | uniq`);

echo -e "━━━━━━━━━━━━━━━━━━━━━" > /tmp/vmess-login
echo -e "         🟢 Vmess User Login 🟢  " >> /tmp/vmess-login
echo -e "━━━━━━━━━━━━━━━━━━━━━" >> /tmp/vmess-login

for akun in "${data[@]}"
do
if [[ -z "$akun" ]]; then
akun="tidakada"
fi

echo -n > /tmp/ipvmess.txt
data2=( `netstat -anp | grep ESTABLISHED | grep tcp6 | grep $raycheck | awk '{print $5}' | cut -d: -f1 | sort | uniq`);
for ip in "${data2[@]}"
do

jum=$(cat /var/log/$raycheck/access.log | grep -w $akun | awk '{print $3}' | cut -d: -f1 | grep -w $ip | sort | uniq)
if [[ "$jum" = "$ip" ]]; then
echo "$jum" >> /tmp/ipvmess.txt
else
echo "$ip" >> /tmp/other.txt
fi
jum2=$(cat /tmp/ipvmess.txt)
sed -i "/$jum2/d" /tmp/other.txt > /dev/null 2>&1
done

jum=$(cat /tmp/ipvmess.txt)
if [[ -z "$jum" ]]; then
echo > /dev/null
else
jum2=$(cat /tmp/ipvmess.txt | nl)
echo "user : $akun" >> /tmp/vmess-login
echo "$jum2" >> /tmp/vmess-login
echo -e "━━━━━━━━━━━━━━━━━━━━━" >> /tmp/vmess-login
fi
rm -rf /tmp/ipvmess.txt
done

oth=$(cat /tmp/other.txt | sort | uniq | nl)
echo "other" >> /tmp/vmess-login
echo "$oth" >> /tmp/vmess-login
echo -e "━━━━━━━━━━━━━━━━━━━━━" >> /tmp/vmess-login
rm -rf /tmp/other.txt
msg=$(cat /tmp/vmess-login)
cekk=$(cat /tmp/vmess-login | wc -l)
if [ "$cekk" = "0" ] || [ "$cekk" = "6" ]; then
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ NO USERS ONLINE ⛔" \
                --parse_mode html
rm /tmp/vmess-login
return 0
else
ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
         --text "$msg" \
         --parse_mode html
rm /tmp/vmess-login
return 0
fi
else
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ ACCESS DENIED ⛔" \
                --parse_mode html
return 0
fi
}

unset menu_vray
menu_vray=''
ShellBot.InlineKeyboardButton --button 'menu_vray' --line 1 --text 'Add VMess' --callback_data '_add_ray'
ShellBot.InlineKeyboardButton --button 'menu_vray' --line 2 --text 'Delete VMess' --callback_data '_del_ray'
ShellBot.InlineKeyboardButton --button 'menu_vray' --line 3 --text 'Create Trial VMess' --callback_data '_trial_ray'
ShellBot.InlineKeyboardButton --button 'menu_vray' --line 4 --text 'List Member VMess' --callback_data '_list_ray'
ShellBot.InlineKeyboardButton --button 'menu_vray' --line 5 --text 'Check User Login VMess' --callback_data '_login_ray'
ShellBot.InlineKeyboardButton --button 'menu_vray' --line 6 --text '🔙 Back 🔙' --callback_data '_gobackray'
ShellBot.regHandleFunction --function add_ray --callback_data _add_ray
ShellBot.regHandleFunction --function del_ray --callback_data _del_ray
ShellBot.regHandleFunction --function add_ray_trial --callback_data _trial_ray
ShellBot.regHandleFunction --function list_member_ray --callback_data _list_ray
ShellBot.regHandleFunction --function check_login_ray --callback_data _login_ray
ShellBot.regHandleFunction --function admin_service_see --callback_data _gobackray
unset keyboardray
keyboardray="$(ShellBot.InlineKeyboardMarkup -b 'menu_vray')"

unset res_menu_vray
res_menu_vray=''
ShellBot.InlineKeyboardButton --button 'res_menu_vray' --line 1 --text '➕ Add VMess ➕' --callback_data '_res_add_ray'
ShellBot.InlineKeyboardButton --button 'res_menu_vray' --line 2 --text '⏳ Create Trial VMess ⏳' --callback_data '_res_trial_ray'
ShellBot.InlineKeyboardButton --button 'res_menu_vray' --line 3 --text '🟢 List Member VMess 🟢' --callback_data '_res_list_ray'
ShellBot.InlineKeyboardButton --button 'res_menu_vray' --line 4 --text '🔙 Back 🔙' --callback_data '_res_gobackray'
ShellBot.regHandleFunction --function add_ray --callback_data _res_add_ray
ShellBot.regHandleFunction --function add_ray_trial --callback_data _res_trial_ray
ShellBot.regHandleFunction --function list_member_ray --callback_data _res_list_ray
ShellBot.regHandleFunction --function menu_reserv --callback_data _res_gobackray
unset keyboardrayres
keyboardrayres="$(ShellBot.InlineKeyboardMarkup -b 'res_menu_vray')"

#======= TROJAN MENU =========

res_trojan_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'res_menu_trojan')"
        return 0
    }
}
trojan_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_trojan')"
        return 0
    }
}

add_trojan() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE USER Trojan 👤\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_add_trojan() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderTROJAN ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Disable Order TROJAN" \
                --parse_mode html
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
               --text "Func Error Do Nothing" \
               --reply_markup "$(ShellBot.ForceReply)"
        return 0
    }
}

file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
data=$(sed -n '2 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)
        
domain=$(cat /etc/$raycheck/domain)
tr="$(cat /root/log-install.txt | grep -w "Trojan " | cut -d: -f2|sed 's/ //g')"

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-trojan
echo "$userna:$data" >/etc/.maAsiss/info-user-trojan/$userna

uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#trojanTLS$/a\#! '"$userna $exp"'\
},{"password": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json

trojanlink="trojan://${uuid}@${domain}:${tr}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>     🔸 TROJAN ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Domain : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data ⏳ \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TR : $tr\n"
env_msg+="Key : $uuid\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link : \n<code>$trojanlink</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart $raycheck > /dev/null 2>&1
return 0
}

pricetrojan=$(grep -w "Price Trojan :" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
if [ "$saldores" -lt "$pricetrojan" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-trojan
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_trojan
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_trojan/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-trojan/$userna
_CurrSal=$(echo $saldores - $pricetrojan | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#trojanTLS$/a\#! '"$userna $exp"'\
},{"password": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json

trojanlink="trojan://${uuid}@${domain}:${tr}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>     🔸 TROJAN ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Domain : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data 📆 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TR : $tr\n"
env_msg+="Key : $uuid\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link : \n<code>$trojanlink</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 30Days TROJAN | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart $raycheck > /dev/null 2>&1
return 0
fi
}

func_add_trojan2() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderTROJAN ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Disable Order TROJAN" \
                --parse_mode html
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
               --text "Func Error Do Nothing" \
               --reply_markup "$(ShellBot.ForceReply)"
        return 0
    }
}
file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
data=$(sed -n '2 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)
        
domain=$(cat /etc/$raycheck/domain)
tr="$(cat /root/log-install.txt | grep -w "Trojan " | cut -d: -f2|sed 's/ //g')"

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-trojan
echo "$userna:$data" >/etc/.maAsiss/info-user-trojan/$userna

uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#trojanTLS$/a\#! '"$userna $exp"'\
},{"password": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json

trojanlink="trojan://${uuid}@${domain}:${tr}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>     🔸 TROJAN ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Domain : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data 📆 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TR : $tr\n"
env_msg+="Key : $uuid\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link : \n<code>$trojanlink</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart $raycheck > /dev/null 2>&1
return 0
}

pricetrojan=$(grep -w "Price Trojan :" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
urday=$(echo $pricetrojan * 2 | bc)
if [ "$saldores" -lt "$urday" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-trojan
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_trojan
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_trojan/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-trojan/$userna
_CurrSal=$(echo $saldores - $urday | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#trojanTLS$/a\#! '"$userna $exp"'\
},{"password": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json

trojanlink="trojan://${uuid}@${domain}:${tr}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>     🔸 TROJAN ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Domain : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data 📆 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TR : $tr\n"
env_msg+="Key : $uuid\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link : \n<code>$trojanlink</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 60Days TROJAN | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html

systemctl restart $raycheck > /dev/null 2>&1
return 0
fi
}

del_trojan() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🗑 REMOVE USER TROJAN 🗑\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_del_trojan() {
    userna=$1
    [[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
        exp=$(grep -wE "^#! $userna" "/etc/$raycheck/config.json" | cut -d ' ' -f 3 | sort | uniq)
        sed -i "/^#! $userna $exp/,/^},{/d" /etc/$raycheck/config.json
        datata=$(find /etc/.maAsiss/ -name $userna)
        for accc in "${datata[@]}"
        do
        rm $accc
        done
        systemctl restart $raycheck > /dev/null 2>&1
    } || {
        [[ ! -e /etc/.maAsiss/db_reseller/${message_from_id}/user_trojan/$userna ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "⛔ THE USER DOES NOT EXIST ⛔")" \
                --parse_mode html
            _erro='1'      
            ShellBot.sendMessage --chat_id ${callack_query_message_chat_id[$id]} \
                 --text "Func Error Do Nothing" \
                 --reply_markup "$(ShellBot.ForceReply)"
            return 0
        }
        exp=$(grep -wE "^#! $userna" "/etc/$raycheck/config.json" | cut -d ' ' -f 3 | sort | uniq)
        sed -i "/^#! $userna $exp/,/^},{/d" /etc/$raycheck/config.json
        rm /etc/.maAsiss/db_reseller/${message_from_id}/user_trojan/$userna
        rm /etc/.maAsiss/info-user-trojan/$userna
        systemctl restart $raycheck > /dev/null 2>&1
    }
}

add_trojan_trial() {
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE TRIAL Trojan 👤\n\nHow many hours should it last ? EX: 1:" \
            --reply_markup "$(ShellBot.ForceReply)"
    elif [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]]; then
            ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "👤 CREATE TRIAL Trojan 👤\n\nHow many hours should it last ? EX: 1:" \
                --reply_markup "$(ShellBot.ForceReply)"       
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

func_add_trojan_trial() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderTROJAN ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Disable Order TROJAN" \
                --parse_mode html
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
               --text "Func Error Do Nothing" \
               --reply_markup "$(ShellBot.ForceReply)"
        return 0
    }
}
    mkdir -p /etc/.maAsiss/info-user-trojan
    userna=$(echo Trial`</dev/urandom tr -dc A-Z0-9 | head -c4`)
    t_time=$1
    domain=$(cat /etc/$raycheck/domain)
    tr="$(cat /root/log-install.txt | grep -w "Trojan " | cut -d: -f2|sed 's/ //g')"

    exp=`date -d "2 days" +"%Y-%m-%d"`
    tuserdate=$(date '+%C%y/%m/%d' -d " +2 days")
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
       mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold
    }
    [[ -z $t_time ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e "⛔ error try again")" \
            --parse_mode html
        return 0
        _erro='1'
    }
    
echo "$userna:$exp" >/etc/.maAsiss/info-user-trojan/$userna
uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#trojanTLS$/a\#! '"$userna $exp"'\
},{"password": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json
  
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    echo "$userna:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/user_trojan/$userna
    echo "$userna:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna
}
dir_teste="/etc/.maAsiss/db_reseller/${message_from_id}/user_trojan/$userna"
dir_teste2="/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna"
dates=`date`
cat <<-EOF >/etc/.maAsiss/$userna.sh
#!/bin/bash
# USER TRIAL TROJAN by ${message_from_id} $dates
exp=\$(grep -wE "^#! $userna" "/etc/$raycheck/config.json" | cut -d ' ' -f 3 | sort | uniq)
sed -i "/^#! $userna $exp/,/^},{/d" /etc/$raycheck/config.json
systemctl restart $raycheck > /dev/null 2>&1
rm /etc/.maAsiss/db_reseller/${message_from_id}/user_trojan/$userna
rm /etc/.maAsiss/info-user-trojan/$userna
[[ -e $dir_teste ]] && rm $dir_teste
[[ -e $dir_teste2 ]] && rm $dir_teste2
rm -f /etc/.maAsiss/$userna
rm -f /etc/.maAsiss/$userna.sh
EOF
chmod +x /etc/.maAsiss/$userna.sh
echo "/etc/.maAsiss/$userna.sh" | at now + $t_time hour >/dev/null 2>&1
[[ "$t_time" == '1' ]] && hrs="hour" || hrs="hours"          

trojanlink="trojan://${uuid}@${domain}:${tr}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>     🔸 TROJAN ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Domain : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $t_time $hrs ⏳ \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TR : $tr\n"
env_msg+="Key : $uuid\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link : \n<code>$trojanlink</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart $raycheck > /dev/null 2>&1
return 0

}

list_member_trojan() {
   if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
      _result=$(grep -E "^#! " "/etc/$raycheck/config.json" | cut -d ' ' -f 2 | column -t | sort | uniq | wc -l)
      _results=$(grep -E "^#! " "/etc/$raycheck/config.json" | cut -d ' ' -f 2 | column -t | sort | uniq )
   elif [[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]]; then
      _result=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_trojan | wc -l)
      _results=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_trojan )
   else
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ ACCESS DENIED ⛔" \
                --parse_mode html
      return 0
   fi
   if [ "$_result" = "0" ]; then
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ YOU DONT HAVE ANY USER YET ⛔" \
                --parse_mode html
      return 0
   else
      ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
      ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
         --text "━━━━━━━━━━━━━━━━━━━━━\n 🟢 TROJAN MEMBER LIST 🟢 \n━━━━━━━━━━━━━━━━━━━━━\n\n$_results\n\n━━━━━━━━━━━━━━━━━━━━━\n" \
         --parse_mode html
      return 0
   fi
}

check_login_trojan(){
if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
echo -n > /tmp/other.txt
data=( `cat /etc/$raycheck/config.json | grep '^#!' | cut -d ' ' -f 2 | sort | uniq`);

echo -e "━━━━━━━━━━━━━━━━━━━━━" > /tmp/vmess-login
echo -e "         🟢 Trojan User Login 🟢  " >> /tmp/vmess-login
echo -e "━━━━━━━━━━━━━━━━━━━━━" >> /tmp/vmess-login

for akun in "${data[@]}"
do
if [[ -z "$akun" ]]; then
akun="tidakada"
fi

echo -n > /tmp/ipvmess.txt
data2=( `netstat -anp | grep ESTABLISHED | grep tcp6 | grep $raycheck | awk '{print $5}' | cut -d: -f1 | sort | uniq`);
for ip in "${data2[@]}"
do

jum=$(cat /var/log/$raycheck/access.log | grep -w $akun | awk '{print $3}' | cut -d: -f1 | grep -w $ip | sort | uniq)
if [[ "$jum" = "$ip" ]]; then
echo "$jum" >> /tmp/ipvmess.txt
else
echo "$ip" >> /tmp/other.txt
fi
jum2=$(cat /tmp/ipvmess.txt)
sed -i "/$jum2/d" /tmp/other.txt > /dev/null 2>&1
done

jum=$(cat /tmp/ipvmess.txt)
if [[ -z "$jum" ]]; then
echo > /dev/null
else
jum2=$(cat /tmp/ipvmess.txt | nl)
echo "user : $akun" >> /tmp/vmess-login
echo "$jum2" >> /tmp/vmess-login
echo -e "━━━━━━━━━━━━━━━━━━━━━" >> /tmp/vmess-login
fi
rm -rf /tmp/ipvmess.txt
done

oth=$(cat /tmp/other.txt | sort | uniq | nl)
echo "other" >> /tmp/vmess-login
echo "$oth" >> /tmp/vmess-login
echo -e "━━━━━━━━━━━━━━━━━━━━━" >> /tmp/vmess-login
rm -rf /tmp/other.txt
msg=$(cat /tmp/vmess-login)
cekk=$(cat /tmp/vmess-login | wc -l)
if [ "$cekk" = "0" ] || [ "$cekk" = "6" ]; then
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ NO USERS ONLINE ⛔" \
                --parse_mode html
rm /tmp/vmess-login
return 0
else
ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
         --text "$msg" \
         --parse_mode html
rm /tmp/vmess-login
return 0
fi
else
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ ACCES DENIED ⛔" \
                --parse_mode html
return 0
fi
}

unset menu_trojan
menu_trojan=''
ShellBot.InlineKeyboardButton --button 'menu_trojan' --line 1 --text 'Add Trojan' --callback_data '_add_trojan'
ShellBot.InlineKeyboardButton --button 'menu_trojan' --line 2 --text 'Delete Trojan' --callback_data '_delete_trojan'
ShellBot.InlineKeyboardButton --button 'menu_trojan' --line 3 --text 'Create Trial Trojan' --callback_data '_trial_trojan'
ShellBot.InlineKeyboardButton --button 'menu_trojan' --line 4 --text 'List Member Trojan' --callback_data '_member_trojan'
ShellBot.InlineKeyboardButton --button 'menu_trojan' --line 5 --text 'Check User Login Trojan' --callback_data '_login_trojan'
ShellBot.InlineKeyboardButton --button 'menu_trojan' --line 6 --text '🔙 Back 🔙' --callback_data '_gobacktro'
ShellBot.regHandleFunction --function add_trojan --callback_data _add_trojan
ShellBot.regHandleFunction --function del_trojan --callback_data _delete_trojan
ShellBot.regHandleFunction --function add_trojan_trial --callback_data _trial_trojan
ShellBot.regHandleFunction --function list_member_trojan --callback_data _member_trojan
ShellBot.regHandleFunction --function check_login_trojan --callback_data _login_trojan
ShellBot.regHandleFunction --function admin_service_see --callback_data _gobacktro
unset keyboardtro
keyboardtro="$(ShellBot.InlineKeyboardMarkup -b 'menu_trojan')"

unset res_menu_trojan
res_menu_trojan=''
ShellBot.InlineKeyboardButton --button 'res_menu_trojan' --line 1 --text '➕ Add Trojan ➕' --callback_data '_res_add_trojan'
ShellBot.InlineKeyboardButton --button 'res_menu_trojan' --line 3 --text '⏳ Create Trial Trojan ⏳' --callback_data '_res_trial_trojan'
ShellBot.InlineKeyboardButton --button 'res_menu_trojan' --line 4 --text '🟢 List Member Trojan 🟢' --callback_data '_res_member_trojan'
ShellBot.InlineKeyboardButton --button 'res_menu_trojan' --line 5 --text '🔙 Back 🔙' --callback_data '_res_gobacktro'
ShellBot.regHandleFunction --function add_trojan --callback_data _res_add_trojan
ShellBot.regHandleFunction --function add_trojan_trial --callback_data _res_trial_trojan
ShellBot.regHandleFunction --function list_member_trojan --callback_data _res_member_trojan
ShellBot.regHandleFunction --function menu_reserv --callback_data _res_gobacktro
unset keyboardtrores
keyboardtrores="$(ShellBot.InlineKeyboardMarkup -b 'res_menu_trojan')"

#======= VLESS MENU =========
res_vless_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'res_menu_vless')"
        return 0
    }
}

vless_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_vless')"
        return 0
    }
}

add_vless() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE USER VLess 👤\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_add_vless() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderVLESS ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Disable Order VLESS" \
                    --parse_mode html
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                   --text "Func Error Do Nothing" \
                   --reply_markup "$(ShellBot.ForceReply)"
            return 0
    }
}

file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
data=$(sed -n '2 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)
        
domain=$(cat /etc/$raycheck/domain)
tls="$(cat /root/log-install.txt | grep -w "Vless TLS" | cut -d: -f2|sed 's/ //g')"
none="$(cat /root/log-install.txt | grep -w "Vless None TLS" | cut -d: -f2|sed 's/ //g')"

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-vless
echo "$userna:$data" >/etc/.maAsiss/info-user-vless/$userna

uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vlessWSTLS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json
sed -i '/#vlessWS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json

vlesslink1="vless://${uuid}@${domain}:$tls?path=/vlessws%26security=tls%26encryption=none%26type=ws#${userna}"
vlesslink2="vless://${uuid}@${domain}:$none?path=/vlessws%26encryption=none%26type=ws#${userna}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>        🔸 VLESS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TLS : $tls\n"
env_msg+="Port None TLS : $none\n"
env_msg+="ID : <code>$uuid</code>\n"
env_msg+="Encryption : none\n"
env_msg+="Network : websocket/ws\n"
env_msg+="Path : /vlessws\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TLS : \n"
env_msg+="<code>$vlesslink1</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link None TLS : \n"
env_msg+="<code>$vlesslink2</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html 
systemctl restart $raycheck > /dev/null 2>&1
return 0
}

pricevless=$(grep -w "Price VLess" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
if [ "$saldores" -lt "$pricevless" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-vless
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_vless
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_vless/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-vless/$userna
_CurrSal=$(echo $saldores - $pricevless | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vlessWSTLS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json
sed -i '/#vlessWS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json

vlesslink1="vless://${uuid}@${domain}:$tls?path=/vlessws%26security=tls%26encryption=none%26type=ws#${userna}"
vlesslink2="vless://${uuid}@${domain}:$none?path=/vlessws%26encryption=none%26type=ws#${userna}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>        🔸 VLESS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TLS : $tls\n"
env_msg+="Port None TLS : $none\n"
env_msg+="ID : <code>$uuid</code>\n"
env_msg+="Encryption : none\n"
env_msg+="Network : websocket/ws\n"
env_msg+="Path : /vlessws\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TLS : \n"
env_msg+="<code>$vlesslink1</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link None TLS : \n"
env_msg+="<code>$vlesslink2</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 30Days VLESS | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart $raycheck > /dev/null 2>&1
return 0
fi
}

func_add_vless2() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderVLESS ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Disable Order VLESS" \
                    --parse_mode html
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                   --text "Func Error Do Nothing" \
                   --reply_markup "$(ShellBot.ForceReply)"
            return 0
    }
}
file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
data=$(sed -n '2 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)
        
domain=$(cat /etc/$raycheck/domain)
tls="$(cat /root/log-install.txt | grep -w "Vless TLS" | cut -d: -f2|sed 's/ //g')"
none="$(cat /root/log-install.txt | grep -w "Vless None TLS" | cut -d: -f2|sed 's/ //g')"

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-vless
echo "$userna:$data" >/etc/.maAsiss/info-user-vless/$userna

uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vlessWSTLS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json
sed -i '/#vlessWS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json

vlesslink1="vless://${uuid}@${domain}:$tls?path=/vlessws%26security=tls%26encryption=none%26type=ws#${userna}"
vlesslink2="vless://${uuid}@${domain}:$none?path=/vlessws%26encryption=none%26type=ws#${userna}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>        🔸 VLESS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TLS : $tls\n"
env_msg+="Port None TLS : $none\n"
env_msg+="ID : <code>$uuid</code>\n"
env_msg+="Encryption : none\n"
env_msg+="Network : websocket/ws\n"
env_msg+="Path : /vlessws\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TLS : \n"
env_msg+="<code>$vlesslink1</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link None TLS : \n"
env_msg+="<code>$vlesslink2</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html 
systemctl restart $raycheck > /dev/null 2>&1
return 0
}

pricevless=$(grep -w "Price VLess" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
urday=$(echo $pricevless * 2 | bc)
if [ "$saldores" -lt "$urday" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-vless
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_vless
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_vless/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-vless/$userna
_CurrSal=$(echo $saldores - $urday | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vlessWSTLS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json
sed -i '/#vlessWS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json

vlesslink1="vless://${uuid}@${domain}:$tls?path=/vlessws%26security=tls%26encryption=none%26type=ws#${userna}"
vlesslink2="vless://${uuid}@${domain}:$none?path=/vlessws%26encryption=none%26type=ws#${userna}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>        🔸 VLESS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TLS : $tls\n"
env_msg+="Port None TLS : $none\n"
env_msg+="ID : <code>$uuid</code>\n"
env_msg+="Encryption : none\n"
env_msg+="Network : websocket/ws\n"
env_msg+="Path : /vlessws\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TLS : \n"
env_msg+="<code>$vlesslink1</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link None TLS : \n"
env_msg+="<code>$vlesslink2</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 60Days VLESS | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart $raycheck > /dev/null 2>&1
return 0
fi
}

add_vless_trial() {
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE TRIAL VLess 👤\n\nHow many hours should it last ? EX: 1:" \
            --reply_markup "$(ShellBot.ForceReply)"
    elif [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]]; then
            ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "👤 CREATE TRIAL VLess 👤\n\nHow many hours should it last ? EX: 1:" \
                --reply_markup "$(ShellBot.ForceReply)"       
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

func_add_vless_trial() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderVLESS ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Disable Order VLESS" \
                    --parse_mode html
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                   --text "Func Error Do Nothing" \
                   --reply_markup "$(ShellBot.ForceReply)"
            return 0
    }
}
mkdir -p /etc/.maAsiss/info-user-vless
    userna=$(echo Trial`</dev/urandom tr -dc A-Z0-9 | head -c4`)
    t_time=$1
    domain=$(cat /etc/$raycheck/domain)
    tls="$(cat /root/log-install.txt | grep -w "Vless TLS" | cut -d: -f2|sed 's/ //g')"
    none="$(cat /root/log-install.txt | grep -w "Vless None TLS" | cut -d: -f2|sed 's/ //g')"

    exp=`date -d "2 days" +"%Y-%m-%d"`
    tuserdate=$(date '+%C%y/%m/%d' -d " +2 days")
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
       mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold
    }
    [[ -z $t_time ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e "⛔ error try again")" \
            --parse_mode html
        return 0
        _erro='1'
    }
    
echo "$userna:$exp" >/etc/.maAsiss/info-user-vless/$userna
uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vlessWSTLS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json
sed -i '/#vlessWS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json
  
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    echo "$userna:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/user_vless/$userna
    echo "$userna:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna
}
dir_teste="/etc/.maAsiss/db_reseller/${message_from_id}/user_vless/$userna"
dir_teste2="/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna"
dates=`date`
cat <<-EOF >/etc/.maAsiss/$userna.sh
#!/bin/bash
# USER TRIAL VLESS by ${message_from_id} $dates
exp=\$(grep -wE "^#& $userna" "/etc/$raycheck/config.json" | cut -d ' ' -f 3 | sort | uniq)
sed -i "/^#& $userna $exp/,/^},{/d" /etc/$raycheck/config.json
systemctl restart $raycheck > /dev/null 2>&1
rm /etc/.maAsiss/db_reseller/${message_from_id}/user_vless/$userna
rm /etc/.maAsiss/info-user-vless/$userna
[[ -e $dir_teste ]] && rm $dir_teste
[[ -e $dir_teste2 ]] && rm $dir_teste2
rm -f /etc/.maAsiss/$userna
rm -f /etc/.maAsiss/$userna.sh
EOF
chmod +x /etc/.maAsiss/$userna.sh
echo "/etc/.maAsiss/$userna.sh" | at now + $t_time hour >/dev/null 2>&1
[[ "$t_time" == '1' ]] && hrs="hour" || hrs="hours"          

vlesslink1="vless://${uuid}@${domain}:$tls?path=/vlessws%26security=tls%26encryption=none%26type=ws#${userna}"
vlesslink2="vless://${uuid}@${domain}:$none?path=/vlessws%26encryption=none%26type=ws#${userna}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>        🔸 VLESS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $t_time $hrs ⏳ \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TLS : $tls\n"
env_msg+="Port None TLS : $none\n"
env_msg+="ID : <code>$uuid</code>\n"
env_msg+="Encryption : none\n"
env_msg+="Network : websocket/ws\n"
env_msg+="Path : /vlessws\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TLS : \n"
env_msg+="<code>$vlesslink1</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link None TLS : \n"
env_msg+="<code>$vlesslink2</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart $raycheck > /dev/null 2>&1
return 0

}

list_member_vless() {
   if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
      _result=$(grep -E "^#& " "/etc/$raycheck/config.json" | cut -d ' ' -f 2 | column -t | sort | uniq | wc -l)
      _results=$(grep -E "^#& " "/etc/$raycheck/config.json" | cut -d ' ' -f 2 | column -t | sort | uniq )
   elif [[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]]; then
      _result=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_vless | wc -l)
      _results=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_vless )
   else
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ ACCESS DENIED ⛔" \
                --parse_mode html
      return 0
   fi
   if [ "$_result" = "0" ]; then
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ YOU DONT HAVE ANY USER YET ⛔" \
                --parse_mode html
      return 0
   else
      ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
      ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
         --text "━━━━━━━━━━━━━━━━━━━━━\n 🟢 VLESS MEMBER LIST 🟢 \n━━━━━━━━━━━━━━━━━━━━━\n\n$_results\n\n━━━━━━━━━━━━━━━━━━━━━\n" \
         --parse_mode html
      return 0
   fi
}

del_vless() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🗑 REMOVE USER VLess 🗑\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_del_vless() {
    userna=$1
    [[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
        exp=$(grep -wE "^#& $userna" "/etc/$raycheck/config.json" | cut -d ' ' -f 3 | sort | uniq)
        sed -i "/^#& $userna $exp/,/^},{/d" /etc/$raycheck/config.json
        datata=$(find /etc/.maAsiss/ -name $userna)
        for accc in "${datata[@]}"
        do
        rm $accc
        done
        systemctl restart $raycheck > /dev/null 2>&1
    } || {
        [[ ! -e /etc/.maAsiss/db_reseller/${message_from_id}/user_vless/$userna ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "⛔ THE USER DOES NOT EXIST ⛔")" \
                --parse_mode html
            _erro='1'      
            ShellBot.sendMessage --chat_id ${callack_query_message_chat_id[$id]} \
                 --text "Func Error Do Nothing" \
                 --reply_markup "$(ShellBot.ForceReply)"
            return 0
        }
        exp=$(grep -wE "^#& $userna" "/etc/$raycheck/config.json" | cut -d ' ' -f 3 | sort | uniq)
        sed -i "/^#& $userna $exp/,/^},{/d" /etc/$raycheck/config.json
        rm /etc/.maAsiss/db_reseller/${message_from_id}/user_vless/$userna
        rm /etc/.maAsiss/info-user-vless/$userna
        systemctl restart $raycheck > /dev/null 2>&1
    }
}

check_login_vless(){
if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
echo -n > /tmp/other.txt
data=( `cat /etc/$raycheck/config.json | grep '^#&' | cut -d ' ' -f 2 | sort | uniq`);

echo -e "━━━━━━━━━━━━━━━━━━━━━" > /tmp/vmess-login
echo -e "         🟢 VLess User Login 🟢  " >> /tmp/vmess-login
echo -e "━━━━━━━━━━━━━━━━━━━━━" >> /tmp/vmess-login

for akun in "${data[@]}"
do
if [[ -z "$akun" ]]; then
akun="tidakada"
fi

echo -n > /tmp/ipvmess.txt
data2=( `netstat -anp | grep ESTABLISHED | grep tcp6 | grep $raycheck | awk '{print $5}' | cut -d: -f1 | sort | uniq`);
for ip in "${data2[@]}"
do

jum=$(cat /var/log/$raycheck/access.log | grep -w $akun | awk '{print $3}' | cut -d: -f1 | grep -w $ip | sort | uniq)
if [[ "$jum" = "$ip" ]]; then
echo "$jum" >> /tmp/ipvmess.txt
else
echo "$ip" >> /tmp/other.txt
fi
jum2=$(cat /tmp/ipvmess.txt)
sed -i "/$jum2/d" /tmp/other.txt > /dev/null 2>&1
done

jum=$(cat /tmp/ipvmess.txt)
if [[ -z "$jum" ]]; then
echo > /dev/null
else
jum2=$(cat /tmp/ipvmess.txt | nl)
echo "user : $akun" >> /tmp/vmess-login
echo "$jum2" >> /tmp/vmess-login
echo -e "━━━━━━━━━━━━━━━━━━━━━" >> /tmp/vmess-login
fi
rm -rf /tmp/ipvmess.txt
done

oth=$(cat /tmp/other.txt | sort | uniq | nl)
echo "other" >> /tmp/vmess-login
echo "$oth" >> /tmp/vmess-login
echo -e "━━━━━━━━━━━━━━━━━━━━━" >> /tmp/vmess-login
rm -rf /tmp/other.txt
msg=$(cat /tmp/vmess-login)
cekk=$(cat /tmp/vmess-login | wc -l)
if [ "$cekk" = "0" ] || [ "$cekk" = "6" ]; then
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ NO USERS ONLINE ⛔" \
                --parse_mode html
rm /tmp/vmess-login
return 0
else
ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
         --text "$msg" \
         --parse_mode html
rm /tmp/vmess-login
return 0
fi
else
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ ACCESS DENIED ⛔" \
                --parse_mode html
return 0
fi
}

res_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menuzzz')" \
        return 0
    }
}

unset menu_vless
menu_vless=''
ShellBot.InlineKeyboardButton --button 'menu_vless' --line 1 --text 'Add VLess' --callback_data '_add_vless'
ShellBot.InlineKeyboardButton --button 'menu_vless' --line 2 --text 'Delete VLess' --callback_data '_delete_vless'
ShellBot.InlineKeyboardButton --button 'menu_vless' --line 3 --text 'Create Trial VLess' --callback_data '_trial_vless'
ShellBot.InlineKeyboardButton --button 'menu_vless' --line 4 --text 'List Member VLess' --callback_data '_member_vless'
ShellBot.InlineKeyboardButton --button 'menu_vless' --line 5 --text 'Check User Login VLess' --callback_data '_login_vless'
ShellBot.InlineKeyboardButton --button 'menu_vless' --line 6 --text '🔙 Back 🔙' --callback_data '_gobackvless'
ShellBot.regHandleFunction --function add_vless --callback_data _add_vless
ShellBot.regHandleFunction --function del_vless --callback_data _delete_vless
ShellBot.regHandleFunction --function add_vless_trial --callback_data _trial_vless
ShellBot.regHandleFunction --function list_member_vless --callback_data _member_vless
ShellBot.regHandleFunction --function check_login_vless --callback_data _login_vless
ShellBot.regHandleFunction --function admin_service_see --callback_data _gobackvless
unset keyboardvless
keyboardvless="$(ShellBot.InlineKeyboardMarkup -b 'menu_vless')"

unset res_menu_vless
res_menu_vless=''
ShellBot.InlineKeyboardButton --button 'res_menu_vless' --line 1 --text '➕ Add VLess ➕' --callback_data '_res_add_vless'
ShellBot.InlineKeyboardButton --button 'res_menu_vless' --line 3 --text '⏳ Create Trial VLess ⏳' --callback_data '_res_trial_vless'
ShellBot.InlineKeyboardButton --button 'res_menu_vless' --line 4 --text '🟢 List Member VLess 🟢' --callback_data '_res_member_vless'
ShellBot.InlineKeyboardButton --button 'res_menu_vless' --line 5 --text '🔙 Back 🔙' --callback_data '_res_gobackvless'
ShellBot.regHandleFunction --function add_vless --callback_data _res_add_vless
ShellBot.regHandleFunction --function add_vless_trial --callback_data _res_trial_vless
ShellBot.regHandleFunction --function list_member_vless --callback_data _res_member_vless
ShellBot.regHandleFunction --function menu_reserv --callback_data _res_gobackvless
unset keyboardvlessres
keyboardvlessres="$(ShellBot.InlineKeyboardMarkup -b 'res_menu_vless')"

#====== ALL ABOUT WIREGUARD =======#

res_wg_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'res_menu_wg')"
        return 0
    }
}

wg_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_wg')"
        return 0
    }
}

add_wg() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE USER WireGuard 👤\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_add_wg() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderWG ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Disable Order Wireguard" \
                --parse_mode html
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
               --text "Func Error Do Nothing" \
               --reply_markup "$(ShellBot.ForceReply)"
        return 0
    }
}

source /etc/wireguard/params
file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
data=$(sed -n '2 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)
        
domain=$(cat /etc/$raycheck/domain)

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-wg
echo "$userna:$data" >/etc/.maAsiss/info-user-wg/$userna

#echo "IPv4 Detected"
ENDPOINT="$domain:$SERVER_PORT"
WG_CONFIG="/etc/wireguard/wg0.conf"
LASTIP=$( grep "/32" $WG_CONFIG | tail -n1 | awk '{print $3}' | cut -d "/" -f 1 | cut -d "." -f 4 )
if [[ "$LASTIP" = "" ]]; then
CLIENT_ADDRESS="10.66.66.2"
else
CLIENT_ADDRESS="10.66.66.$((LASTIP+1))"
fi

# Adguard DNS by default
CLIENT_DNS_1="176.103.130.130"

CLIENT_DNS_2="176.103.130.131"
MYIP2=$(wget -qO- ipv4.icanhazip.com);

# Generate key pair for the client
CLIENT_PRIV_KEY=$(wg genkey)
CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)
CLIENT_PRE_SHARED_KEY=$(wg genpsk)

# Create client file and add the server as a peer
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY
Address = $CLIENT_ADDRESS/24
DNS = $CLIENT_DNS_1,$CLIENT_DNS_2

[Peer]
PublicKey = $SERVER_PUB_KEY
PresharedKey = $CLIENT_PRE_SHARED_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0" >>"$HOME/$SERVER_WG_NIC-client-$userna.conf"

# Add the client as a peer to the server
echo -e "### Client $userna $exp
[Peer]
PublicKey = $CLIENT_PUB_KEY
PresharedKey = $CLIENT_PRE_SHARED_KEY
AllowedIPs = $CLIENT_ADDRESS/32" >>"/etc/wireguard/$SERVER_WG_NIC.conf"
cp $HOME/$SERVER_WG_NIC-client-$userna.conf /home/vps/public_html/$userna.conf

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>   🔸 WIREGUARD ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="User : $userna\n"
env_msg+="Expired On : $data 📆 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Wireguard	: http://$domain:81/$userna.conf\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart "wg-quick@$SERVER_WG_NIC" > /dev/null 2>&1
rm -f /root/wg0-client-$userna.conf
return 0
}

pricewg=$(grep -w "Price Wireguard" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
if [ "$saldores" -lt "$pricewg" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-wg
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_wg
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_wg/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-wg/$userna
_CurrSal=$(echo $saldores - $pricewg | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active


#echo "IPv4 Detected"
ENDPOINT="$domain:$SERVER_PORT"
WG_CONFIG="/etc/wireguard/wg0.conf"
LASTIP=$( grep "/32" $WG_CONFIG | tail -n1 | awk '{print $3}' | cut -d "/" -f 1 | cut -d "." -f 4 )
if [[ "$LASTIP" = "" ]]; then
CLIENT_ADDRESS="10.66.66.2"
else
CLIENT_ADDRESS="10.66.66.$((LASTIP+1))"
fi

# Adguard DNS by default
CLIENT_DNS_1="176.103.130.130"

CLIENT_DNS_2="176.103.130.131"
MYIP2=$(wget -qO- ipv4.icanhazip.com);

# Generate key pair for the client
CLIENT_PRIV_KEY=$(wg genkey)
CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)
CLIENT_PRE_SHARED_KEY=$(wg genpsk)

# Create client file and add the server as a peer
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY
Address = $CLIENT_ADDRESS/24
DNS = $CLIENT_DNS_1,$CLIENT_DNS_2

[Peer]
PublicKey = $SERVER_PUB_KEY
PresharedKey = $CLIENT_PRE_SHARED_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0" >>"$HOME/$SERVER_WG_NIC-client-$userna.conf"

# Add the client as a peer to the server
echo -e "### Client $userna $exp
[Peer]
PublicKey = $CLIENT_PUB_KEY
PresharedKey = $CLIENT_PRE_SHARED_KEY
AllowedIPs = $CLIENT_ADDRESS/32" >>"/etc/wireguard/$SERVER_WG_NIC.conf"
cp $HOME/$SERVER_WG_NIC-client-$userna.conf /home/vps/public_html/$userna.conf

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>   🔸 WIREGUARD ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="User : $userna\n"
env_msg+="Expired On : $data 📆 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Wireguard	: http://$domain:81/$userna.conf\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 30Days WIREGUARD | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart "wg-quick@$SERVER_WG_NIC" > /dev/null 2>&1
rm -f /root/wg0-client-$userna.conf
return 0
fi
}

func_add_wg2() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderWG ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Disable Order Wireguard" \
                --parse_mode html
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
               --text "Func Error Do Nothing" \
               --reply_markup "$(ShellBot.ForceReply)"
        return 0
    }
}
source /etc/wireguard/params
file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
data=$(sed -n '2 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)
        
domain=$(cat /etc/$raycheck/domain)

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-wg
echo "$userna:$data" >/etc/.maAsiss/info-user-wg/$userna

#echo "IPv4 Detected"
ENDPOINT="$domain:$SERVER_PORT"
WG_CONFIG="/etc/wireguard/wg0.conf"
LASTIP=$( grep "/32" $WG_CONFIG | tail -n1 | awk '{print $3}' | cut -d "/" -f 1 | cut -d "." -f 4 )
if [[ "$LASTIP" = "" ]]; then
CLIENT_ADDRESS="10.66.66.2"
else
CLIENT_ADDRESS="10.66.66.$((LASTIP+1))"
fi

# Adguard DNS by default
CLIENT_DNS_1="176.103.130.130"

CLIENT_DNS_2="176.103.130.131"
MYIP2=$(wget -qO- ipv4.icanhazip.com);

# Generate key pair for the client
CLIENT_PRIV_KEY=$(wg genkey)
CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)
CLIENT_PRE_SHARED_KEY=$(wg genpsk)

# Create client file and add the server as a peer
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY
Address = $CLIENT_ADDRESS/24
DNS = $CLIENT_DNS_1,$CLIENT_DNS_2

[Peer]
PublicKey = $SERVER_PUB_KEY
PresharedKey = $CLIENT_PRE_SHARED_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0" >>"$HOME/$SERVER_WG_NIC-client-$userna.conf"

# Add the client as a peer to the server
echo -e "### Client $userna $exp
[Peer]
PublicKey = $CLIENT_PUB_KEY
PresharedKey = $CLIENT_PRE_SHARED_KEY
AllowedIPs = $CLIENT_ADDRESS/32" >>"/etc/wireguard/$SERVER_WG_NIC.conf"
cp $HOME/$SERVER_WG_NIC-client-$userna.conf /home/vps/public_html/$userna.conf

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>   🔸 WIREGUARD ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="User : $userna\n"
env_msg+="Expired On : $data 📆 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Wireguard	: http://$domain:81/$userna.conf\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart "wg-quick@$SERVER_WG_NIC" > /dev/null 2>&1
rm -f /root/wg0-client-$userna.conf
return 0
}

pricewg=$(grep -w "Price Wireguard" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
urday=$(echo $pricewg * 2 | bc)
if [ "$saldores" -lt "$urday" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-wg
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_wg
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_wg/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-wg/$userna
_CurrSal=$(echo $saldores - $urday | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active


#echo "IPv4 Detected"
ENDPOINT="$domain:$SERVER_PORT"
WG_CONFIG="/etc/wireguard/wg0.conf"
LASTIP=$( grep "/32" $WG_CONFIG | tail -n1 | awk '{print $3}' | cut -d "/" -f 1 | cut -d "." -f 4 )
if [[ "$LASTIP" = "" ]]; then
CLIENT_ADDRESS="10.66.66.2"
else
CLIENT_ADDRESS="10.66.66.$((LASTIP+1))"
fi

# Adguard DNS by default
CLIENT_DNS_1="176.103.130.130"

CLIENT_DNS_2="176.103.130.131"
MYIP2=$(wget -qO- ipv4.icanhazip.com);

# Generate key pair for the client
CLIENT_PRIV_KEY=$(wg genkey)
CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)
CLIENT_PRE_SHARED_KEY=$(wg genpsk)

# Create client file and add the server as a peer
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY
Address = $CLIENT_ADDRESS/24
DNS = $CLIENT_DNS_1,$CLIENT_DNS_2

[Peer]
PublicKey = $SERVER_PUB_KEY
PresharedKey = $CLIENT_PRE_SHARED_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0" >>"$HOME/$SERVER_WG_NIC-client-$userna.conf"

# Add the client as a peer to the server
echo -e "### Client $userna $exp
[Peer]
PublicKey = $CLIENT_PUB_KEY
PresharedKey = $CLIENT_PRE_SHARED_KEY
AllowedIPs = $CLIENT_ADDRESS/32" >>"/etc/wireguard/$SERVER_WG_NIC.conf"
cp $HOME/$SERVER_WG_NIC-client-$userna.conf /home/vps/public_html/$userna.conf

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>   🔸 WIREGUARD ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="User : $userna\n"
env_msg+="Expired On : $data 📆 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Wireguard	: http://$domain:81/$userna.conf\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 60Days WIREGUARD | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart "wg-quick@$SERVER_WG_NIC" > /dev/null 2>&1
rm -f /root/wg0-client-$userna.conf
return 0
fi
}

del_wg() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🗑 REMOVE USER WireGuard 🗑\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}
	
func_del_wg() {
source /etc/wireguard/params
    userna=$1
    if [[ "${message_from_id[$id]}" = "$Admin_ID" ]]; then
        exp=$(grep -wE "^### Client" "/etc/wireguard/$SERVER_WG_NIC.conf" | cut -d ' ' -f 4 | sort | uniq)
        sed -i "/^### Client $userna $exp/,/^AllowedIPs/d" /etc/wireguard/wg0.conf
        rm -f "/home/vps/public_html/$userna.conf"
        datata=$(find /etc/.maAsiss/ -name $userna)
        for accc in "${datata[@]}"
        do
        rm $accc
        done
        systemctl restart wg-quick@wg0 > /dev/null 2>&1
    elif [[ "${message_from_id[$id]}" != "$Admin_ID" ]]; then
        [[ ! -e /etc/.maAsiss/db_reseller/${message_from_id}/user_wg/$userna ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "⛔ THE USER DOES NOT EXIST ⛔")" \
                --parse_mode html
            _erro='1'      
            ShellBot.sendMessage --chat_id ${callack_query_message_chat_id[$id]} \
                 --text "Func Error Do Nothing" \
                 --reply_markup "$(ShellBot.ForceReply)"
            return 0
        }
        exp=$(grep -wE "^### Client" "/etc/wireguard/$SERVER_WG_NIC.conf" | cut -d ' ' -f 4 | sort | uniq)
        sed -i "/^### Client $userna $exp/,/^AllowedIPs/d" /etc/wireguard/wg0.conf
        rm -f "/home/vps/public_html/$userna.conf"
        rm /etc/.maAsiss/db_reseller/${message_from_id}/user_wg/$userna
        rm /etc/.maAsiss/info-user-wg/$userna
        systemctl restart wg-quick@wg0 > /dev/null 2>&1
    fi
}

add_wg_trial() {
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE TRIAL WireGuard 👤\n\nHow many hours should it last ? EX: 1:" \
            --reply_markup "$(ShellBot.ForceReply)"
    elif [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]]; then
            ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "👤 CREATE TRIAL WireGuard 👤\n\nHow many hours should it last ? EX: 1:" \
                --reply_markup "$(ShellBot.ForceReply)"       
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

func_add_wg_trial() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderWG ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Disable Order Wireguard" \
                --parse_mode html
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
               --text "Func Error Do Nothing" \
               --reply_markup "$(ShellBot.ForceReply)"
        return 0
    }
}
mkdir -p /etc/.maAsiss/info-user-wg
    source /etc/wireguard/params
    userna=$(echo Trial`</dev/urandom tr -dc A-Z0-9 | head -c4`)
    t_time=$1
    domain=$(cat /etc/$raycheck/domain)
    
    exp=`date -d "2 days" +"%Y-%m-%d"`
    tuserdate=$(date '+%C%y/%m/%d' -d " +2 days")
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
       mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold
    }
    [[ -z $t_time ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e "⛔ error try again")" \
            --parse_mode html
        return 0
        _erro='1'
    }
    
echo "$userna:$exp" >/etc/.maAsiss/info-user-wg/$userna

ENDPOINT="$domain:$SERVER_PORT"
WG_CONFIG="/etc/wireguard/wg0.conf"
LASTIP=$( grep "/32" $WG_CONFIG | tail -n1 | awk '{print $3}' | cut -d "/" -f 1 | cut -d "." -f 4 )
if [[ "$LASTIP" = "" ]]; then
CLIENT_ADDRESS="10.66.66.2"
else
CLIENT_ADDRESS="10.66.66.$((LASTIP+1))"
fi

# Adguard DNS by default
CLIENT_DNS_1="176.103.130.130"

CLIENT_DNS_2="176.103.130.131"
MYIP2=$(wget -qO- ipv4.icanhazip.com);

# Generate key pair for the client
CLIENT_PRIV_KEY=$(wg genkey)
CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)
CLIENT_PRE_SHARED_KEY=$(wg genpsk)

# Create client file and add the server as a peer
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY
Address = $CLIENT_ADDRESS/24
DNS = $CLIENT_DNS_1,$CLIENT_DNS_2

[Peer]
PublicKey = $SERVER_PUB_KEY
PresharedKey = $CLIENT_PRE_SHARED_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0" >>"$HOME/$SERVER_WG_NIC-client-$userna.conf"

# Add the client as a peer to the server
echo -e "### Client $userna $exp
[Peer]
PublicKey = $CLIENT_PUB_KEY
PresharedKey = $CLIENT_PRE_SHARED_KEY
AllowedIPs = $CLIENT_ADDRESS/32" >>"/etc/wireguard/$SERVER_WG_NIC.conf"
cp $HOME/$SERVER_WG_NIC-client-$userna.conf /home/vps/public_html/$userna.conf
  
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    echo "$userna:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/user_wg/$userna
    echo "$userna:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna
}
dir_teste="/etc/.maAsiss/db_reseller/${message_from_id}/user_wg/$userna"
dir_teste2="/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna"
dates=`date`
cat <<-EOF >/etc/.maAsiss/$userna.sh
#!/bin/bash
# USER TRIAL WG by ${message_from_id} $dates
exp=\$(grep -wE "^### Client" "/etc/wireguard/$SERVER_WG_NIC.conf" | cut -d ' ' -f 4 | sort | uniq)
sed -i "/^### Client $userna $exp/,/^AllowedIPs/d" /etc/wireguard/wg0.conf
rm -f "/home/vps/public_html/$userna.conf"
systemctl restart "wg-quick@wg0" > /dev/null 2>&1
rm -f /etc/.maAsiss/db_reseller/${message_from_id}/user_wg/$userna
rm -f /etc/.maAsiss/info-user-wg/$userna
[[ -e $dir_teste ]] && rm $dir_teste
[[ -e $dir_teste2 ]] && rm $dir_teste2
rm -f /etc/.maAsiss/$userna
rm -f /etc/.maAsiss/$userna.sh
EOF

chmod +x /etc/.maAsiss/$userna.sh
echo "/etc/.maAsiss/$userna.sh" | at now + $t_time hour >/dev/null 2>&1
[[ "$t_time" == '1' ]] && hrs="hour" || hrs="hours"          

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>   🔸 WIREGUARD ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="User : $userna\n"
env_msg+="Expired On : $t_time $hrs ⌛\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Wireguard	: http://$domain:81/$userna.conf\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
rm -f /root/wg0-client-$userna.conf
systemctl restart "wg-quick@$SERVER_WG_NIC" > /dev/null 2>&1
return 0
}

list_member_wg() {
   if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
      _result=$(grep -E "^### Client " "/etc/wireguard/wg0.conf" | cut -d ' ' -f 3 | column -t | sort | uniq | wc -l)
      _results=$(grep -E "^### Client " "/etc/wireguard/wg0.conf" | cut -d ' ' -f 3 | column -t | sort | uniq )
   elif [[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]]; then
      _result=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_wg | wc -l)
      _results=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_wg )
   else
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ ACCESS DENIED ⛔" \
                --parse_mode html
      return 0
   fi
   if [ "$_result" = "0" ]; then
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ YOU DONT HAVE ANY USER YET ⛔" \
                --parse_mode html
      return 0
   else
      ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
      ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
         --text "━━━━━━━━━━━━━━━━━━━━━\n 🟢 WireGuard Member List 🟢 \n━━━━━━━━━━━━━━━━━━━━━\n\n$_results\n\n━━━━━━━━━━━━━━━━━━━━━\n" \
         --parse_mode html
      return 0
   fi
}

unset menu_wg
menu_wg=''
ShellBot.InlineKeyboardButton --button 'menu_wg' --line 1 --text 'Add WireGuard' --callback_data '_add_wg'
ShellBot.InlineKeyboardButton --button 'menu_wg' --line 2 --text 'Delete WireGuard' --callback_data '_delete_wg'
ShellBot.InlineKeyboardButton --button 'menu_wg' --line 3 --text 'Create Trial WG' --callback_data '_trial_wg'
ShellBot.InlineKeyboardButton --button 'menu_wg' --line 4 --text 'List Member WG' --callback_data '_member_wg'
# ShellBot.InlineKeyboardButton --button 'menu_wg' --line 5 --text 'Check User Login WG' --callback_data '_login_wg'
ShellBot.InlineKeyboardButton --button 'menu_wg' --line 6 --text '🔙 Back 🔙' --callback_data '_gobackwg'
ShellBot.regHandleFunction --function add_wg --callback_data _add_wg
ShellBot.regHandleFunction --function del_wg --callback_data _delete_wg
ShellBot.regHandleFunction --function add_wg_trial --callback_data _trial_wg
ShellBot.regHandleFunction --function list_member_wg --callback_data _member_wg
# ShellBot.regHandleFunction --function check_login_wg --callback_data _login_wg
ShellBot.regHandleFunction --function admin_service_see --callback_data _gobackwg
unset keyboardwg
keyboardwg="$(ShellBot.InlineKeyboardMarkup -b 'menu_wg')"

unset res_menu_wg
res_menu_wg=''
ShellBot.InlineKeyboardButton --button 'res_menu_wg' --line 1 --text '➕ Add WireGuard ➕' --callback_data '_res_add_wg'
ShellBot.InlineKeyboardButton --button 'res_menu_wg' --line 3 --text '⏳ Create Trial WG ⏳' --callback_data '_res_trial_wg'
ShellBot.InlineKeyboardButton --button 'res_menu_wg' --line 4 --text '🟢 List Member WG 🟢' --callback_data '_res_member_wg'
ShellBot.InlineKeyboardButton --button 'res_menu_wg' --line 5 --text '🔙 Back 🔙' --callback_data '_res_gobackwg'
ShellBot.regHandleFunction --function add_wg --callback_data _res_add_wg
ShellBot.regHandleFunction --function add_wg_trial --callback_data _res_trial_wg
ShellBot.regHandleFunction --function list_member_wg --callback_data _res_member_wg
ShellBot.regHandleFunction --function menu_reserv --callback_data _res_gobackwg
unset keyboardwgres
keyboardwgres="$(ShellBot.InlineKeyboardMarkup -b 'res_menu_wg')"

#====== ALL ABOUT ShadowSocks =======#

res_ss_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'res_menu_ss')"
        return 0
    }
}

ss_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_ss')"
        return 0
    }
}

add_ss() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE USER ShadowSocks 👤\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_add_ss() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderSS ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Disable Order Shadowsocks" \
                --parse_mode html
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
               --text "Func Error Do Nothing" \
               --reply_markup "$(ShellBot.ForceReply)"
        return 0
    }
}

file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
data=$(sed -n '2 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)
        
domain=$(cat /etc/$raycheck/domain)
lastport1=$(grep "port_tls" /etc/shadowsocks-libev/akun.conf | tail -n1 | awk '{print $2}')
lastport2=$(grep "port_http" /etc/shadowsocks-libev/akun.conf | tail -n1 | awk '{print $2}')
if [[ $lastport1 == '' ]]; then
tls=2443
else
tls="$((lastport1+1))"
fi
if [[ $lastport2 == '' ]]; then
http=3443
else
http="$((lastport2+1))"
fi

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-ss
echo "$userna:$data" >/etc/.maAsiss/info-user-ss/$userna

cat > /etc/shadowsocks-libev/$userna-tls.json<<END
{   
    "server":"0.0.0.0",
    "server_port":$tls,
    "password":"$userna",
    "timeout":60,
    "method":"aes-256-cfb",
    "fast_open":true,
    "no_delay":true,
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=tls"
}
END
cat > /etc/shadowsocks-libev/$userna-http.json <<-END
{
    "server":"0.0.0.0",
    "server_port":$http,
    "password":"$userna",
    "timeout":60,
    "method":"aes-256-cfb",
    "fast_open":true,
    "no_delay":true,
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=http"
}
END
chmod +x /etc/shadowsocks-libev/$userna-tls.json
chmod +x /etc/shadowsocks-libev/$userna-http.json

systemctl start shadowsocks-libev-server@$userna-tls.service > /dev/null 2>&1
systemctl enable shadowsocks-libev-server@$userna-tls.service > /dev/null 2>&1
systemctl start shadowsocks-libev-server@$userna-http.service > /dev/null 2>&1
systemctl enable shadowsocks-libev-server@$userna-http.service > /dev/null 2>&1
tmp1=$(echo -n "aes-256-cfb:${userna}@${domain}:$tls" | base64 -w0)
tmp2=$(echo -n "aes-256-cfb:${userna}@${domain}:$http" | base64 -w0)
linkss1="ss://${tmp1}?plugin=obfs-local;obfs=tls;obfs-host=bing.com"
linkss2="ss://${tmp2}?plugin=obfs-local;obfs=http;obfs-host=bing.com"
echo -e "### $userna $exp
port_tls $tls
port_http $http">>"/etc/shadowsocks-libev/akun.conf"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>      🔸 SS OBFS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Password : $userna\n"
env_msg+="Expired On : $data \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port OBFS TLS : $tls\n"
env_msg+="Port OBFS HTTP : $http\n"
env_msg+="Encrypt Method : aes-256-cfb\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link OBFS TLS : \n"
env_msg+="<code>$linkss1</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link OBFS HTTP : \n"
env_msg+="<code>$linkss2</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
return 0
}

pricess=$(grep -w "Price Shadowsocks :" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
if [ "$saldores" -lt "$pricess" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-ss
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_ss
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_ss/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-ss/$userna
_CurrSal=$(echo $saldores - $pricess | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

cat > /etc/shadowsocks-libev/$userna-tls.json<<END
{   
    "server":"0.0.0.0",
    "server_port":$tls,
    "password":"$userna",
    "timeout":60,
    "method":"aes-256-cfb",
    "fast_open":true,
    "no_delay":true,
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=tls"
}
END
cat > /etc/shadowsocks-libev/$userna-http.json <<-END
{
    "server":"0.0.0.0",
    "server_port":$http,
    "password":"$userna",
    "timeout":60,
    "method":"aes-256-cfb",
    "fast_open":true,
    "no_delay":true,
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=http"
}
END
chmod +x /etc/shadowsocks-libev/$userna-tls.json
chmod +x /etc/shadowsocks-libev/$userna-http.json

systemctl start shadowsocks-libev-server@$userna-tls.service > /dev/null 2>&1
systemctl enable shadowsocks-libev-server@$userna-tls.service > /dev/null 2>&1
systemctl start shadowsocks-libev-server@$userna-http.service > /dev/null 2>&1
systemctl enable shadowsocks-libev-server@$userna-http.service > /dev/null 2>&1
tmp1=$(echo -n "aes-256-cfb:${userna}@${domain}:$tls" | base64 -w0)
tmp2=$(echo -n "aes-256-cfb:${userna}@${domain}:$http" | base64 -w0)
linkss1="ss://${tmp1}?plugin=obfs-local;obfs=tls;obfs-host=bing.com"
linkss2="ss://${tmp2}?plugin=obfs-local;obfs=http;obfs-host=bing.com"
echo -e "### $userna $exp
port_tls $tls
port_http $http">>"/etc/shadowsocks-libev/akun.conf"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>      🔸 SS OBFS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Password : $userna\n"
env_msg+="Expired On : $data \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port OBFS TLS : $tls\n"
env_msg+="Port OBFS HTTP : $http\n"
env_msg+="Encrypt Method : aes-256-cfb\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link OBFS TLS : \n"
env_msg+="<code>$linkss1</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link OBFS HTTP : \n"
env_msg+="<code>$linkss2</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 30Days SHADOWSOCKS | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
return 0
fi
}

func_add_ss2() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderSS ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Disable Order Shadowsocks" \
                --parse_mode html
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
               --text "Func Error Do Nothing" \
               --reply_markup "$(ShellBot.ForceReply)"
        return 0
    }
}
file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
data=$(sed -n '2 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)
        
domain=$(cat /etc/$raycheck/domain)
lastport1=$(grep "port_tls" /etc/shadowsocks-libev/akun.conf | tail -n1 | awk '{print $2}')
lastport2=$(grep "port_http" /etc/shadowsocks-libev/akun.conf | tail -n1 | awk '{print $2}')
if [[ $lastport1 == '' ]]; then
tls=2443
else
tls="$((lastport1+1))"
fi
if [[ $lastport2 == '' ]]; then
http=3443
else
http="$((lastport2+1))"
fi

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-ss
echo "$userna:$data" >/etc/.maAsiss/info-user-ss/$userna

cat > /etc/shadowsocks-libev/$userna-tls.json<<END
{   
    "server":"0.0.0.0",
    "server_port":$tls,
    "password":"$userna",
    "timeout":60,
    "method":"aes-256-cfb",
    "fast_open":true,
    "no_delay":true,
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=tls"
}
END
cat > /etc/shadowsocks-libev/$userna-http.json <<-END
{
    "server":"0.0.0.0",
    "server_port":$http,
    "password":"$userna",
    "timeout":60,
    "method":"aes-256-cfb",
    "fast_open":true,
    "no_delay":true,
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=http"
}
END
chmod +x /etc/shadowsocks-libev/$userna-tls.json
chmod +x /etc/shadowsocks-libev/$userna-http.json

systemctl start shadowsocks-libev-server@$userna-tls.service > /dev/null 2>&1
systemctl enable shadowsocks-libev-server@$userna-tls.service > /dev/null 2>&1
systemctl start shadowsocks-libev-server@$userna-http.service > /dev/null 2>&1
systemctl enable shadowsocks-libev-server@$userna-http.service > /dev/null 2>&1
tmp1=$(echo -n "aes-256-cfb:${userna}@${domain}:$tls" | base64 -w0)
tmp2=$(echo -n "aes-256-cfb:${userna}@${domain}:$http" | base64 -w0)
linkss1="ss://${tmp1}?plugin=obfs-local;obfs=tls;obfs-host=bing.com"
linkss2="ss://${tmp2}?plugin=obfs-local;obfs=http;obfs-host=bing.com"
echo -e "### $userna $exp
port_tls $tls
port_http $http">>"/etc/shadowsocks-libev/akun.conf"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>      🔸 SS OBFS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Password : $userna\n"
env_msg+="Expired On : $data \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port OBFS TLS : $tls\n"
env_msg+="Port OBFS HTTP : $http\n"
env_msg+="Encrypt Method : aes-256-cfb\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link OBFS TLS : \n"
env_msg+="<code>$linkss1</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link OBFS HTTP : \n"
env_msg+="<code>$linkss2</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
return 0
}

pricess=$(grep -w "Price Shadowsocks :" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
urday=$(echo $pricess * 2 | bc)
if [ "$saldores" -lt "$urday" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-ss
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_ss
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_ss/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-ss/$userna
_CurrSal=$(echo $saldores - $urday | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

cat > /etc/shadowsocks-libev/$userna-tls.json<<END
{   
    "server":"0.0.0.0",
    "server_port":$tls,
    "password":"$userna",
    "timeout":60,
    "method":"aes-256-cfb",
    "fast_open":true,
    "no_delay":true,
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=tls"
}
END
cat > /etc/shadowsocks-libev/$userna-http.json <<-END
{
    "server":"0.0.0.0",
    "server_port":$http,
    "password":"$userna",
    "timeout":60,
    "method":"aes-256-cfb",
    "fast_open":true,
    "no_delay":true,
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=http"
}
END
chmod +x /etc/shadowsocks-libev/$userna-tls.json
chmod +x /etc/shadowsocks-libev/$userna-http.json

systemctl start shadowsocks-libev-server@$userna-tls.service > /dev/null 2>&1
systemctl enable shadowsocks-libev-server@$userna-tls.service > /dev/null 2>&1
systemctl start shadowsocks-libev-server@$userna-http.service > /dev/null 2>&1
systemctl enable shadowsocks-libev-server@$userna-http.service > /dev/null 2>&1
tmp1=$(echo -n "aes-256-cfb:${userna}@${domain}:$tls" | base64 -w0)
tmp2=$(echo -n "aes-256-cfb:${userna}@${domain}:$http" | base64 -w0)
linkss1="ss://${tmp1}?plugin=obfs-local;obfs=tls;obfs-host=bing.com"
linkss2="ss://${tmp2}?plugin=obfs-local;obfs=http;obfs-host=bing.com"
echo -e "### $userna $exp
port_tls $tls
port_http $http">>"/etc/shadowsocks-libev/akun.conf"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>      🔸 SS OBFS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Password : $userna\n"
env_msg+="Expired On : $data \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port OBFS TLS : $tls\n"
env_msg+="Port OBFS HTTP : $http\n"
env_msg+="Encrypt Method : aes-256-cfb\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link OBFS TLS : \n"
env_msg+="<code>$linkss1</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link OBFS HTTP : \n"
env_msg+="<code>$linkss2</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 60Days SHADOWSOCKS | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
return 0
fi
}

del_ss() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🗑 REMOVE USER ShadowSocks 🗑\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}
	
func_del_ss() {
    userna=$1
    if [[ "${message_from_id[$id]}" = "$Admin_ID" ]]; then
        exp=$(grep -wE "^###" "/etc/shadowsocks-libev/akun.conf" | cut -d ' ' -f3 )
        sed -i "/^### $userna $exp/,/^port_http/d" "/etc/shadowsocks-libev/akun.conf"
        systemctl disable shadowsocks-libev-server@$userna-tls.service > /dev/null 2>&1
        systemctl disable shadowsocks-libev-server@$userna-http.service > /dev/null 2>&1
        systemctl stop shadowsocks-libev-server@$userna-tls.service > /dev/null 2>&1
        systemctl stop shadowsocks-libev-server@$userna-http.service > /dev/null 2>&1
	    rm -f "/etc/shadowsocks-libev/$userna-tls.json"
	    rm -f "/etc/shadowsocks-libev/$userna-http.json"
        datata=$(find /etc/.maAsiss/ -name $userna)
        for accc in "${datata[@]}"
        do
        rm $accc
        done
    elif [[ "${message_from_id[$id]}" != "$Admin_ID" ]]; then
        [[ ! -e /etc/.maAsiss/db_reseller/${message_from_id}/user_ss/$userna ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "⛔ THE USER DOES NOT EXIST ⛔")" \
                --parse_mode html
            _erro='1'      
            ShellBot.sendMessage --chat_id ${callack_query_message_chat_id[$id]} \
                 --text "Func Error Do Nothing" \
                 --reply_markup "$(ShellBot.ForceReply)"
            return 0
        }
        exp=$(grep -wE "^###" "/etc/shadowsocks-libev/akun.conf" | cut -d ' ' -f3 )
        sed -i "/^### $userna $exp/,/^port_http/d" "/etc/shadowsocks-libev/akun.conf"
        systemctl disable shadowsocks-libev-server@$userna-tls.service > /dev/null 2>&1
        systemctl disable shadowsocks-libev-server@$userna-http.service > /dev/null 2>&1
        systemctl stop shadowsocks-libev-server@$userna-tls.service > /dev/null 2>&1
        systemctl stop shadowsocks-libev-server@$userna-http.service > /dev/null 2>&1
	    rm -f "/etc/shadowsocks-libev/$userna-tls.json"
	    rm -f "/etc/shadowsocks-libev/$userna-http.json"
        rm -f /etc/.maAsiss/db_reseller/${message_from_id}/user_ss/$userna
        rm -f /etc/.maAsiss/info-user-ss/$userna
    fi
}

add_ss_trial() {
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE TRIAL ShadowSocks 👤\n\nHow many hours should it last ? EX: 1:" \
            --reply_markup "$(ShellBot.ForceReply)"
    elif [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]]; then
            ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "👤 CREATE TRIAL ShadowSocks 👤\n\nHow many hours should it last ? EX: 1:" \
                --reply_markup "$(ShellBot.ForceReply)"       
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

func_add_ss_trial() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderSS ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "⛔ Disable Order Shadowsocks" \
                --parse_mode html
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
               --text "Func Error Do Nothing" \
               --reply_markup "$(ShellBot.ForceReply)"
        return 0
    }
}
mkdir -p /etc/.maAsiss/info-user-ss
    userna=$(echo Trial`</dev/urandom tr -dc A-Z0-9 | head -c4`)
    t_time=$1
    domain=$(cat /etc/$raycheck/domain)
    lastport1=$(grep "port_tls" /etc/shadowsocks-libev/akun.conf | tail -n1 | awk '{print $2}')
    lastport2=$(grep "port_http" /etc/shadowsocks-libev/akun.conf | tail -n1 | awk '{print $2}')
    if [[ $lastport1 == '' ]]; then
    tls=2443
    else
    tls="$((lastport1+1))"
    fi
    if [[ $lastport2 == '' ]]; then
    http=3443
    else
    http="$((lastport2+1))"
    fi
    exp=`date -d "2 days" +"%Y-%m-%d"`
    tuserdate=$(date '+%C%y/%m/%d' -d " +2 days")
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
       mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold
    }
    [[ -z $t_time ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e "⛔ error try again")" \
            --parse_mode html
        return 0
        _erro='1'
    }
    

cat > /etc/shadowsocks-libev/$userna-tls.json<<END
{   
    "server":"0.0.0.0",
    "server_port":$tls,
    "password":"$userna",
    "timeout":60,
    "method":"aes-256-cfb",
    "fast_open":true,
    "no_delay":true,
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=tls"
}
END
cat > /etc/shadowsocks-libev/$userna-http.json <<-END
{
    "server":"0.0.0.0",
    "server_port":$http,
    "password":"$userna",
    "timeout":60,
    "method":"aes-256-cfb",
    "fast_open":true,
    "no_delay":true,
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=http"
}
END
chmod +x /etc/shadowsocks-libev/$userna-tls.json
chmod +x /etc/shadowsocks-libev/$userna-http.json

[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    echo "$userna:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/user_ss/$userna
    echo "$userna:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna
}
dir_teste="/etc/.maAsiss/db_reseller/${message_from_id}/user_ss/$userna"
dir_teste2="/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna"
dates=`date`
cat <<-EOF >/etc/.maAsiss/$userna.sh
#!/bin/bash
# USER TRIAL SS by ${message_from_id} $dates
exp=\$(grep -wE "^### " "/etc/shadowsocks-libev/akun.conf" | cut -d ' ' -f3 )
sed -i "/^### $userna $exp/,/^port_http/d" "/etc/shadowsocks-libev/akun.conf"
systemctl disable shadowsocks-libev-server@$userna-tls.service > /dev/null 2>&1
systemctl disable shadowsocks-libev-server@$userna-http.service > /dev/null 2>&1
systemctl stop shadowsocks-libev-server@$userna-tls.service > /dev/null 2>&1
systemctl stop shadowsocks-libev-server@$userna-http.service > /dev/null 2>&1
rm -f "/etc/shadowsocks-libev/$userna-tls.json"
rm -f "/etc/shadowsocks-libev/$userna-http.json"

rm /etc/.maAsiss/db_reseller/${message_from_id}/user_ss/$userna
rm /etc/.maAsiss/info-user-ss/$userna
[[ -e $dir_teste ]] && rm $dir_teste
[[ -e $dir_teste2 ]] && rm $dir_teste2
rm -f /etc/.maAsiss/$userna
rm -f /etc/.maAsiss/$userna.sh
EOF

chmod +x /etc/.maAsiss/$userna.sh
echo "/etc/.maAsiss/$userna.sh" | at now + $t_time hour >/dev/null 2>&1
[[ "$t_time" == '1' ]] && hrs="hour" || hrs="hours"          

systemctl start shadowsocks-libev-server@$userna-tls.service > /dev/null 2>&1
systemctl enable shadowsocks-libev-server@$userna-tls.service > /dev/null 2>&1
systemctl start shadowsocks-libev-server@$userna-http.service > /dev/null 2>&1
systemctl enable shadowsocks-libev-server@$userna-http.service > /dev/null 2>&1
tmp1=$(echo -n "aes-256-cfb:${userna}@${domain}:$tls" | base64 -w0)
tmp2=$(echo -n "aes-256-cfb:${userna}@${domain}:$http" | base64 -w0)
linkss1="ss://${tmp1}?plugin=obfs-local;obfs=tls;obfs-host=bing.com"
linkss2="ss://${tmp2}?plugin=obfs-local;obfs=http;obfs-host=bing.com"
echo -e "### $userna $exp
port_tls $tls
port_http $http">>"/etc/shadowsocks-libev/akun.conf"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>      🔸 SS OBFS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Password : $userna\n"
env_msg+="Expired On : $t_time $hrs ⏳ \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port OBFS TLS : $tls\n"
env_msg+="Port OBFS HTTP : $http\n"
env_msg+="Encrypt Method : aes-256-cfb\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link OBFS TLS : \n"
env_msg+="<code>$linkss1</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link OBFS HTTP : \n"
env_msg+="<code>$linkss2</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
return 0
}

list_member_ss() {
   if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
      _result=$(grep -wE "^###" "/etc/shadowsocks-libev/akun.conf" | cut -d ' ' -f2 | column -t | sort | uniq | wc -l)
      _results=$(grep -wE "^###" "/etc/shadowsocks-libev/akun.conf" | cut -d ' ' -f2 | column -t | sort | uniq )
   elif [[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]]; then
      _result=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_ss | wc -l)
      _results=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_ss )
   else
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ ACCESS DENIE ⛔" \
                --parse_mode html
      return 0
   fi
   if [ "$_result" = "0" ]; then
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ YOU DONT HAVE ANY USER YET ⛔" \
                --parse_mode html
      return 0
   else
      ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
      ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
         --text "━━━━━━━━━━━━━━━━━━━━━\n 🟢 ShadowSocks Member List 🟢 \n━━━━━━━━━━━━━━━━━━━━━\n\n$_results\n\n━━━━━━━━━━━━━━━━━━━━━\n" \
         --parse_mode html
      return 0
   fi
}

check_login_ss(){
if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
echo -e "━━━━━━━━━━━━━━━━━━━━━" > /tmp/ss-login
echo -e "       🟢 ShadowSocks User Login 🟢 " >> /tmp/ss-login
echo -e "━━━━━━━━━━━━━━━━━━━━━" >> /tmp/ss-login
data=( `cat /etc/shadowsocks-libev/akun.conf | grep '^###' | cut -d ' ' -f 2`);
x=1
echo " User | TLS : ">> /tmp/ss-login
for akun in "${data[@]}"
do
port=$(cat /etc/shadowsocks-libev/akun.conf | grep '^port_tls' | cut -d ' ' -f 2 | tr '\n' ' ' | awk '{print $'"$x"'}')
jum=$(netstat -anp | grep ESTABLISHED | grep obfs-server | cut -d ':' -f 2 | grep -w $port | awk '{print $2}' | sort | uniq | nl)
if [[ -z "$jum" ]]; then
echo > /dev/null
else
echo " $akun - $port">> /tmp/ss-login
echo "$jum">> /tmp/ss-login
echo -e "━━━━━━━━━━━━━━━━━━━━━">> /tmp/ss-login
fi
x=$(( "$x" + 1 ))
done
data=( `cat /etc/shadowsocks-libev/akun.conf | grep '^###' | cut -d ' ' -f 2`);
x=1
echo " User |  HTTP :">> /tmp/ss-login
for akun in "${data[@]}"
do
port=$(cat /etc/shadowsocks-libev/akun.conf | grep '^port_http' | cut -d ' ' -f 2 | tr '\n' ' ' | awk '{print $'"$x"'}')
jum=$(netstat -anp | grep ESTABLISHED | grep obfs-server | cut -d ':' -f 2 | grep -w $port | awk '{print $2}' | sort | uniq | nl)
if [[ -z "$jum" ]]; then
echo > /dev/null
else
echo " $akun - $port">> /tmp/ss-login
echo "$jum">> /tmp/ss-login
echo -e "━━━━━━━━━━━━━━━━━━━━━">> /tmp/ss-login
fi
x=$(( "$x" + 1 ))
done
msg=$(cat /tmp/ss-login)
cekk=$(cat /tmp/vmess-login | wc -l)
if [ "$cekk" = "0" ] || [ "$cekk" = "5" ]; then
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ NO USERS ONLINE ⛔" \
                --parse_mode html
rm /tmp/ss-login
return 0
else
ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
         --text "$msg" \
         --parse_mode html
rm /tmp/ss-login
return 0
fi
else
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ ACCESS DENIED ⛔" \
                --parse_mode html
return 0
fi
}

unset menu_ss
menu_ss=''
ShellBot.InlineKeyboardButton --button 'menu_ss' --line 1 --text 'Add Shadowsocks' --callback_data '_add_ss'
ShellBot.InlineKeyboardButton --button 'menu_ss' --line 2 --text 'Delete Shadowsocks' --callback_data '_delete_ss'
ShellBot.InlineKeyboardButton --button 'menu_ss' --line 3 --text 'Create Trial SS' --callback_data '_trial_ss'
ShellBot.InlineKeyboardButton --button 'menu_ss' --line 4 --text 'List Member SS' --callback_data '_member_ss'
ShellBot.InlineKeyboardButton --button 'menu_ss' --line 5 --text 'Check User Login SS' --callback_data '_login_ss'
ShellBot.InlineKeyboardButton --button 'menu_ss' --line 6 --text '🔙 Back 🔙' --callback_data '_gobackss'
ShellBot.regHandleFunction --function add_ss --callback_data _add_ss
ShellBot.regHandleFunction --function del_ss --callback_data _delete_ss
ShellBot.regHandleFunction --function add_ss_trial --callback_data _trial_ss
ShellBot.regHandleFunction --function list_member_ss --callback_data _member_ss
ShellBot.regHandleFunction --function check_login_ss --callback_data _login_ss
ShellBot.regHandleFunction --function admin_service_see --callback_data _gobackss
unset keyboardss
keyboardss="$(ShellBot.InlineKeyboardMarkup -b 'menu_ss')"

unset res_menu_ss
res_menu_ss=''
ShellBot.InlineKeyboardButton --button 'res_menu_ss' --line 1 --text '➕ Add Shadowsocks ➕' --callback_data '_res_add_ss'
ShellBot.InlineKeyboardButton --button 'res_menu_ss' --line 3 --text '⏳ Create Trial SS ⏳' --callback_data '_res_trial_ss'
ShellBot.InlineKeyboardButton --button 'res_menu_ss' --line 4 --text '🟢 List Member SS 🟢' --callback_data '_res_member_ss'
ShellBot.InlineKeyboardButton --button 'res_menu_ss' --line 5 --text '🔙 Back 🔙' --callback_data '_res_gobackss'
ShellBot.regHandleFunction --function add_ss --callback_data _res_add_ss
ShellBot.regHandleFunction --function add_ss_trial --callback_data _res_trial_ss
ShellBot.regHandleFunction --function list_member_ss --callback_data _res_member_ss
ShellBot.regHandleFunction --function menu_reserv --callback_data _res_gobackss
unset keyboardssres
keyboardssres="$(ShellBot.InlineKeyboardMarkup -b 'res_menu_ss')"

#====== ALL ABOUT ShadowSocksR =======#

res_ssr_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'res_menu_ssr')"
        return 0
    }
}

ssr_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_ssr')"
        return 0
    }
}

add_ssr() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE USER Shadowsocks-R 👤\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_add_ssr() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderSSR ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Disable Order Shadowsocks-R" \
                    --parse_mode html
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                   --text "Func Error Do Nothing" \
                   --reply_markup "$(ShellBot.ForceReply)"
            return 0
    }
}

file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
data=$(sed -n '2 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)        

domain=$(cat /etc/$raycheck/domain)
lastport=$(cat /usr/local/shadowsocksr/mudb.json | grep '"port": ' | tail -n1 | awk '{print $2}' | cut -d "," -f 1 | cut -d ":" -f 1 )
if [[ $lastport == '' ]]; then
ssr_port=1443
else
ssr_port=$((lastport+1))
fi

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-ssr
echo "$userna:$data" >/etc/.maAsiss/info-user-ssr/$userna

ssr_password="$userna"
ssr_method="aes-256-cfb"
ssr_protocol="origin"
ssr_obfs="tls1.2_ticket_auth_compatible"
ssr_protocol_param="2"
ssr_speed_limit_per_con=0
ssr_speed_limit_per_user=0
ssr_transfer="838868"
ssr_forbid="bittorrent"
cd /usr/local/shadowsocksr
match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
cd

echo -e "### $userna $exp" >> /usr/local/shadowsocksr/akun.conf
tmp1=$(echo -n "${ssr_password}" | base64 -w0 | sed 's/=//g;s/\//_/g;s/+/-/g')
SSRobfs=$(echo ${ssr_obfs} | sed 's/_compatible//g')
tmp2=$(echo -n "$domain:${ssr_port}:${ssr_protocol}:${ssr_method}:${SSRobfs}:${tmp1}/obfsparam=" | base64 -w0)
ssr_link="ssr://${tmp2}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>  🔸 Shadosocks-R ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Password : $userna\n"
env_msg+="Expired On : $exp \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $ssr_port\n"
env_msg+="Protocol : $ssr_protocol\n"
env_msg+="Encrypt Method : $ssr_method\n"
env_msg+="Obfs : $ssr_obfs\n"
env_msg+="Device Limit : $ssr_protocol_param\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link SSR: \n\n"
env_msg+="<code>$ssr_link</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
/etc/init.d/ssrmu restart
return 0
}

pricessr=$(grep -w "Price Shadowsocks-R" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
if [ "$saldores" -lt "$pricessr" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-ssr
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_ssr
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_ssr/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-ssr/$userna
_CurrSal=$(echo $saldores - $pricessr | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

ssr_password="$userna"
ssr_method="aes-256-cfb"
ssr_protocol="origin"
ssr_obfs="tls1.2_ticket_auth_compatible"
ssr_protocol_param="2"
ssr_speed_limit_per_con=0
ssr_speed_limit_per_user=0
ssr_transfer="838868"
ssr_forbid="bittorrent"
cd /usr/local/shadowsocksr
match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
cd

echo -e "### $userna $exp" >> /usr/local/shadowsocksr/akun.conf
tmp1=$(echo -n "${ssr_password}" | base64 -w0 | sed 's/=//g;s/\//_/g;s/+/-/g')
SSRobfs=$(echo ${ssr_obfs} | sed 's/_compatible//g')
tmp2=$(echo -n "$domain:${ssr_port}:${ssr_protocol}:${ssr_method}:${SSRobfs}:${tmp1}/obfsparam=" | base64 -w0)
ssr_link="ssr://${tmp2}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>  🔸 Shadosocks-R ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Password : $userna\n"
env_msg+="Expired On : $exp \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $ssr_port\n"
env_msg+="Protocol : $ssr_protocol\n"
env_msg+="Encrypt Method : $ssr_method\n"
env_msg+="Obfs : $ssr_obfs\n"
env_msg+="Device Limit : $ssr_protocol_param\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link SSR: \n\n"
env_msg+="<code>$ssr_link</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 30Days SHADOWSOCKS-R | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
/etc/init.d/ssrmu restart
return 0
fi
}

func_add_ssr2() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderSSR ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Disable Order Shadowsocks-R" \
                    --parse_mode html
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                   --text "Func Error Do Nothing" \
                   --reply_markup "$(ShellBot.ForceReply)"
            return 0
    }
}
file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
data=$(sed -n '2 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)        

domain=$(cat /etc/$raycheck/domain)
lastport=$(cat /usr/local/shadowsocksr/mudb.json | grep '"port": ' | tail -n1 | awk '{print $2}' | cut -d "," -f 1 | cut -d ":" -f 1 )
if [[ $lastport == '' ]]; then
ssr_port=1443
else
ssr_port=$((lastport+1))
fi

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-ssr
echo "$userna:$data" >/etc/.maAsiss/info-user-ssr/$userna

ssr_password="$userna"
ssr_method="aes-256-cfb"
ssr_protocol="origin"
ssr_obfs="tls1.2_ticket_auth_compatible"
ssr_protocol_param="2"
ssr_speed_limit_per_con=0
ssr_speed_limit_per_user=0
ssr_transfer="838868"
ssr_forbid="bittorrent"
cd /usr/local/shadowsocksr
match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
cd

echo -e "### $userna $exp" >> /usr/local/shadowsocksr/akun.conf
tmp1=$(echo -n "${ssr_password}" | base64 -w0 | sed 's/=//g;s/\//_/g;s/+/-/g')
SSRobfs=$(echo ${ssr_obfs} | sed 's/_compatible//g')
tmp2=$(echo -n "$domain:${ssr_port}:${ssr_protocol}:${ssr_method}:${SSRobfs}:${tmp1}/obfsparam=" | base64 -w0)
ssr_link="ssr://${tmp2}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>  🔸 Shadosocks-R ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Password : $userna\n"
env_msg+="Expired On : $exp \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $ssr_port\n"
env_msg+="Protocol : $ssr_protocol\n"
env_msg+="Encrypt Method : $ssr_method\n"
env_msg+="Obfs : $ssr_obfs\n"
env_msg+="Device Limit : $ssr_protocol_param\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link SSR: \n\n"
env_msg+="<code>$ssr_link</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
/etc/init.d/ssrmu restart
return 0
}

pricessr=$(grep -w "Price Shadowsocks-R" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
urday=$(echo $pricessr * 2 | bc)
if [ "$saldores" -lt "$urday" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-ssr
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_ssr
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_ssr/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-ssr/$userna
_CurrSal=$(echo $saldores - $urday | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

ssr_password="$userna"
ssr_method="aes-256-cfb"
ssr_protocol="origin"
ssr_obfs="tls1.2_ticket_auth_compatible"
ssr_protocol_param="2"
ssr_speed_limit_per_con=0
ssr_speed_limit_per_user=0
ssr_transfer="838868"
ssr_forbid="bittorrent"
cd /usr/local/shadowsocksr
match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
cd

echo -e "### $userna $exp" >> /usr/local/shadowsocksr/akun.conf
tmp1=$(echo -n "${ssr_password}" | base64 -w0 | sed 's/=//g;s/\//_/g;s/+/-/g')
SSRobfs=$(echo ${ssr_obfs} | sed 's/_compatible//g')
tmp2=$(echo -n "$domain:${ssr_port}:${ssr_protocol}:${ssr_method}:${SSRobfs}:${tmp1}/obfsparam=" | base64 -w0)
ssr_link="ssr://${tmp2}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>  🔸 Shadosocks-R ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Password : $userna\n"
env_msg+="Expired On : $exp \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $ssr_port\n"
env_msg+="Protocol : $ssr_protocol\n"
env_msg+="Encrypt Method : $ssr_method\n"
env_msg+="Obfs : $ssr_obfs\n"
env_msg+="Device Limit : $ssr_protocol_param\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link SSR: \n\n"
env_msg+="<code>$ssr_link</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 60Days SHADOWSOCKS-R | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
/etc/init.d/ssrmu restart
return 0
fi
}

del_ssr() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🗑 REMOVE USER Shadowsocks-R 🗑\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_del_ssr() {
    userna=$1
    if [[ "${message_from_id[$id]}" = "$Admin_ID" ]]; then
        exp=$(grep -wE "^###" "/usr/local/shadowsocksr/akun.conf" | cut -d ' ' -f 3)
        sed -i "/^### $userna/d" "/usr/local/shadowsocksr/akun.conf"
        cd /usr/local/shadowsocksr
        match_del=$(python mujson_mgr.py -d -u "${userna}"|grep -w "delete user")
        cd
        datata=$(find /etc/.maAsiss/ -name $userna)
        for accc in "${datata[@]}"
        do
        rm $accc
        done
        /etc/init.d/ssrmu restart
    elif [[ "${message_from_id[$id]}" != "$Admin_ID" ]]; then
        [[ ! -e /etc/.maAsiss/db_reseller/${message_from_id}/user_ssr/$userna ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "⛔ THE USER DOES NOT EXIST ⛔")" \
                --parse_mode html
            _erro='1'      
            ShellBot.sendMessage --chat_id ${callack_query_message_chat_id[$id]} \
                 --text "Func Error Do Nothing" \
                 --reply_markup "$(ShellBot.ForceReply)"
            return 0
        }
        exp=$(grep -wE "^###" "/usr/local/shadowsocksr/akun.conf" | cut -d ' ' -f 3)
        sed -i "/^### $userna/d" "/usr/local/shadowsocksr/akun.conf"
        cd /usr/local/shadowsocksr
        match_del=$(python mujson_mgr.py -d -u "${userna}"|grep -w "delete user")
        cd
        rm -f /etc/.maAsiss/db_reseller/${message_from_id}/user_ssr/$userna
        rm -f /etc/.maAsiss/info-user-ssr/$userna
        /etc/init.d/ssrmu restart
    fi
}

add_ssr_trial() {
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE TRIAL Shadowsocks-R 👤\n\nHow many hours should it last ? EX: 1:" \
            --reply_markup "$(ShellBot.ForceReply)"
    elif [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]]; then
            ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "👤 CREATE TRIAL Shadowsocks-R 👤\n\nHow many hours should it last ? EX: 1:" \
                --reply_markup "$(ShellBot.ForceReply)"       
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

func_add_ssr_trial() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderSSR ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Disable Order Shadowsocks-R" \
                    --parse_mode html
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                   --text "Func Error Do Nothing" \
                   --reply_markup "$(ShellBot.ForceReply)"
            return 0
    }
}
mkdir -p /etc/.maAsiss/info-user-ssr
    userna=$(echo Trial`</dev/urandom tr -dc A-Z0-9 | head -c4`)
    t_time=$1
    domain=$(cat /etc/$raycheck/domain)
    lastport=$(cat /usr/local/shadowsocksr/mudb.json | grep '"port": ' | tail -n1 | awk '{print $2}' | cut -d "," -f 1 | cut -d ":" -f 1 )
    if [[ $lastport == '' ]]; then
    ssr_port=1443
    else
    ssr_port=$((lastport+1))
    fi
    exp=`date -d "2 days" +"%Y-%m-%d"`
    tuserdate=$(date '+%C%y/%m/%d' -d " +2 days")
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
       mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold
    }
    [[ -z $t_time ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e "⛔ error try again")" \
            --parse_mode html
        return 0
        _erro='1'
    }

ssr_password="$userna"
ssr_method="aes-256-cfb"
ssr_protocol="origin"
ssr_obfs="tls1.2_ticket_auth_compatible"
ssr_protocol_param="2"
ssr_speed_limit_per_con=0
ssr_speed_limit_per_user=0
ssr_transfer="838868"
ssr_forbid="bittorrent"
cd /usr/local/shadowsocksr
match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
cd

[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    echo "$userna:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/user_ssr/$userna
    echo "$userna:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna
}
dir_teste="/etc/.maAsiss/db_reseller/${message_from_id}/user_ssr/$userna"
dir_teste2="/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna"
dates=`date`
cat <<-EOF >/etc/.maAsiss/$userna.sh
#!/bin/bash
# USER TRIAL SSR by ${message_from_id} $dates
exp=\$(grep -wE "^###" "/usr/local/shadowsocksr/akun.conf" | cut -d ' ' -f 3)
sed -i "/^### $userna/d" "/usr/local/shadowsocksr/akun.conf"
cd /usr/local/shadowsocksr
match_del=$(python mujson_mgr.py -d -u "${userna}"|grep -w "delete user")
cd
rm -f /etc/.maAsiss/db_reseller/${message_from_id}/user_ssr/$userna
rm -f /etc/.maAsiss/info-user-ssr/$userna
/etc/init.d/ssrmu restart
[[ -e $dir_teste ]] && rm $dir_teste
[[ -e $dir_teste2 ]] && rm $dir_teste2
rm -f /etc/.maAsiss/$userna
rm -f /etc/.maAsiss/$userna.sh
EOF

chmod +x /etc/.maAsiss/$userna.sh
echo "/etc/.maAsiss/$userna.sh" | at now + $t_time hour >/dev/null 2>&1
[[ "$t_time" == '1' ]] && hrs="hour" || hrs="hours"          

echo -e "### $userna $exp" >> /usr/local/shadowsocksr/akun.conf
tmp1=$(echo -n "${ssr_password}" | base64 -w0 | sed 's/=//g;s/\//_/g;s/+/-/g')
SSRobfs=$(echo ${ssr_obfs} | sed 's/_compatible//g')
tmp2=$(echo -n "$domain:${ssr_port}:${ssr_protocol}:${ssr_method}:${SSRobfs}:${tmp1}/obfsparam=" | base64 -w0)
ssr_link="ssr://${tmp2}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>  🔸 Shadosocks-R ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Password : $userna\n"
env_msg+="Expired On : $t_time $hrs ⏳ \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $ssr_port\n"
env_msg+="Protocol : $ssr_protocol\n"
env_msg+="Encrypt Method : $ssr_method\n"
env_msg+="Obfs : $ssr_obfs\n"
env_msg+="Device Limit : $ssr_protocol_param\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link SSR: \n\n"
env_msg+="<code>$ssr_link</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
    
/etc/init.d/ssrmu restart
return 0
}

list_member_ssr() {
   if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
      _result=$(grep -wE "^###" "/usr/local/shadowsocksr/akun.conf" | cut -d ' ' -f2 | column -t | sort | uniq | wc -l)
      _results=$(grep -wE "^###" "/usr/local/shadowsocksr/akun.conf" | cut -d ' ' -f2 | column -t | sort | uniq )
   elif [[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]]; then
      _result=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_ssr | wc -l)
      _results=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_ssr )
   else
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ ACCESS DENIED ⛔" \
                --parse_mode html
      return 0
   fi
   if [ "$_result" = "0" ]; then
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ YOU DONT HAVE ANY USER YET ⛔" \
                --parse_mode html
      return 0
   else
      ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
      ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
         --text "━━━━━━━━━━━━━━━━━━━━━\n🟢 ShadowsocksR Member List 🟢\n━━━━━━━━━━━━━━━━━━━━━\n\n$_results\n\n━━━━━━━━━━━━━━━━━━━━━\n" \
         --parse_mode html
      return 0
   fi
}

unset menu_ssr
menu_ssr=''
ShellBot.InlineKeyboardButton --button 'menu_ssr' --line 1 --text 'Add Shadowsocks-R' --callback_data '_add_ssr'
ShellBot.InlineKeyboardButton --button 'menu_ssr' --line 2 --text 'Delete Shadowsocks-R' --callback_data '_delete_ssr'
ShellBot.InlineKeyboardButton --button 'menu_ssr' --line 3 --text 'Create Trial SSR' --callback_data '_trial_ssr'
ShellBot.InlineKeyboardButton --button 'menu_ssr' --line 4 --text 'List Member SSR' --callback_data '_member_ssr'
ShellBot.InlineKeyboardButton --button 'menu_ssr' --line 6 --text '🔙 Back 🔙' --callback_data '_gobackssr'
ShellBot.regHandleFunction --function add_ssr --callback_data _add_ssr
ShellBot.regHandleFunction --function del_ssr --callback_data _delete_ssr
ShellBot.regHandleFunction --function add_ssr_trial --callback_data _trial_ssr
ShellBot.regHandleFunction --function list_member_ssr --callback_data _member_ssr
ShellBot.regHandleFunction --function admin_service_see --callback_data _gobackssr
unset keyboardssr
keyboardssr="$(ShellBot.InlineKeyboardMarkup -b 'menu_ssr')"

unset res_menu_ssr
res_menu_ssr=''
ShellBot.InlineKeyboardButton --button 'res_menu_ssr' --line 1 --text '➕ Add Shadowsocks-R ➕' --callback_data '_res_add_ssr'
ShellBot.InlineKeyboardButton --button 'res_menu_ssr' --line 3 --text '⏳ Create Trial SSR ⏳' --callback_data '_res_trial_ssr'
ShellBot.InlineKeyboardButton --button 'res_menu_ssr' --line 4 --text '🟢 List Member SSR 🟢' --callback_data '_res_member_ssr'
ShellBot.InlineKeyboardButton --button 'res_menu_ssr' --line 5 --text '🔙 Back 🔙' --callback_data '_res_gobackssr'
ShellBot.regHandleFunction --function add_ssr --callback_data _res_add_ssr
ShellBot.regHandleFunction --function add_ssr_trial --callback_data _res_trial_ssr
ShellBot.regHandleFunction --function list_member_ssr --callback_data _res_member_ssr
ShellBot.regHandleFunction --function menu_reserv --callback_data _res_gobackssr
unset keyboardssrres
keyboardssrres="$(ShellBot.InlineKeyboardMarkup -b 'res_menu_ssr')"

#====== ALL ABOUT SSTP =======#

res_sstp_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'res_menu_sstppx')"
        return 0
    }
}

sstp_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_sstppx')"
        return 0
    }
}

add_sstp() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE USER SSTP 👤\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_add_sstp() {
file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
passw=$(sed -n '2 p' $file_user | cut -d' ' -f2)
data=$(sed -n '3 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)        
domain=$(cat /etc/$raycheck/domain)
IPK=$(curl -sS ipv4.icanhazip.com)
sstport="$(cat /root/log-install.txt | grep -i SSTP | cut -d: -f2|sed 's/ //g')"

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-sstp
echo "$userna:$data" >/etc/.maAsiss/info-user-sstp/$userna

cat >> /home/sstp/sstp_account <<EOF
$userna * $passw *
EOF
echo -e "### $userna $exp">>"/var/lib/scrz-prem/data-user-sstp"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>         🔸 SSTP ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IP : $IPK\n"
env_msg+="Username : $userna\n"
env_msg+="Password : $passw\n"
env_msg+="Expired On : $data 🗓 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $sstport\n"
env_msg+="Cert : http://$IPs:81/server.crt\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart accel-ppp > /dev/null 2>&1
return 0
}

pricesstp=$(grep -w "Price SSTP" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
if [ "$saldores" -lt "$pricesstp" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-sstp
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_sstp
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_sstp/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-sstp/$userna
_CurrSal=$(echo $saldores - $pricesstp | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

cat >> /home/sstp/sstp_account <<EOF
$userna * $passw *
EOF
echo -e "### $userna $exp">>"/var/lib/scrz-prem/data-user-sstp"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>         🔸 SSTP ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IP : $IPK\n"
env_msg+="Username : $userna\n"
env_msg+="Password : $passw\n"
env_msg+="Expired On : $data 🗓 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $sstport\n"
env_msg+="Cert : http://$IPs:81/server.crt\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 30Days SSTP | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart accel-ppp > /dev/null 2>&1
return 0
fi
}

func_add_sstp2() {
file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
passw=$(sed -n '2 p' $file_user | cut -d' ' -f2)
data=$(sed -n '3 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)        
domain=$(cat /etc/$raycheck/domain)
IPK=$(curl -sS ipv4.icanhazip.com)
sstport="$(cat /root/log-install.txt | grep -i SSTP | cut -d: -f2|sed 's/ //g')"

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-sstp
echo "$userna:$data" >/etc/.maAsiss/info-user-sstp/$userna

cat >> /home/sstp/sstp_account <<EOF
$userna * $passw *
EOF
echo -e "### $userna $exp">>"/var/lib/scrz-prem/data-user-sstp"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>         🔸 SSTP ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IP : $IPK\n"
env_msg+="Username : $userna\n"
env_msg+="Password : $passw\n"
env_msg+="Expired On : $data 🗓 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $sstport\n"
env_msg+="Cert : http://$IPs:81/server.crt\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart accel-ppp > /dev/null 2>&1
return 0
}

pricesstp=$(grep -w "Price SSTP" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
urday=$(echo $pricesstp * 2 | bc)
if [ "$saldores" -lt "$urday" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-sstp
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_sstp
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_sstp/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-sstp/$userna
_CurrSal=$(echo $saldores - $urday | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

cat >> /home/sstp/sstp_account <<EOF
$userna * $passw *
EOF
echo -e "### $userna $exp">>"/var/lib/scrz-prem/data-user-sstp"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>         🔸 SSTP ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IP : $IPK\n"
env_msg+="Username : $userna\n"
env_msg+="Password : $passw\n"
env_msg+="Expired On : $data 🗓 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $sstport\n"
env_msg+="Cert : http://$IPs:81/server.crt\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 60Days SSTP | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart accel-ppp > /dev/null 2>&1
return 0
fi
}

del_sstp() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🗑 REMOVE USER SSTP 🗑\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_del_sstp() {
    userna=$1
    if [[ "${message_from_id[$id]}" = "$Admin_ID" ]]; then
        exp=$(grep -E "^###" /var/lib/scrz-prem/data-user-sstp | cut -d ' ' -f 3 )
        sed -i "/^### $userna $exp/d" /var/lib/scrz-prem/data-user-sstp
        sed -i '/^'"$userna"'/d' /home/sstp/sstp_account
        datata=$(find /etc/.maAsiss/ -name $userna)
        for accc in "${datata[@]}"
        do
        rm $accc
        done
        systemctl restart accel-ppp > /dev/null 2>&1
    elif [[ "${message_from_id[$id]}" != "$Admin_ID" ]]; then
        [[ ! -e /etc/.maAsiss/db_reseller/${message_from_id}/user_sstp/$userna ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "⛔ THE USER DOES NOT EXIST ⛔")" \
                --parse_mode html
            _erro='1'      
            ShellBot.sendMessage --chat_id ${callack_query_message_chat_id[$id]} \
                 --text "Func Error Do Nothing" \
                 --reply_markup "$(ShellBot.ForceReply)"
            return 0
        }
        exp=$(grep -E "^###" /var/lib/scrz-prem/data-user-sstp | cut -d ' ' -f 3 )
        sed -i "/^### $userna $exp/d" /var/lib/scrz-prem/data-user-sstp
        sed -i '/^'"$userna"'/d' /home/sstp/sstp_account
        rm -f /etc/.maAsiss/db_reseller/${message_from_id}/user_sstp/$userna
        rm -f /etc/.maAsiss/info-user-sstp/$userna
        systemctl restart accel-ppp > /dev/null 2>&1
    fi
}

add_sstp_trial() {
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE TRIAL SSTP 👤\n\nHow many hours should it last ? EX: 1:" \
            --reply_markup "$(ShellBot.ForceReply)"
    elif [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]]; then
            ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "👤 CREATE TRIAL SSTP 👤\n\nHow many hours should it last ? EX: 1:" \
                --reply_markup "$(ShellBot.ForceReply)"       
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

func_add_sstp_trial() {
mkdir -p /etc/.maAsiss/info-user-sstp
    userna=$(echo Trial`</dev/urandom tr -dc A-Z0-9 | head -c4`)
    t_time=$1
    passw="1"
    domain=$(cat /etc/$raycheck/domain)
    IPK=$(curl -sS ipv4.icanhazip.com)
    sstport="$(cat /root/log-install.txt | grep -i SSTP | cut -d: -f2|sed 's/ //g')"
    exp=`date -d "2 days" +"%Y-%m-%d"`
    tuserdate=$(date '+%C%y/%m/%d' -d " +2 days")
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
       mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold
    }
    [[ -z $t_time ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e "⛔ error try again")" \
            --parse_mode html
        return 0
        _erro='1'
    }

[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    echo "$userna:$passw:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/user_sstp/$userna
    echo "$userna:$passw:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna
}
dir_teste="/etc/.maAsiss/db_reseller/${message_from_id}/user_sstp/$userna"
dir_teste2="/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna"
dates=`date`
cat <<-EOF >/etc/.maAsiss/$userna.sh
#!/bin/bash
# USER TRIAL SSTP by ${message_from_id} $dates
exp=\$(grep -E "^###" /var/lib/scrz-prem/data-user-sstp | cut -d ' ' -f 3 )
sed -i "/^### $userna $exp/d" /var/lib/scrz-prem/data-user-sstp
sed -i '/^'"$userna"'/d' /home/sstp/sstp_account
rm -f /etc/.maAsiss/db_reseller/${message_from_id}/user_sstp/$userna
rm -f /etc/.maAsiss/info-user-sstp/$userna
systemctl restart accel-ppp > /dev/null 2>&1
[[ -e $dir_teste ]] && rm $dir_teste
[[ -e $dir_teste2 ]] && rm $dir_teste2
rm -f /etc/.maAsiss/$userna
rm -f /etc/.maAsiss/$userna.sh
EOF

chmod +x /etc/.maAsiss/$userna.sh
echo "/etc/.maAsiss/$userna.sh" | at now + $t_time hour >/dev/null 2>&1
[[ "$t_time" == '1' ]] && hrs="hour" || hrs="hours"          

cat >> /home/sstp/sstp_account <<EOF
$userna * $passw *
EOF
echo -e "### $userna $exp">>"/var/lib/scrz-prem/data-user-sstp"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>         🔸 SSTP ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IP : $IPK\n"
env_msg+="Username : $userna\n"
env_msg+="Password : $passw\n"
env_msg+="Expired On : $t_time $hrs ⏳ \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $sstport\n"
env_msg+="Cert : http://$IPs:81/server.crt\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
    
systemctl restart accel-ppp > /dev/null 2>&1
return 0
}

list_member_sstp() {
   if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
      _result=$(grep -wE "^###" "/var/lib/scrz-prem/data-user-sstp" | cut -d ' ' -f2 | column -t | sort | uniq | wc -l)
      _results=$(grep -wE "^###" "/var/lib/scrz-prem/data-user-sstp" | cut -d ' ' -f2 | column -t | sort | uniq )
   elif [[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]]; then
      _result=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_sstp | wc -l)
      _results=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_sstp )
   else
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ ACCESS DENIED ⛔" \
                --parse_mode html
      return 0
   fi
   if [ "$_result" = "0" ]; then
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ YOU DONT HAVE ANY USER YET ⛔" \
                --parse_mode html
      return 0
   else
      ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
      ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
         --text "━━━━━━━━━━━━━━━━━━━━━\n 🟢 SSTP Member List 🟢\n━━━━━━━━━━━━━━━━━━━━━\n\n$_results\n\n━━━━━━━━━━━━━━━━━━━━━\n" \
         --parse_mode html
      return 0
   fi
}

unset menu_sstppx
menu_sstppx=''
ShellBot.InlineKeyboardButton --button 'menu_sstppx' --line 1 --text 'Add SSTP' --callback_data '_add_sstp'
ShellBot.InlineKeyboardButton --button 'menu_sstppx' --line 2 --text 'Delete SSTP' --callback_data '_delete_sstp'
ShellBot.InlineKeyboardButton --button 'menu_sstppx' --line 3 --text 'Create Trial SSTP' --callback_data '_trial_sstp'
ShellBot.InlineKeyboardButton --button 'menu_sstppx' --line 4 --text 'List Member SSTP' --callback_data '_member_sstp'
ShellBot.InlineKeyboardButton --button 'menu_sstppx' --line 6 --text '🔙 Back 🔙' --callback_data '_gobacksstp'
ShellBot.regHandleFunction --function add_sstp --callback_data _add_sstp
ShellBot.regHandleFunction --function del_sstp --callback_data _delete_sstp
ShellBot.regHandleFunction --function add_sstp_trial --callback_data _trial_sstp
ShellBot.regHandleFunction --function list_member_sstp --callback_data _member_sstp
ShellBot.regHandleFunction --function admin_service_see --callback_data _gobacksstp
unset keyboardsstp
keyboardsstp="$(ShellBot.InlineKeyboardMarkup -b 'menu_sstppx')"

unset res_menu_sstppx
res_menu_sstppx=''
ShellBot.InlineKeyboardButton --button 'res_menu_sstppx' --line 1 --text '➕ Add SSTP ➕' --callback_data '_res_add_sstp'
ShellBot.InlineKeyboardButton --button 'res_menu_sstppx' --line 2 --text '⏳ Create Trial SSTP ⏳' --callback_data '_res_trial_sstp'
ShellBot.InlineKeyboardButton --button 'res_menu_sstppx' --line 3 --text '🟢 List Member SSTP 🟢' --callback_data '_res_member_sstp'
ShellBot.InlineKeyboardButton --button 'res_menu_sstppx' --line 4 --text '🔙 Back 🔙' --callback_data '_res_gobacksstp'
ShellBot.regHandleFunction --function add_sstp --callback_data _res_add_sstp
ShellBot.regHandleFunction --function add_sstp_trial --callback_data _res_trial_sstp
ShellBot.regHandleFunction --function list_member_sstp --callback_data _res_member_sstp
ShellBot.regHandleFunction --function menu_reserv --callback_data _res_gobacksstp
unset keyboardsstpres
keyboardsstpres="$(ShellBot.InlineKeyboardMarkup -b 'res_menu_sstppx')"

#====== ALL ABOUT L2TP =======#

res_l2tp_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'res_menu_l2tp')"
        return 0
    }
}

l2tp_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_l2tp')"
        return 0
    }
}

add_l2tp() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE USER L2TP 👤\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_add_l2tp() {
file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
passw=$(sed -n '2 p' $file_user | cut -d' ' -f2)
data=$(sed -n '3 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)        
domain=$(cat /etc/$raycheck/domain)

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-l2tp
echo "$userna:$data" >/etc/.maAsiss/info-user-l2tp/$userna

# Add or update VPN user
cat >> /etc/ppp/chap-secrets <<EOF
"$userna" l2tpd "$passw" *
EOF

VPN_PASSWORD_ENC=$(openssl passwd -1 "$passw")
cat >> /etc/ipsec.d/passwd <<EOF
$userna:$VPN_PASSWORD_ENC:xauth-psk
EOF

# Update file attributes
chmod 600 /etc/ppp/chap-secrets* /etc/ipsec.d/passwd*
echo -e "### $userna $exp">>"/var/lib/scrz-prem/data-user-l2tp"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>         🔸 L2TP ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IP : $IPs\n"
env_msg+="Username : $userna\n"
env_msg+="Password : $passw\n"
env_msg+="Expired On : $data 🗓 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IPsec PSK : myvpn\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart l2tpd > /dev/null 2>&1
return 0
}

pricel2tp=$(grep -w "Price L2TP" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
if [ "$saldores" -lt "$pricel2tp" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-l2tp
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_l2tp
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_l2tp/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-l2tp/$userna
_CurrSal=$(echo $saldores - $pricel2tp | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

cat >> /etc/ppp/chap-secrets <<EOF
"$userna" l2tpd "$passw" *
EOF

VPN_PASSWORD_ENC=$(openssl passwd -1 "$passw")
cat >> /etc/ipsec.d/passwd <<EOF
$userna:$VPN_PASSWORD_ENC:xauth-psk
EOF

# Update file attributes
chmod 600 /etc/ppp/chap-secrets* /etc/ipsec.d/passwd*
echo -e "### $userna $exp">>"/var/lib/scrz-prem/data-user-l2tp"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>         🔸 L2TP ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IP : $IPs\n"
env_msg+="Username : $userna\n"
env_msg+="Password : $passw\n"
env_msg+="Expired On : $data 🗓 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IPsec PSK : myvpn\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 30Days L2TP | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart l2tpd > /dev/null 2>&1
return 0
fi
}

func_add_l2tp2() {
file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
passw=$(sed -n '2 p' $file_user | cut -d' ' -f2)
data=$(sed -n '3 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)        
domain=$(cat /etc/$raycheck/domain)

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-l2tp
echo "$userna:$data" >/etc/.maAsiss/info-user-l2tp/$userna

# Add or update VPN user
cat >> /etc/ppp/chap-secrets <<EOF
"$userna" l2tpd "$passw" *
EOF

VPN_PASSWORD_ENC=$(openssl passwd -1 "$passw")
cat >> /etc/ipsec.d/passwd <<EOF
$userna:$VPN_PASSWORD_ENC:xauth-psk
EOF

# Update file attributes
chmod 600 /etc/ppp/chap-secrets* /etc/ipsec.d/passwd*
echo -e "### $userna $exp">>"/var/lib/scrz-prem/data-user-l2tp"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>         🔸 L2TP ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IP : $IPs\n"
env_msg+="Username : $userna\n"
env_msg+="Password : $passw\n"
env_msg+="Expired On : $data 🗓 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IPsec PSK : myvpn\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart l2tpd > /dev/null 2>&1
return 0
}

pricel2tp=$(grep -w "Price L2TP" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
urday=$(echo $pricel2tp * 2 | bc )
if [ "$saldores" -lt "$urday" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-l2tp
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_l2tp
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_l2tp/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-l2tp/$userna
_CurrSal=$(echo $saldores - $urday | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

cat >> /etc/ppp/chap-secrets <<EOF
"$userna" l2tpd "$passw" *
EOF

VPN_PASSWORD_ENC=$(openssl passwd -1 "$passw")
cat >> /etc/ipsec.d/passwd <<EOF
$userna:$VPN_PASSWORD_ENC:xauth-psk
EOF

# Update file attributes
chmod 600 /etc/ppp/chap-secrets* /etc/ipsec.d/passwd*
echo -e "### $userna $exp">>"/var/lib/scrz-prem/data-user-l2tp"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>         🔸 L2TP ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IP : $IPs\n"
env_msg+="Username : $userna\n"
env_msg+="Password : $passw\n"
env_msg+="Expired On : $data 🗓 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IPsec PSK : myvpn\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 60Days L2TP | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart l2tpd > /dev/null 2>&1
return 0
fi
}

del_l2tp() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🗑 REMOVE USER L2TP 🗑\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_del_l2tp() {
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    userna=$1
    if [[ "${message_from_id[$id]}" = "$Admin_ID" ]]; then
        exp=$(grep -E "^### " /var/lib/scrz-prem/data-user-l2tp | cut -d ' ' -f 3 )
        sed -i '/^"'"$userna"'" l2tpd/d' /etc/ppp/chap-secrets
        sed -i '/^'"$userna"':\$1\$/d' /etc/ipsec.d/passwd
        sed -i "/^### $userna $exp/d" /var/lib/scrz-prem/data-user-l2tp
        chmod 600 /etc/ppp/chap-secrets* /etc/ipsec.d/passwd*
        datata=$(find /etc/.maAsiss/ -name $userna)
        for accc in "${datata[@]}"
        do
        rm $accc
        done
        systemctl restart l2tpd> /dev/null 2>&1
    elif [[ "${message_from_id[$id]}" != "$Admin_ID" ]]; then
        [[ ! -e /etc/.maAsiss/db_reseller/${message_from_id}/user_l2tp/$userna ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "⛔ THE USER DOES NOT EXIST ⛔")" \
                --parse_mode html
            _erro='1'      
            ShellBot.sendMessage --chat_id ${callack_query_message_chat_id[$id]} \
                 --text "Func Error Do Nothing" \
                 --reply_markup "$(ShellBot.ForceReply)"
            return 0
        }
        exp=$(grep -E "^### " /var/lib/scrz-prem/data-user-l2tp | cut -d ' ' -f 3 )
        sed -i '/^"'"$userna"'" l2tpd/d' /etc/ppp/chap-secrets
        sed -i '/^'"$userna"':\$1\$/d' /etc/ipsec.d/passwd
        sed -i "/^### $userna $exp/d" /var/lib/scrz-prem/data-user-l2tp
        chmod 600 /etc/ppp/chap-secrets* /etc/ipsec.d/passwd*
        rm -f /etc/.maAsiss/db_reseller/${message_from_id}/user_l2tp/$userna
        rm -f /etc/.maAsiss/info-user-l2tp/$userna
        systemctl restart l2tpd > /dev/null 2>&1
    fi
}

add_l2tp_trial() {
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE TRIAL L2TP 👤\n\nHow many hours should it last ? EX: 1:" \
            --reply_markup "$(ShellBot.ForceReply)"
    elif [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]]; then
            ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "👤 CREATE TRIAL L2TP 👤\n\nHow many hours should it last ? EX: 1:" \
                --reply_markup "$(ShellBot.ForceReply)"       
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

func_add_l2tp_trial() {
mkdir -p /etc/.maAsiss/info-user-l2tp
    userna=$(echo Trial`</dev/urandom tr -dc A-Z0-9 | head -c4`)
    t_time=$1
    passw="1"
    domain=$(cat /etc/$raycheck/domain)
    exp=`date -d "2 days" +"%Y-%m-%d"`
    tuserdate=$(date '+%C%y/%m/%d' -d " +2 days")
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
       mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold
    }
    [[ -z $t_time ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e "⛔ error try again")" \
            --parse_mode html
        return 0
        _erro='1'
    }

[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    echo "$userna:$passw:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/user_l2tp/$userna
    echo "$userna:$passw:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna
}
dir_teste="/etc/.maAsiss/db_reseller/${message_from_id}/user_l2tp/$userna"
dir_teste2="/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna"
dates=`date`
cat <<-EOF >/etc/.maAsiss/$userna.sh
#!/bin/bash
# USER TRIAL L2TP by ${message_from_id} $dates
exp=\$(grep -E "^###" /var/lib/scrz-prem/data-user-l2tp | cut -d ' ' -f 3 )
sed -i '/^"'"$userna"'" l2tpd/d' /etc/ppp/chap-secrets
sed -i '/^'"$userna"':\$1\$/d' /etc/ipsec.d/passwd
sed -i "/^### $userna $exp/d" /var/lib/scrz-prem/data-user-l2tp
chmod 600 /etc/ppp/chap-secrets* /etc/ipsec.d/passwd*
rm -f /etc/.maAsiss/db_reseller/${message_from_id}/user_l2tp/$userna
rm -f /etc/.maAsiss/info-user-l2tp/$userna
systemctl restart l2tpd > /dev/null 2>&1
[[ -e $dir_teste ]] && rm $dir_teste
[[ -e $dir_teste2 ]] && rm $dir_teste2
rm -f /etc/.maAsiss/$userna
rm -f /etc/.maAsiss/$userna.sh
EOF

chmod +x /etc/.maAsiss/$userna.sh
echo "/etc/.maAsiss/$userna.sh" | at now + $t_time hour >/dev/null 2>&1
[[ "$t_time" == '1' ]] && hrs="hour" || hrs="hours"          

cat >> /etc/ppp/chap-secrets <<EOF
"$userna" l2tpd "$passw" *
EOF

VPN_PASSWORD_ENC=$(openssl passwd -1 "$passw")
cat >> /etc/ipsec.d/passwd <<EOF
$userna:$VPN_PASSWORD_ENC:xauth-psk
EOF

# Update file attributes
chmod 600 /etc/ppp/chap-secrets* /etc/ipsec.d/passwd*
echo -e "### $userna $exp">>"/var/lib/scrz-prem/data-user-l2tp"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>         🔸 L2TP ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IP : $IPs\n"
env_msg+="Username : $userna\n"
env_msg+="Password : $passw\n"
env_msg+="Expired On : $t_time $hrs ⏳ \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IPsec PSK : myvpn\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
    
systemctl restart l2tpd > /dev/null 2>&1
return 0
}

list_member_l2tp() {
   if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
      _result=$(grep -wE "^###" "/var/lib/scrz-prem/data-user-l2tp" | cut -d ' ' -f2 | column -t | sort | uniq | wc -l)
      _results=$(grep -wE "^###" "/var/lib/scrz-prem/data-user-l2tp" | cut -d ' ' -f2 | column -t | sort | uniq )
   elif [[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]]; then
      _result=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_l2tp | wc -l)
      _results=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_l2tp )
   else
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ ACCESS DENIED ⛔" \
                --parse_mode html
      return 0
   fi
   if [ "$_result" = "0" ]; then
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ YOU DONT HAVE ANY USER YET ⛔" \
                --parse_mode html
      return 0
   else
      ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
      ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
         --text "━━━━━━━━━━━━━━━━━━━━━\n 🟢 L2TP Member List 🟢\n━━━━━━━━━━━━━━━━━━━━━\n\n$_results\n\n━━━━━━━━━━━━━━━━━━━━━\n" \
         --parse_mode html
      return 0
   fi
}

unset menu_l2tp
menu_l2tp=''
ShellBot.InlineKeyboardButton --button 'menu_l2tp' --line 1 --text 'Add L2TP' --callback_data '_add_l2tp'
ShellBot.InlineKeyboardButton --button 'menu_l2tp' --line 2 --text 'Delete L2TP' --callback_data '_delete_l2tp'
ShellBot.InlineKeyboardButton --button 'menu_l2tp' --line 3 --text 'Create Trial L2TP' --callback_data '_trial_l2tp'
ShellBot.InlineKeyboardButton --button 'menu_l2tp' --line 4 --text 'List Member L2TP' --callback_data '_member_l2tp'
ShellBot.InlineKeyboardButton --button 'menu_l2tp' --line 6 --text '🔙 Back 🔙' --callback_data '_gobackl2tp'
ShellBot.regHandleFunction --function add_l2tp --callback_data _add_l2tp
ShellBot.regHandleFunction --function del_l2tp --callback_data _delete_l2tp
ShellBot.regHandleFunction --function add_l2tp_trial --callback_data _trial_l2tp
ShellBot.regHandleFunction --function list_member_l2tp --callback_data _member_l2tp
ShellBot.regHandleFunction --function admin_service_see --callback_data _gobackl2tp
unset keyboardl2tp
keyboardl2tp="$(ShellBot.InlineKeyboardMarkup -b 'menu_l2tp')"

unset res_menu_l2tp
res_menu_l2tp=''
ShellBot.InlineKeyboardButton --button 'res_menu_l2tp' --line 1 --text '➕ Add L2TP ➕' --callback_data '_res_add_l2tp'
ShellBot.InlineKeyboardButton --button 'res_menu_l2tp' --line 3 --text '⏳ Create Trial L2TP ⏳' --callback_data '_res_trial_l2tp'
ShellBot.InlineKeyboardButton --button 'res_menu_l2tp' --line 4 --text '🟢 List Member L2TP 🟢' --callback_data '_res_member_l2tp'
ShellBot.InlineKeyboardButton --button 'res_menu_l2tp' --line 5 --text '🔙 Back 🔙' --callback_data '_res_gobackl2tp'
ShellBot.regHandleFunction --function add_l2tp --callback_data _res_add_l2tp
ShellBot.regHandleFunction --function add_l2tp_trial --callback_data _res_trial_l2tp
ShellBot.regHandleFunction --function list_member_l2tp --callback_data _res_member_l2tp
ShellBot.regHandleFunction --function menu_reserv --callback_data _res_gobackl2tp
unset keyboardl2tpres
keyboardl2tpres="$(ShellBot.InlineKeyboardMarkup -b 'res_menu_l2tp')"

#====== ALL ABOUT PPTP =======#

res_pptp_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'res_menu_pptp')"
        return 0
    }
}

pptp_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_pptp')"
        return 0
    }
}

add_pptp() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE USER PPTP 👤\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_add_pptp() {
file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
passw=$(sed -n '2 p' $file_user | cut -d' ' -f2)
data=$(sed -n '3 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)        
domain=$(cat /etc/$raycheck/domain)

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-pptp
echo "$userna:$data" >/etc/.maAsiss/info-user-pptp/$userna

cat >> /etc/ppp/chap-secrets <<EOF
"$userna" pptpd "$passw" *
EOF

# Update file attributes
chmod 600 /etc/ppp/chap-secrets*
echo -e "### $userna $exp">>"/var/lib/scrz-prem/data-user-pptp"
local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>         🔸 PPTP ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IP : $IPs\n"
env_msg+="Username : $userna\n"
env_msg+="Password : $passw\n"
env_msg+="Expired On : $data 🗓 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart pptpd > /dev/null 2>&1
return 0
}

pricepptp=$(grep -w "Price PPTP" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
if [ "$saldores" -lt "$pricepptp" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-pptp
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_pptp
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_pptp/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-pptp/$userna
_CurrSal=$(echo $saldores - $pricepptp | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

cat >> /etc/ppp/chap-secrets <<EOF
"$userna" pptpd "$passw" *
EOF

# Update file attributes
chmod 600 /etc/ppp/chap-secrets*
echo -e "### $userna $exp">>"/var/lib/scrz-prem/data-user-pptp"
local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>         🔸 PPTP ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IP : $IPs\n"
env_msg+="Username : $userna\n"
env_msg+="Password : $passw\n"
env_msg+="Expired On : $data 🗓 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 30Days PPTP | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart pptpd > /dev/null 2>&1
return 0
fi
}

func_add_pptp2() {
file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
passw=$(sed -n '2 p' $file_user | cut -d' ' -f2)
data=$(sed -n '3 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)        
domain=$(cat /etc/$raycheck/domain)

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-pptp
echo "$userna:$data" >/etc/.maAsiss/info-user-pptp/$userna

cat >> /etc/ppp/chap-secrets <<EOF
"$userna" pptpd "$passw" *
EOF

# Update file attributes
chmod 600 /etc/ppp/chap-secrets*
echo -e "### $userna $exp">>"/var/lib/scrz-prem/data-user-pptp"
local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>         🔸 PPTP ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IP : $IPs\n"
env_msg+="Username : $userna\n"
env_msg+="Password : $passw\n"
env_msg+="Expired On : $data 🗓 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart pptpd > /dev/null 2>&1
return 0
}

pricepptp=$(grep -w "Price PPTP" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
urday=$(echo $pricepptp * 2 | bc )
if [ "$saldores" -lt "$urday" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-pptp
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_pptp
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_pptp/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-pptp/$userna
_CurrSal=$(echo $saldores - $urday | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

cat >> /etc/ppp/chap-secrets <<EOF
"$userna" pptpd "$passw" *
EOF

# Update file attributes
chmod 600 /etc/ppp/chap-secrets*
echo -e "### $userna $exp">>"/var/lib/scrz-prem/data-user-pptp"
local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>         🔸 PPTP ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IP : $IPs\n"
env_msg+="Username : $userna\n"
env_msg+="Password : $passw\n"
env_msg+="Expired On : $data 🗓 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 60Days PPTP | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart pptpd > /dev/null 2>&1
return 0
fi
}

del_pptp() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🗑 REMOVE USER PPTP 🗑\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_del_pptp() {
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    userna=$1
    if [[ "${message_from_id[$id]}" = "$Admin_ID" ]]; then
        exp=$(grep -E "^### " /var/lib/scrz-prem/data-user-pptp | cut -d ' ' -f 3 )
        sed -i '/^"'"$userna"'" pptpd/d' /etc/ppp/chap-secrets
        sed -i "/^### $userna $exp/d" /var/lib/scrz-prem/data-user-pptp
        chmod 600 /etc/ppp/chap-secrets* /etc/ipsec.d/passwd*
        datata=$(find /etc/.maAsiss/ -name $userna)
        for accc in "${datata[@]}"
        do
        rm $accc
        done
        systemctl restart pptpd > /dev/null 2>&1
    elif [[ "${message_from_id[$id]}" != "$Admin_ID" ]]; then
        [[ ! -e /etc/.maAsiss/db_reseller/${message_from_id}/user_pptp/$userna ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "⛔ THE USER DOES NOT EXIST ⛔")" \
                --parse_mode html
            _erro='1'      
            ShellBot.sendMessage --chat_id ${callack_query_message_chat_id[$id]} \
                 --text "Func Error Do Nothing" \
                 --reply_markup "$(ShellBot.ForceReply)"
            return 0
        }
        exp=$(grep -E "^### " /var/lib/scrz-prem/data-user-pptp | cut -d ' ' -f 3 )
        sed -i '/^"'"$userna"'" pptpd/d' /etc/ppp/chap-secrets
        sed -i "/^### $userna $exp/d" /var/lib/scrz-prem/data-user-pptp
        chmod 600 /etc/ppp/chap-secrets* /etc/ipsec.d/passwd*
        rm -f /etc/.maAsiss/db_reseller/${message_from_id}/user_pptp/$userna
        rm -f /etc/.maAsiss/info-user-pptp/$userna
        systemctl restart pptpd > /dev/null 2>&1
    fi
}

add_pptp_trial() {
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE TRIAL PPTP 👤\n\nHow many hours should it last ? EX: 1:" \
            --reply_markup "$(ShellBot.ForceReply)"
    elif [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]]; then
            ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "👤 CREATE TRIAL PPTP 👤\n\nHow many hours should it last ? EX: 1:" \
                --reply_markup "$(ShellBot.ForceReply)"       
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

func_add_pptp_trial() {
mkdir -p /etc/.maAsiss/info-user-pptp
    userna=$(echo Trial`</dev/urandom tr -dc A-Z0-9 | head -c4`)
    t_time=$1
    passw="1"
    domain=$(cat /etc/$raycheck/domain)
    exp=`date -d "2 days" +"%Y-%m-%d"`
    tuserdate=$(date '+%C%y/%m/%d' -d " +2 days")
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
       mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold
    }
    [[ -z $t_time ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e "⛔ error try again")" \
            --parse_mode html
        return 0
        _erro='1'
    }

[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    echo "$userna:$passw:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/user_pptp/$userna
    echo "$userna:$passw:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna
}
dir_teste="/etc/.maAsiss/db_reseller/${message_from_id}/user_pptp/$userna"
dir_teste2="/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna"
dates=`date`
cat <<-EOF >/etc/.maAsiss/$userna.sh
#!/bin/bash
# USER TRIAL PPTP by ${message_from_id} $dates
exp=\$(grep -E "^###" /var/lib/scrz-prem/data-user-pptp | cut -d ' ' -f 3 )
sed -i '/^"'"$userna"'" pptpd/d' /etc/ppp/chap-secrets
sed -i "/^### $userna $exp/d" /var/lib/scrz-prem/data-user-pptp
chmod 600 /etc/ppp/chap-secrets* /etc/ipsec.d/passwd*
rm -f /etc/.maAsiss/db_reseller/${message_from_id}/user_pptp/$userna
rm -f /etc/.maAsiss/info-user-pptp/$userna
systemctl restart pptpd > /dev/null 2>&1
[[ -e $dir_teste ]] && rm $dir_teste
[[ -e $dir_teste2 ]] && rm $dir_teste2
rm -f /etc/.maAsiss/$userna
rm -f /etc/.maAsiss/$userna.sh
EOF

chmod +x /etc/.maAsiss/$userna.sh
echo "/etc/.maAsiss/$userna.sh" | at now + $t_time hour >/dev/null 2>&1
[[ "$t_time" == '1' ]] && hrs="hour" || hrs="hours"          

cat >> /etc/ppp/chap-secrets <<EOF
"$userna" pptpd "$passw" *
EOF

# Update file attributes
chmod 600 /etc/ppp/chap-secrets*
echo -e "### $userna $exp">>"/var/lib/scrz-prem/data-user-pptp"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>         🔸 PPTP ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="IP : $IPs\n"
env_msg+="Username : $userna\n"
env_msg+="Password : $passw\n"
env_msg+="Expired On : $t_time $hrs ⏳ \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
    
systemctl restart pptpd > /dev/null 2>&1
return 0
}

list_member_pptp() {
   if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
      _result=$(grep -wE "^###" "/var/lib/scrz-prem/data-user-pptp" | cut -d ' ' -f2 | column -t | sort | uniq | wc -l)
      _results=$(grep -wE "^###" "/var/lib/scrz-prem/data-user-pptp" | cut -d ' ' -f2 | column -t | sort | uniq )
   elif [[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]]; then
      _result=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_pptp | wc -l)
      _results=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_pptp )
   else
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ ACCESS DENIED ⛔" \
                --parse_mode html
      return 0
   fi
   if [ "$_result" = "0" ]; then
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ YOU DONT HAVE ANY USER YET ⛔" \
                --parse_mode html
      return 0
   else
      ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
      ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
         --text "━━━━━━━━━━━━━━━━━━━━━\n 🟢 PPTP Member List 🟢\n━━━━━━━━━━━━━━━━━━━━━\n\n$_results\n\n━━━━━━━━━━━━━━━━━━━━━\n" \
         --parse_mode html
      return 0
   fi
}

unset menu_pptp
menu_pptp=''
ShellBot.InlineKeyboardButton --button 'menu_pptp' --line 1 --text 'Add PPTP' --callback_data '_add_pptp'
ShellBot.InlineKeyboardButton --button 'menu_pptp' --line 2 --text 'Delete PPTP' --callback_data '_delete_pptp'
ShellBot.InlineKeyboardButton --button 'menu_pptp' --line 3 --text 'Create Trial PPTP' --callback_data '_trial_pptp'
ShellBot.InlineKeyboardButton --button 'menu_pptp' --line 4 --text 'List Member PPTP' --callback_data '_member_pptp'
ShellBot.InlineKeyboardButton --button 'menu_pptp' --line 6 --text '🔙 Back 🔙' --callback_data '_gobackpptp'
ShellBot.regHandleFunction --function add_pptp --callback_data _add_pptp
ShellBot.regHandleFunction --function del_pptp --callback_data _delete_pptp
ShellBot.regHandleFunction --function add_pptp_trial --callback_data _trial_pptp
ShellBot.regHandleFunction --function list_member_pptp --callback_data _member_pptp
ShellBot.regHandleFunction --function admin_service_see --callback_data _gobackpptp
unset keyboardpptp
keyboardpptp="$(ShellBot.InlineKeyboardMarkup -b 'menu_pptp')"

unset res_menu_pptp
res_menu_pptp=''
ShellBot.InlineKeyboardButton --button 'res_menu_pptp' --line 1 --text '➕ Add PPTP ➕' --callback_data '_res_add_pptp'
ShellBot.InlineKeyboardButton --button 'res_menu_pptp' --line 3 --text '⏳ Create Trial PPTP ⏳' --callback_data '_res_trial_pptp'
ShellBot.InlineKeyboardButton --button 'res_menu_pptp' --line 4 --text '🟢 List Member PPTP 🟢' --callback_data '_res_member_pptp'
ShellBot.InlineKeyboardButton --button 'res_menu_pptp' --line 5 --text '🔙 Back 🔙' --callback_data '_res_gobackpptp'
ShellBot.regHandleFunction --function add_pptp --callback_data _res_add_pptp
ShellBot.regHandleFunction --function add_pptp_trial --callback_data _res_trial_pptp
ShellBot.regHandleFunction --function list_member_pptp --callback_data _res_member_pptp
ShellBot.regHandleFunction --function menu_reserv --callback_data _res_gobackpptp
unset keyboardpptpres
keyboardpptpres="$(ShellBot.InlineKeyboardMarkup -b 'res_menu_pptp')"

#====== ALL ABOUT TRGO =======#

res_trgo_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'res_menu_trgo')"
        return 0
    }
}

trgo_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_trgo')"
        return 0
    }
}

add_trgo() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE USER Trojan-GO 👤\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_add_trgo() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderTROJANGO ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Disable Order Trojan-Go" \
                    --parse_mode html
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                   --text "Func Error Do Nothing" \
                   --reply_markup "$(ShellBot.ForceReply)"
            return 0
    }
}

file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
data=$(sed -n '2 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)        
domain=$(cat /etc/$raycheck/domain)
trgo="$(cat /root/log-install.txt | grep -w "Trojan Go" | cut -d: -f2|sed 's/ //g')"

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-trgo
echo "$userna:$data" >/etc/.maAsiss/info-user-trgo/$userna

uuidR=$(cat /proc/sys/kernel/random/uuid)
uuid=$(cat /etc/trojan-go/idtrojango)
sed -i '/"'""$uuid""'"$/a\,"'""$uuidR""'"' /etc/trojan-go/config.json
echo -e "### $userna $exp $uuidR" | tee -a /etc/trojan-go/akun.conf
linktrgo="trojan-go://${uuidR}@${domain}:${trgo}/?sni=${domain}%26type=ws%26host=${domain}%26path=/scvps%26encryption=none#${userna}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>       🔸 TROJAN GO ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="User : $userna\n"
env_msg+="Expired On : $data 🗓 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $trgo\n"
env_msg+="Key : $uuidR\n"
env_msg+="Network : ws\n"
env_msg+="Path : /scvps\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TRGO: \n\n"
env_msg+="<code>$linktrgo</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart trojan-go > /dev/null 2>&1
return 0
}

pricetrgo=$(grep -w "Price Trojan-GO" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
if [ "$saldores" -lt "$pricetrgo" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-trgo
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_trgo
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_trgo/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-trgo/$userna
_CurrSal=$(echo $saldores - $pricetrgo | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

uuidR=$(cat /proc/sys/kernel/random/uuid)
uuid=$(cat /etc/trojan-go/idtrojango)
sed -i '/"'""$uuid""'"$/a\,"'""$uuidR""'"' /etc/trojan-go/config.json
echo -e "### $userna $exp $uuidR" | tee -a /etc/trojan-go/akun.conf
linktrgo="trojan-go://${uuidR}@${domain}:${trgo}/?sni=${domain}%26type=ws%26host=${domain}%26path=/scvps%26encryption=none#${userna}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>       🔸 TROJAN GO ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="User : $userna\n"
env_msg+="Expired On : $data 🗓 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $trgo\n"
env_msg+="Key : $uuidR\n"
env_msg+="Network : ws\n"
env_msg+="Path : /scvps\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TRGO: \n\n"
env_msg+="<code>$linktrgo</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 30Days TROJAN-GO | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart trojan-go > /dev/null 2>&1
return 0
fi
}

func_add_trgo2() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderTROJANGO ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Disable Order Trojan-Go" \
                    --parse_mode html
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                   --text "Func Error Do Nothing" \
                   --reply_markup "$(ShellBot.ForceReply)"
            return 0
    }
}

file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
data=$(sed -n '2 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)        
domain=$(cat /etc/$raycheck/domain)
trgo="$(cat /root/log-install.txt | grep -w "Trojan Go" | cut -d: -f2|sed 's/ //g')"

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-trgo
echo "$userna:$data" >/etc/.maAsiss/info-user-trgo/$userna

uuidR=$(cat /proc/sys/kernel/random/uuid)
uuid=$(cat /etc/trojan-go/idtrojango)
sed -i '/"'""$uuid""'"$/a\,"'""$uuidR""'"' /etc/trojan-go/config.json
echo -e "### $userna $exp $uuidR" | tee -a /etc/trojan-go/akun.conf
linktrgo="trojan-go://${uuidR}@${domain}:${trgo}/?sni=${domain}%26type=ws%26host=${domain}%26path=/scvps%26encryption=none#${userna}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>       🔸 TROJAN GO ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="User : $userna\n"
env_msg+="Expired On : $data 🗓 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $trgo\n"
env_msg+="Key : $uuidR\n"
env_msg+="Network : ws\n"
env_msg+="Path : /scvps\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TRGO: \n\n"
env_msg+="<code>$linktrgo</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart trojan-go > /dev/null 2>&1
return 0
}

pricetrgo=$(grep -w "Price Trojan-GO" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
urday=$(echo $pricetrgo * 2 | bc )
if [ "$saldores" -lt "$urday" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-trgo
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_trgo
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_trgo/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-trgo/$userna
_CurrSal=$(echo $saldores - $urday | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

uuidR=$(cat /proc/sys/kernel/random/uuid)
uuid=$(cat /etc/trojan-go/idtrojango)
sed -i '/"'""$uuid""'"$/a\,"'""$uuidR""'"' /etc/trojan-go/config.json
echo -e "### $userna $exp $uuidR" | tee -a /etc/trojan-go/akun.conf
linktrgo="trojan-go://${uuidR}@${domain}:${trgo}/?sni=${domain}%26type=ws%26host=${domain}%26path=/scvps%26encryption=none#${userna}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>       🔸 TROJAN GO ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="User : $userna\n"
env_msg+="Expired On : $data 🗓 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $trgo\n"
env_msg+="Key : $uuidR\n"
env_msg+="Network : ws\n"
env_msg+="Path : /scvps\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TRGO: \n\n"
env_msg+="<code>$linktrgo</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 60Days TROJAN-GO | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart trojan-go > /dev/null 2>&1
return 0
fi
}

del_trgo() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🗑 REMOVE USER Trojan-GO 🗑\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_del_trgo() {
    userna=$1
    if [[ "${message_from_id[$id]}" = "$Admin_ID" ]]; then
        exp=$(grep -E "^### $userna" "/etc/trojan-go/akun.conf" | cut -d ' ' -f 3 )
        xid=$(grep -E "^### $userna" "/etc/trojan-go/akun.conf" | cut -d ' ' -f 4 )
        echo "$xid" > /etc/trojan-go/tmp
        bcod=`cat /etc/trojan-go/tmp`
        sed -i '/'$bcod'/d' /etc/trojan-go/config.json
        sed -i "/^### $userna $exp $xid/d" /etc/trojan-go/akun.conf
        
        datata=$(find /etc/.maAsiss/ -name $userna)
        for accc in "${datata[@]}"
        do
        rm $accc
        done
        rm -f /etc/trojan-go/tmp
        systemctl restart trojan-go > /dev/null 2>&1
    elif [[ "${message_from_id[$id]}" != "$Admin_ID" ]]; then
        [[ ! -e /etc/.maAsiss/db_reseller/${message_from_id}/user_trgo/$userna ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "⛔ THE USER DOES NOT EXIST ⛔")" \
                --parse_mode html
            _erro='1'      
            ShellBot.sendMessage --chat_id ${callack_query_message_chat_id[$id]} \
                 --text "Func Error Do Nothing" \
                 --reply_markup "$(ShellBot.ForceReply)"
            return 0
        }
        exp=$(grep -E "^### $userna" "/etc/trojan-go/akun.conf" | cut -d ' ' -f 3 )
        xid=$(grep -E "^### $userna" "/etc/trojan-go/akun.conf" | cut -d ' ' -f 4 )
        echo "$xid" > /etc/trojan-go/tmp
        bcod=`cat /etc/trojan-go/tmp`
        sed -i '/'$bcod'/d' /etc/trojan-go/config.json
        sed -i "/^### $userna $exp $xid/d" /etc/trojan-go/akun.conf
        
        rm -f /etc/.maAsiss/db_reseller/${message_from_id}/user_trgo/$userna
        rm -f /etc/.maAsiss/info-user-trgo/$userna
        rm -f /etc/trojan-go/tmp
        systemctl restart trojan-go > /dev/null 2>&1
    fi
}

add_trgo_trial() {
    if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
        ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE TRIAL Trojan-GO 👤\n\nHow many hours should it last ? EX: 1:" \
            --reply_markup "$(ShellBot.ForceReply)"
    elif [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]]; then
            ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                --text "👤 CREATE TRIAL Trojan-GO 👤\n\nHow many hours should it last ? EX: 1:" \
                --reply_markup "$(ShellBot.ForceReply)"       
    else
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    fi
}

func_add_trgo_trial() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderTROJANGO ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Disable Order Trojan-Go" \
                    --parse_mode html
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                   --text "Func Error Do Nothing" \
                   --reply_markup "$(ShellBot.ForceReply)"
            return 0
    }
}

mkdir -p /etc/.maAsiss/info-user-trgo
    userna=$(echo Trial`</dev/urandom tr -dc A-Z0-9 | head -c4`)
    t_time=$1
    domain=$(cat /etc/$raycheck/domain)
    trgo="$(cat /root/log-install.txt | grep -w "Trojan Go" | cut -d: -f2|sed 's/ //g')"
    
    exp=`date -d "2 days" +"%Y-%m-%d"`
    tuserdate=$(date '+%C%y/%m/%d' -d " +2 days")
    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
       mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold
    }
    [[ -z $t_time ]] && {
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "$(echo -e "⛔ error try again")" \
            --parse_mode html
        return 0
        _erro='1'
    }

[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    echo "$userna:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/user_trgo/$userna
    echo "$userna:$exp" >/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna
}
dir_teste="/etc/.maAsiss/db_reseller/${message_from_id}/user_trgo/$userna"
dir_teste2="/etc/.maAsiss/db_reseller/${message_from_id}/trial-fold/$userna"
dates=`date`
cat <<-EOF >/etc/.maAsiss/$userna.sh
#!/bin/bash
# USER TRIAL TRGO by ${message_from_id} $dates
exp=\$(grep -E "^### $userna" "/etc/trojan-go/akun.conf" | cut -d ' ' -f 3)
xid=\$(grep -E "^### $userna" "/etc/trojan-go/akun.conf" | cut -d ' ' -f 4)
echo "\$xid" > /etc/trojan-go/tmp
bcod=\$(cat /etc/trojan-go/tmp)
sed -i '/'\$bcod'/d' /etc/trojan-go/config.json
sed -i "/^### $userna \$exp \$xid/d" /etc/trojan-go/akun.conf

rm -f /etc/.maAsiss/db_reseller/${message_from_id}/user_trgo/$userna
rm -f /etc/.maAsiss/info-user-trgo/$userna
rm -f /etc/trojan-go/tmp
systemctl restart trojan-go > /dev/null 2>&1
[[ -e $dir_teste ]] && rm $dir_teste
[[ -e $dir_teste2 ]] && rm $dir_teste2
rm -f /etc/.maAsiss/$userna
rm -f /etc/.maAsiss/$userna.sh
EOF

chmod +x /etc/.maAsiss/$userna.sh
echo "/etc/.maAsiss/$userna.sh" | at now + $t_time hour >/dev/null 2>&1
[[ "$t_time" == '1' ]] && hrs="hour" || hrs="hours"          

uuidR=$(cat /proc/sys/kernel/random/uuid)
uuid=$(cat /etc/trojan-go/idtrojango)
sed -i '/"'""$uuid""'"$/a\,"'""$uuidR""'"' /etc/trojan-go/config.json
echo -e "### $userna $exp $uuidR" | tee -a /etc/trojan-go/akun.conf
linktrgo="trojan-go://${uuidR}@${domain}:${trgo}/?sni=${domain}%26type=ws%26host=${domain}%26path=/scvps%26encryption=none#${userna}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>       🔸 TROJAN GO ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="User : $userna\n"
env_msg+="Expired On : $t_time $hrs ⏳ \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $trgo\n"
env_msg+="Key : $uuidR\n"
env_msg+="Network : ws\n"
env_msg+="Path : /scvps\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TRGO: \n\n"
env_msg+="<code>$linktrgo</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart trojan-go > /dev/null 2>&1
return 0
}

list_member_trgo() {
   if [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]]; then
      _result=$(grep -E "^### " "/etc/trojan-go/akun.conf" | cut -d ' ' -f2 | column -t | sort | uniq | wc -l)
      _results=$(grep -E "^### " "/etc/trojan-go/akun.conf" | cut -d ' ' -f2 | column -t | sort | uniq )
   elif [[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]]; then
      _result=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_trgo | wc -l)
      _results=$(ls /etc/.maAsiss/db_reseller/${callback_query_from_id}/user_trgo )
   else
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ ACCESS DENIED ⛔" \
                --parse_mode html
      return 0
   fi
   if [ "$_result" = "0" ]; then
      ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
                --text "⛔ YOU DONT HAVE ANY USER YET ⛔" \
                --parse_mode html
      return 0
   else
      ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
      ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
         --text "━━━━━━━━━━━━━━━━━━━━━\n 🟢 Trojan-GO Member List 🟢\n━━━━━━━━━━━━━━━━━━━━━\n\n$_results\n\n━━━━━━━━━━━━━━━━━━━━━\n" \
         --parse_mode html
      return 0
   fi
}

unset menu_trgo
menu_trgo=''
ShellBot.InlineKeyboardButton --button 'menu_trgo' --line 1 --text 'Add Trojan-GO' --callback_data '_add_trgo'
ShellBot.InlineKeyboardButton --button 'menu_trgo' --line 2 --text 'Delete Trojan-GO' --callback_data '_delete_trgo'
ShellBot.InlineKeyboardButton --button 'menu_trgo' --line 3 --text 'Create Trial Trojan-GO' --callback_data '_trial_trgo'
ShellBot.InlineKeyboardButton --button 'menu_trgo' --line 4 --text 'List Member Trojan-GO' --callback_data '_member_trgo'
ShellBot.InlineKeyboardButton --button 'menu_trgo' --line 6 --text '🔙 Back 🔙' --callback_data '_gobacktrgo'
ShellBot.regHandleFunction --function add_trgo --callback_data _add_trgo
ShellBot.regHandleFunction --function del_trgo --callback_data _delete_trgo
ShellBot.regHandleFunction --function add_trgo_trial --callback_data _trial_trgo
ShellBot.regHandleFunction --function list_member_trgo --callback_data _member_trgo
ShellBot.regHandleFunction --function admin_service_see --callback_data _gobacktrgo
unset keyboardtrgo
keyboardtrgo="$(ShellBot.InlineKeyboardMarkup -b 'menu_trgo')"

unset res_menu_trgo
res_menu_trgo=''
ShellBot.InlineKeyboardButton --button 'res_menu_trgo' --line 1 --text '➕ Add Trojan-GO ➕' --callback_data '_res_add_trgo'
ShellBot.InlineKeyboardButton --button 'res_menu_trgo' --line 3 --text '⏳ Create Trial Trojan-GO ⏳' --callback_data '_res_trial_trgo'
ShellBot.InlineKeyboardButton --button 'res_menu_trgo' --line 4 --text '🟢 List Member Trojan-GO 🟢' --callback_data '_res_member_trgo'
ShellBot.InlineKeyboardButton --button 'res_menu_trgo' --line 5 --text '🔙 Back 🔙' --callback_data '_res_gobacktrgo'
ShellBot.regHandleFunction --function add_trgo --callback_data _res_add_trgo
ShellBot.regHandleFunction --function add_trgo_trial --callback_data _res_trial_trgo
ShellBot.regHandleFunction --function list_member_trgo --callback_data _res_member_trgo
ShellBot.regHandleFunction --function menu_reserv --callback_data _res_gobacktrgo
unset keyboardtrgores
keyboardtrgores="$(ShellBot.InlineKeyboardMarkup -b 'res_menu_trgo')"

#====== ALL ABOUT XRAY =======#

res_xray_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'res_menu_xray')"
        return 0
    }
}

xray_menus() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "SELECT AN OPTION BELOW:" \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'menu_xray')"
        return 0
    }
}

add_xray() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "👤 CREATE USER Xray 👤\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_add_xray() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderXRAY ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Disable Order Xray" \
                    --parse_mode html
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                   --text "Func Error Do Nothing" \
                   --reply_markup "$(ShellBot.ForceReply)"
            return 0
    }
}

file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
data=$(sed -n '2 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)        
domain=$(cat /etc/$raycheck/domain)
xray="$(cat /root/log-install.txt | grep -w "VLess TCP XTLS" | cut -d: -f2|sed 's/ //g')"

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-xray
echo "$userna:$data" >/etc/.maAsiss/info-user-xray/$userna

xCho='xtls-rprx-direct'
uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vlessXTLS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","flow": "'""$xCho""'","email": "'""$userna""'"' /usr/local/etc/xtls/config.json

vlessTcpXtls="vless://${uuid}@${domain}:$xray?path=/%26security=xtls%26encryption=none%26flow=${xCho}%26type=tcp#${userna}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>    🔸 VLESS XTLS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $xray\n"
env_msg+="ID : <code>$uuid</code>\n"
env_msg+="Encryption : none\n"
env_msg+="Network : tcp\n"
env_msg+="Flow : $xCho\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link : \n"
env_msg+="<code>$vlessTcpXtls</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 30Days VLESS | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart xtls > /dev/null 2>&1
return 0
}

pricexray=$(grep -w "Price Xray" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
if [ "$saldores" -lt "$pricexray" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-xray
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_xray
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_xray/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-xray/$userna
_CurrSal=$(echo $saldores - $pricexray | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

xCho='xtls-rprx-direct'
uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vlessXTLS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","flow": "'""$xCho""'","email": "'""$userna""'"' /usr/local/etc/xtls/config.json

vlessTcpXtls="vless://${uuid}@${domain}:$xray?path=/%26security=xtls%26encryption=none%26flow=${xCho}%26type=tcp#${userna}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>    🔸 VLESS XTLS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $xray\n"
env_msg+="ID : <code>$uuid</code>\n"
env_msg+="Encryption : none\n"
env_msg+="Network : tcp\n"
env_msg+="Flow : $xCho\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link : \n"
env_msg+="<code>$vlessTcpXtls</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 30Days VLESS | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart xtls > /dev/null 2>&1
return 0
fi
}

func_add_xray2() {
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
    [[ -f /etc/.maAsiss/.cache/DisableOrderXRAY ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                    --text "⛔ Disable Order Xray" \
                    --parse_mode html
            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                   --text "Func Error Do Nothing" \
                   --reply_markup "$(ShellBot.ForceReply)"
            return 0
    }
}

file_user=$1
userna=$(sed -n '1 p' $file_user | cut -d' ' -f2)
data=$(sed -n '2 p' $file_user | cut -d' ' -f2)
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)        
domain=$(cat /etc/$raycheck/domain)
xray="$(cat /root/log-install.txt | grep -w "VLess TCP XTLS" | cut -d: -f2|sed 's/ //g')"

[[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
mkdir -p /etc/.maAsiss/info-user-xray
echo "$userna:$data" >/etc/.maAsiss/info-user-xray/$userna

xCho='xtls-rprx-direct'
uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vlessXTLS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","flow": "'""$xCho""'","email": "'""$userna""'"' /usr/local/etc/xtls/config.json

vlessTcpXtls="vless://${uuid}@${domain}:$xray?path=/%26security=xtls%26encryption=none%26flow=${xCho}%26type=tcp#${userna}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>    🔸 VLESS XTLS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $xray\n"
env_msg+="ID : <code>$uuid</code>\n"
env_msg+="Encryption : none\n"
env_msg+="Network : tcp\n"
env_msg+="Flow : $xCho\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link : \n"
env_msg+="<code>$vlessTcpXtls</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 60Days VLESS | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart xtls > /dev/null 2>&1
return 0
}

pricexray=$(grep -w "Price Xray" /etc/.maAsiss/price | awk '{print $NF}')
saldores=$(grep -w "Saldo_Reseller" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id} | awk '{print $NF}')
urday=$(echo $pricexray * 2 | bc )
if [ "$saldores" -lt "$urday" ]; then
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "⛔ Your Balance Not Enough ⛔" \
    --parse_mode html
return 0
else
mkdir -p /etc/.maAsiss/info-user-xray
mkdir -p /etc/.maAsiss/db_reseller/${message_from_id}/user_xray
echo "$userna:$data" >/etc/.maAsiss/db_reseller/${message_from_id}/user_xray/$userna
echo "$userna:$data" >/etc/.maAsiss/info-user-xray/$userna
_CurrSal=$(echo $saldores - $pricexray | bc)
sed -i "/Saldo_Reseller/c\Saldo_Reseller: $_CurrSal" /etc/.maAsiss/db_reseller/${message_from_id}/${message_from_id}
sed -i "/${message_from_id}/c\USER: ${message_from_id} SALDO: $_CurrSal TYPE: reseller" $User_Active

xCho='xtls-rprx-direct'
uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vlessXTLS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","flow": "'""$xCho""'","email": "'""$userna""'"' /usr/local/etc/xtls/config.json

vlessTcpXtls="vless://${uuid}@${domain}:$xray?path=/%26security=xtls%26encryption=none%26flow=${xCho}%26type=tcp#${userna}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>    🔸 VLESS XTLS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $xray\n"
env_msg+="ID : <code>$uuid</code>\n"
env_msg+="Encryption : none\n"
env_msg+="Network : tcp\n"
env_msg+="Flow : $xCho\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link : \n"
env_msg+="<code>$vlessTcpXtls</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
echo "$userna 60Days VLESS | ${message_from_username}" >> /etc/.maAsiss/log_res

ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart xtls > /dev/null 2>&1
return 0
fi
}

del_xray() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🗑 REMOVE USER Xray 🗑\n\nUsername:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

func_del_xray() {
    userna=$1
    if [[ "${message_from_id[$id]}" = "$Admin_ID" ]]; then
        exp=$(grep -wE "^#& $user" "/usr/local/etc/xtls/config.json" | cut -d ' ' -f 3 | sort | uniq)
        sed -i "/^#& $user $exp/,/^},{/d" /usr/local/etc/xtls/config.json        
        datata=$(find /etc/.maAsiss/ -name $userna)
        for accc in "${datata[@]}"
        do
        rm $accc
        done
        systemctl restart xtls > /dev/null 2>&1
    elif [[ "${message_from_id[$id]}" != "$Admin_ID" ]]; then
        [[ ! -e /etc/.maAsiss/db_reseller/${message_from_id}/user_xray/$userna ]] && {
            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                --text "$(echo -e "⛔ THE USER DOES NOT EXIST ⛔")" \
                --parse_mode html
            _erro='1'      
            ShellBot.sendMessage --chat_id ${callack_query_message_chat_id[$id]} \
                 --text "Func Error Do Nothing" \
                 --reply_markup "$(ShellBot.ForceReply)"
            return 0
        }
        exp=$(grep -wE "^#& $user" "/usr/local/etc/xtls/config.json" | cut -d ' ' -f 3 | sort | uniq)
        sed -i "/^#& $user $exp/,/^},{/d" /usr/local/etc/xtls/config.json        
        
        rm -f /etc/.maAsiss/db_reseller/${message_from_id}/user_xray/$userna
        rm -f /etc/.maAsiss/info-user-xray/$userna
        systemctl restart xtls > /dev/null 2>&1
    fi
}


unset menu_xray
menu_xray=''
ShellBot.InlineKeyboardButton --button 'menu_xray' --line 1 --text 'Add Xray' --callback_data '_add_xray'
ShellBot.InlineKeyboardButton --button 'menu_xray' --line 2 --text 'Delete Xray' --callback_data '_delete_xray'
#ShellBot.InlineKeyboardButton --button 'menu_xray' --line 3 --text 'Create Trial Xray' --callback_data '_trial_xray'
#ShellBot.InlineKeyboardButton --button 'menu_xray' --line 4 --text 'List Member Xray' --callback_data '_member_xray'
ShellBot.InlineKeyboardButton --button 'menu_xray' --line 6 --text '🔙 Back 🔙' --callback_data '_gobackxray'
ShellBot.regHandleFunction --function add_xray --callback_data _add_xray
ShellBot.regHandleFunction --function del_xray --callback_data _delete_xray
#ShellBot.regHandleFunction --function add_xray_trial --callback_data _trial_xray
#ShellBot.regHandleFunction --function list_member_xray --callback_data _member_xray
ShellBot.regHandleFunction --function admin_service_see --callback_data _gobackxray
unset keyboardxray
keyboardxray="$(ShellBot.InlineKeyboardMarkup -b 'menu_xray')"

unset res_menu_xray
res_menu_xray=''
ShellBot.InlineKeyboardButton --button 'res_menu_xray' --line 1 --text '➕ Add Xray ➕' --callback_data '_res_add_xray'
#ShellBot.InlineKeyboardButton --button 'res_menu_xray' --line 3 --text '⏳ Create Trial Xray ⏳' --callback_data '_res_trial_xray'
#ShellBot.InlineKeyboardButton --button 'res_menu_xray' --line 4 --text '🟢 List Member Xray 🟢' --callback_data '_res_member_xray'
ShellBot.InlineKeyboardButton --button 'res_menu_xray' --line 5 --text '🔙 Back 🔙' --callback_data '_res_gobackxray'
ShellBot.regHandleFunction --function add_xray --callback_data _res_add_xray
#ShellBot.regHandleFunction --function add_xray_trial --callback_data _res_trial_xray
#ShellBot.regHandleFunction --function list_member_xray --callback_data _res_member_xray
ShellBot.regHandleFunction --function menu_reserv --callback_data _res_gobackxray
unset keyboardxrayres
keyboardxrayres="$(ShellBot.InlineKeyboardMarkup -b 'res_menu_xray')"


#====== SETTINGS DATABASE =======#

Ganti_Harga() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "💰 Change Price 💰\n\nPrice SSH:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

public_mod() {
[[ -f /etc/.maAsiss/public_mode/settings ]] && {
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
     --text "✅ Public mode is already on ✅"
return 0
}
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        [[ ! -d /etc/.maAsiss/public_mode ]] && mkdir /etc/.maAsiss/public_mode
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "🌐 Enable Public Mode 🌐\n\nExpired Days [ex:3]:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

public_mod_off() {
[[ ! -f /etc/.maAsiss/public_mode/settings ]] && {
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
     --text "⛔ Public mode is currently off ⛔"
return 0
} || {
rm -rf /etc/.maAsiss/public_mode
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
   --text "✅ Success disable public mode ✅"
return 0
}   
}

Add_Info_Reseller() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "📢 Info for reseller 📢\n\ntype your information:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

unblock_usr() {
    [[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] && {
        ShellBot.deleteMessage	--chat_id ${callback_query_message_chat_id[$id]} \
              --message_id ${callback_query_message_message_id[$id]}
        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
            --text "😤 Unblock user 😤\n\nInput user ID to unblock:" \
            --reply_markup "$(ShellBot.ForceReply)"
    } || {
        ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
            --text "⛔ ACCESS DENIED ⛔"
        return 0
    }
}

Del_Info_Reseller() {
[[ ! -f /etc/.maAsiss/update-info ]] && {
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
     --text "⛔ No Information Available ⛔"
return 0
} || {
rm -f /etc/.maAsiss/update-info
ShellBot.answerCallbackQuery --callback_query_id ${callback_query_id[$id]} \
     --text "✅ Success Delete Information ✅"
return 0
}   
}

admin_server() {
[[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "Select Option Below:" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'back_menu_admin')"
        return 0
    }
}


#======= MAIN MENU =========
see_sys() {
        systemctl is-active --quiet stunnel4 && stsstn="Running 🟢" || stsstn="Not Running 🔴"
        systemctl is-active --quiet dropbear && stsdb="Running 🟢" || stsdb="Not Running 🔴"
        systemctl is-active --quiet $raycheck && stsray="Running 🟢" || stsray="Not Running 🔴"
        systemctl is-active --quiet trojan-go && ststrgo="Running 🟢" || ststrgo="Not Running 🔴"
        systemctl is-active --quiet wg-quick@wg0 && stswg="Running 🟢" || stswg="Not Running 🔴"
        systemctl is-active --quiet shadowsocks-libev && stsss="Running 🟢" || stsss="Not Running 🔴"
        systemctl is-active --quiet ssrmu && stsssr="Running 🟢" || stsssr="Not Running 🔴"
        systemctl is-active --quiet accel-ppp && stssstp="Running 🟢" || stssstp="Not Running 🔴"
        systemctl is-active --quiet pptpd && stspptp="Running 🟢" || stspptp="Not Running 🔴"
        systemctl is-active --quiet xl2tpd && stsl2tp="Running 🟢" || stsl2tp="Not Running 🔴"

        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="🟢 Status Service : \n\n"
        env_msg+="<code>Dropbear     : $stsdb\n"
        env_msg+="Stunnel      : $stsstn\n"
        env_msg+="VMess        : $stsray\n"
        env_msg+="VLess        : $stsray\n"
        env_msg+="Trojan       : $stsray\n"
        env_msg+="Trojan-Go    : $ststrgo\n"
        env_msg+="Wireguard    : $stswg\n"
        env_msg+="SSTP         : $stssstp\n"
        env_msg+="PPTP         : $stspptp\n"
        env_msg+="L2TP         : $stsl2tp\n"
        env_msg+="Shadowsocks  : $stsss\n"
        env_msg+="Shadowsocks-R: $stsssr</code>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
[[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'back_menu_admin')"
        return 0
    }
}

sets_menu() {
        local env_msg
        env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
        env_msg+="<b> WELCOME TO BOT $nameStore</b>\n"
        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
[[ "${callback_query_from_id[$id]}" == "$Admin_ID" ]] || [[ "$(grep -wc ${callback_query_from_id} $User_Active)" != '0' ]] && {
        ShellBot.editMessageText --chat_id ${callback_query_message_chat_id[$id]} \
            --message_id ${callback_query_message_message_id[$id]} \
            --text "$env_msg" \
            --parse_mode html \
            --reply_markup "$(ShellBot.InlineKeyboardMarkup --button 'sett_menus')"
        return 0
    }
}


unset menuzzz
menuzzz=''
ShellBot.InlineKeyboardButton --button 'menuzzz' --line 1 --text '👨‍🦱 Add Reseller 👨‍🦱' --callback_data '_add_res'
ShellBot.InlineKeyboardButton --button 'menuzzz' --line 2 --text '💰 Top Up Balance 💰' --callback_data '_top_up_res'
ShellBot.InlineKeyboardButton --button 'menuzzz' --line 3 --text '📃 List %26 Info Reseller 📃' --callback_data '_list_res'
ShellBot.InlineKeyboardButton --button 'menuzzz' --line 4 --text '🗑 Remove Reseller 🗑' --callback_data '_del_res'
ShellBot.InlineKeyboardButton --button 'menuzzz' --line 5 --text '🌀 Reset Saldo Reseller 🌀' --callback_data '_reset_res'
ShellBot.InlineKeyboardButton --button 'menuzzz' --line 10 --text '🔙 Back 🔙' --callback_data '_gobakcuy'
ShellBot.regHandleFunction --function add_res --callback_data _add_res
ShellBot.regHandleFunction --function topup_res --callback_data _top_up_res
ShellBot.regHandleFunction --function func_list_res --callback_data _list_res
ShellBot.regHandleFunction --function del_res --callback_data _del_res
ShellBot.regHandleFunction --function reset_saldo_res --callback_data _reset_res
ShellBot.regHandleFunction --function menu_func_cb --callback_data _gobakcuy
unset keyboardzz
keyboardzz="$(ShellBot.InlineKeyboardMarkup -b 'menuzzz')"


unset menu_adm_ser
menu_adm_ser=''
ShellBot.InlineKeyboardButton --button 'menu_adm_ser' --line 1 --text '• Menu SSH •' --callback_data '_menussh'
ShellBot.InlineKeyboardButton --button 'menu_adm_ser' --line 2 --text '• Menu VMess •' --callback_data '_menuv2ray'
ShellBot.InlineKeyboardButton --button 'menu_adm_ser' --line 1 --text '• Menu Trojan •' --callback_data '_menutrojan'
ShellBot.InlineKeyboardButton --button 'menu_adm_ser' --line 2 --text '• Menu VLess •' --callback_data '_menuvless'
ShellBot.InlineKeyboardButton --button 'menu_adm_ser' --line 3 --text '• Menu WireGuard •' --callback_data '_menuwg'
ShellBot.InlineKeyboardButton --button 'menu_adm_ser' --line 3 --text '• Menu ShadowSock •' --callback_data '_menuss'
ShellBot.InlineKeyboardButton --button 'menu_adm_ser' --line 4 --text '• Menu ShadowSock-R •' --callback_data '_menussr'
ShellBot.InlineKeyboardButton --button 'menu_adm_ser' --line 4 --text '• Menu SSTP •' --callback_data '_menusstp'
ShellBot.InlineKeyboardButton --button 'menu_adm_ser' --line 5 --text '• Menu L2TP •' --callback_data '_menul2tp'
ShellBot.InlineKeyboardButton --button 'menu_adm_ser' --line 5 --text '• Menu PPTP •' --callback_data '_menupptp'
ShellBot.InlineKeyboardButton --button 'menu_adm_ser' --line 6 --text '• Menu Trojan-GO •' --callback_data '_menutrgo'
ShellBot.InlineKeyboardButton --button 'menu_adm_ser' --line 6 --text '• Menu Xray •' --callback_data '_menuxray'
ShellBot.InlineKeyboardButton --button 'menu_adm_ser' --line 7 --text '🔙 Back 🔙' --callback_data '_mebck'
ShellBot.regHandleFunction --function ssh_menus --callback_data _menussh
ShellBot.regHandleFunction --function v2ray_menus --callback_data _menuv2ray
ShellBot.regHandleFunction --function trojan_menus --callback_data _menutrojan
ShellBot.regHandleFunction --function vless_menus --callback_data _menuvless
ShellBot.regHandleFunction --function wg_menus --callback_data _menuwg
ShellBot.regHandleFunction --function ss_menus --callback_data _menuss
ShellBot.regHandleFunction --function ssr_menus --callback_data _menussr
ShellBot.regHandleFunction --function sstp_menus --callback_data _menusstp
ShellBot.regHandleFunction --function l2tp_menus --callback_data _menul2tp
ShellBot.regHandleFunction --function pptp_menus --callback_data _menupptp
ShellBot.regHandleFunction --function trgo_menus --callback_data _menutrgo
ShellBot.regHandleFunction --function xray_menus --callback_data _menuxray
ShellBot.regHandleFunction --function menu_func_cb --callback_data _mebck
unset menu_adm_ser1
menu_adm_ser1="$(ShellBot.InlineKeyboardMarkup -b 'menu_adm_ser')"


unset list_bck_adm
list_bck_adm=''
ShellBot.InlineKeyboardButton --button 'list_bck_adm' --line 1 --text '🔙 Back 🔙' --callback_data 'list_bck_'
ShellBot.regHandleFunction --function res_menus --callback_data list_bck_
unset list_bck_adm1
list_bck_adm1="$(ShellBot.InlineKeyboardMarkup -b 'list_bck_adm')"


unset status_disable
status_disable=''
ShellBot.InlineKeyboardButton --button 'status_disable' --line 1 --text '💡 How To Use 💡' --callback_data '_how_to'
ShellBot.InlineKeyboardButton --button 'status_disable' --line 2 --text '🔙 Back 🔙' --callback_data '_stsbck'
ShellBot.regHandleFunction --function how_to_order --callback_data _how_to
ShellBot.regHandleFunction --function menu_func_cb --callback_data _stsbck
unset status_disable1
status_disable1="$(ShellBot.InlineKeyboardMarkup -b 'status_disable')"

unset status_how_to
status_how_to=''
ShellBot.InlineKeyboardButton --button 'status_how_to' --line 1 --text '🔙 Back 🔙' --callback_data '_howbck'
ShellBot.regHandleFunction --function status_order --callback_data _howbck
unset status_how_to1
status_how_to1="$(ShellBot.InlineKeyboardMarkup -b 'status_how_to')"

unset sett_menus
sett_menus=''
ShellBot.InlineKeyboardButton --button 'sett_menus' --line 1 --text '🔒 Status Order 🔒' --callback_data '_orderfo'
ShellBot.InlineKeyboardButton --button 'sett_menus' --line 1 --text '💰 Change Price 💰' --callback_data '_price'
ShellBot.InlineKeyboardButton --button 'sett_menus' --line 2 --text '🤵 Reseller 🤵' --callback_data '_ressssseller'
ShellBot.InlineKeyboardButton --button 'sett_menus' --line 2 --text '✍️ See Log Reseller ✍️' --callback_data '_seelog'
ShellBot.InlineKeyboardButton --button 'sett_menus' --line 3 --text '🌐 OpenPublic 🌐' --callback_data '_publicmode'
ShellBot.InlineKeyboardButton --button 'sett_menus' --line 3 --text '📛 DisablePublic 📛' --callback_data '_publicmodeoff'
ShellBot.InlineKeyboardButton --button 'sett_menus' --line 4 --text '🔔 Add Info 🔔' --callback_data '_addinfo'
ShellBot.InlineKeyboardButton --button 'sett_menus' --line 4 --text '🔕 Del Info 🔕' --callback_data '_delinfo'
ShellBot.InlineKeyboardButton --button 'sett_menus' --line 10 --text '🔙 Back 🔙' --callback_data '_setssbck'
ShellBot.regHandleFunction --function status_order --callback_data _orderfo
ShellBot.regHandleFunction --function Add_Info_Reseller --callback_data _addinfo
ShellBot.regHandleFunction --function Del_Info_Reseller --callback_data _delinfo
ShellBot.regHandleFunction --function Ganti_Harga --callback_data _price
ShellBot.regHandleFunction --function res_menus --callback_data _ressssseller
ShellBot.regHandleFunction --function see_log --callback_data _seelog
ShellBot.regHandleFunction --function public_mod --callback_data _publicmode
ShellBot.regHandleFunction --function public_mod_off --callback_data _publicmodeoff
ShellBot.regHandleFunction --function menu_func_cb --callback_data _setssbck
unset sett_menus1
sett_menus1="$(ShellBot.InlineKeyboardMarkup -b 'sett_menus')"

unset menu
menu=''
ShellBot.InlineKeyboardButton --button 'menu' --line 1 --text '❇️ Open Service ❇️️' --callback_data '_openserv'
ShellBot.InlineKeyboardButton --button 'menu' --line 1 --text '🟢 Status Service 🟢️️' --callback_data '_stsserv'
ShellBot.InlineKeyboardButton --button 'menu' --line 2 --text '📋 Current Price 📋' --callback_data '_priceinfo'
ShellBot.InlineKeyboardButton --button 'menu' --line 2 --text '⚙️ Settings Menu ⚙️' --callback_data '_menusettss'
ShellBot.InlineKeyboardButton --button 'menu' --line 10 --text '⚠️ Unblock User ⚠️' --callback_data '_unblck'
ShellBot.regHandleFunction --function admin_service_see --callback_data _openserv
ShellBot.regHandleFunction --function see_sys --callback_data _stsserv
ShellBot.regHandleFunction --function admin_price_see --callback_data _priceinfo
ShellBot.regHandleFunction --function sets_menu --callback_data _menusettss
ShellBot.regHandleFunction --function unblock_usr --callback_data _unblck
unset keyboard1
keyboard1="$(ShellBot.InlineKeyboardMarkup -b 'menu')"

unset menu_re_ser
menu_re_ser=''
ShellBot.InlineKeyboardButton --button 'menu_re_ser' --line 1 --text '• SSH •' --callback_data '_res_ssh_menu'
ShellBot.InlineKeyboardButton --button 'menu_re_ser' --line 2 --text '• VMess •' --callback_data '_res_v2ray_menus'
ShellBot.InlineKeyboardButton --button 'menu_re_ser' --line 1 --text '• Trojan •' --callback_data '_res_trojan_menus'
ShellBot.InlineKeyboardButton --button 'menu_re_ser' --line 2 --text '• VLess •' --callback_data '_res_vless_menus'
ShellBot.InlineKeyboardButton --button 'menu_re_ser' --line 1 --text '• WireGuard •' --callback_data '_res_wg_menus'
ShellBot.InlineKeyboardButton --button 'menu_re_ser' --line 6 --text '• ShadowSocks •' --callback_data '_res_ss_menus'
ShellBot.InlineKeyboardButton --button 'menu_re_ser' --line 6 --text '• ShadowSocks-R •' --callback_data '_res_ssr_menus'
ShellBot.InlineKeyboardButton --button 'menu_re_ser' --line 5 --text '• SSTP •' --callback_data '_res_sstp_menus'
ShellBot.InlineKeyboardButton --button 'menu_re_ser' --line 5 --text '• L2TP •' --callback_data '_res_l2tp_menus'
ShellBot.InlineKeyboardButton --button 'menu_re_ser' --line 5 --text '• PPTP •' --callback_data '_res_pptp_menus'
ShellBot.InlineKeyboardButton --button 'menu_re_ser' --line 2 --text '• TRGO •' --callback_data '_res_trgo_menus'
ShellBot.InlineKeyboardButton --button 'menu_re_ser' --line 7 --text '• Xray •' --callback_data '_res_xray_menus'
ShellBot.InlineKeyboardButton --button 'menu_re_ser' --line 10 --text '🔙 Back 🔙' --callback_data 'clses_ser_res'
ShellBot.regHandleFunction --function res_ssh_menu --callback_data _res_ssh_menu
ShellBot.regHandleFunction --function res_v2ray_menus --callback_data _res_v2ray_menus
ShellBot.regHandleFunction --function res_trojan_menus --callback_data _res_trojan_menus
ShellBot.regHandleFunction --function res_vless_menus --callback_data _res_vless_menus
ShellBot.regHandleFunction --function res_wg_menus --callback_data _res_wg_menus
ShellBot.regHandleFunction --function res_ss_menus --callback_data _res_ss_menus
ShellBot.regHandleFunction --function res_ssr_menus --callback_data _res_ssr_menus
ShellBot.regHandleFunction --function res_sstp_menus --callback_data _res_sstp_menus
ShellBot.regHandleFunction --function res_l2tp_menus --callback_data _res_l2tp_menus
ShellBot.regHandleFunction --function res_pptp_menus --callback_data _res_pptp_menus
ShellBot.regHandleFunction --function res_trgo_menus --callback_data _res_trgo_menus
ShellBot.regHandleFunction --function res_xray_menus --callback_data _res_xray_menus
ShellBot.regHandleFunction --function res_opener --callback_data clses_ser_res
unset menu_re_ser1
menu_re_ser1="$(ShellBot.InlineKeyboardMarkup -b 'menu_re_ser')"


unset menu_re_main
menu_re_main=''
ShellBot.InlineKeyboardButton --button 'menu_re_main' --line 1 --text '⚖️ Open Service ⚖️️' --callback_data '_pps_serv'
ShellBot.InlineKeyboardButton --button 'menu_re_main' --line 2 --text '🟢 Status Service 🟢️' --callback_data '_sts_serv'
ShellBot.InlineKeyboardButton --button 'menu_re_main' --line 3 --text '📚 Info Port 📚' --callback_data '_pports'
ShellBot.InlineKeyboardButton --button 'menu_re_main' --line 4 --text '📁 Close Menu 📁' --callback_data 'closesss'
ShellBot.regHandleFunction --function menu_reserv --callback_data _pps_serv
ShellBot.regHandleFunction --function see_sys --callback_data _sts_serv
ShellBot.regHandleFunction --function info_port --callback_data _pports
ShellBot.regHandleFunction --function res_closer --callback_data closesss
unset menu_re_main1
menu_re_main1="$(ShellBot.InlineKeyboardMarkup -b 'menu_re_main')"

unset back_menu
back_menu=''
ShellBot.InlineKeyboardButton --button 'back_menu' --line 1 --text '🔙 Back 🔙' --callback_data '_res_back_opn'
ShellBot.regHandleFunction --function res_opener --callback_data _res_back_opn
unset back_menu1
back_menu1="$(ShellBot.InlineKeyboardMarkup -b 'back_menu')"

unset back_menu_admin
back_menu_admin=''
ShellBot.InlineKeyboardButton --button 'back_menu_admin' --line 1 --text '🔙 Back 🔙' --callback_data '_res_backadm_opn'
ShellBot.regHandleFunction --function menu_func_cb --callback_data _res_backadm_opn
unset back_menu_admin1
back_menu_admin1="$(ShellBot.InlineKeyboardMarkup -b 'back_menu_admin')"

unset menu_re_main_updater
menu_re_main_updater=''
ShellBot.InlineKeyboardButton --button 'menu_re_main_updater' --line 1 --text '📂 Open Menu 📂' --callback_data '_res_main_opn'
ShellBot.regHandleFunction --function res_opener --callback_data _res_main_opn
unset menu_re_main_updater1
menu_re_main_updater1="$(ShellBot.InlineKeyboardMarkup -b 'menu_re_main_updater')"

hantuu() {
    ShellBot.deleteMessage --chat_id ${message_chat_id[$id]} \
             --message_id ${message_message_id[$id]}
    [[ "${message_from_id[$id]}" = "$Admin_ID" ]] && {
        while read _atvs; do
              msg1+="• [ 👻Anonymous](tg://user?id=$_atvs) \n"
        done <<<"$(cat /etc/.maAsiss/User_Generate_Token |  awk '{print $3}' )"
        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
              --text "$msg1" \
              --parse_mode markdown
        return 0
    }
}
#================================| PUBLIC MODE |=====================================
_if_public() {
[[ "$(grep -wc ${message_chat_id[$id]} $User_Flood)" = '1' ]] && return 0 || AUTOBLOCK
[[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
   [[ ! -f /etc/.maAsiss/public_mode/settings ]] && {
       ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
            --text "<b>Public Mode Has Been Closed by Admin</b>" \
            --parse_mode html
       return 0
   }
}
ossl=`cat /root/log-install.txt | grep -w " OpenVPN" | cut -f2 -d: | awk '{print $6}'`
opensh=`cat /root/log-install.txt | grep -w "OpenSSH" | cut -f2 -d: | awk '{print $1}'`
db=`cat /root/log-install.txt | grep -w "Dropbear" | cut -f2 -d: | awk '{print $1,$2}'`
ssl="$(cat /root/log-install.txt | grep -w "Stunnel4" | cut -d: -f2)"
sqd="$(cat /root/log-install.txt | grep -w "Squid" | cut -d: -f2)"
portovpn=$(grep -w " OpenVPN" /root/log-install.txt | awk '{print $5,$7,$9}')
portsshws=`cat /root/log-install.txt | grep -w "SSH Websocket" | cut -d: -f2 | awk '{print $1}'`
tls="$(cat /root/log-install.txt | grep -w "Vmess TLS" | cut -d: -f2|sed 's/ //g')"
none="$(cat /root/log-install.txt | grep -w "Vmess None TLS" | cut -d: -f2|sed 's/ //g')"
trgo="$(cat /root/log-install.txt | grep -w "Trojan Go" | cut -d: -f2|sed 's/ //g')"
tr="$(cat /root/log-install.txt | grep -w "Trojan " | cut -d: -f2|sed 's/ //g')"
OhpSSH=`cat /root/log-install.txt | grep -w "OHP SSH" | cut -d: -f2 | awk '{print $1}'`
OhpDB=`cat /root/log-install.txt | grep -w "OHP DBear" | cut -d: -f2 | awk '{print $1}'`
OhpOVPN=`cat /root/log-install.txt | grep -w "OHP OpenVPN" | cut -d: -f2 | awk '{print $1}'`
wsssl=`cat /root/log-install.txt | grep -w "SSH SSL Websocket" | cut -d: -f2 | awk '{print $1}'`
xray="$(cat /root/log-install.txt | grep -w "VLess TCP XTLS" | cut -d: -f2|sed 's/ //g')"

getLimits=$(grep -w "MAX_USERS" "/etc/.maAsiss/public_mode/settings" | awk '{print $NF}')
dx=$(ls /etc/.maAsiss/public_mode --ignore='settings' | wc -l)
   local env_msg
   env_msg="━━━━━━━━━━━━━━━━━━━━━\n"
   env_msg+="<b>  WELCOME TO $nameStore</b>\n"
   env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
   env_msg+="•> <b>1 ID Tele = 1 Server VPN</b>\n"
   env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
   env_msg+="•OpenSSH : $opensh\n"
   env_msg+="•Dropbear : $db\n"
   env_msg+="•SSH WS : $portsshws\n"
   env_msg+="•SSH-WS-SSL : $wsssl\n"
   env_msg+="•SSL/TLS : $ssl\n"
   env_msg+="•OHP SSH : $OhpSSH\n"
   env_msg+="•OHP Dropbear : $OhpDB\n"
   env_msg+="•OHP OpenVPN : $OhpOVPN\n"
   env_msg+="•Squid : $sqd\n"
   env_msg+="•OpenVPN : $portovpn\n"
   env_msg+="•UDPGW : 7100-7300\n"
   env_msg+="•Trojan TLS : $tr\n"
   env_msg+="•Trojan-Go WS TLS : $trgo\n"
   env_msg+="•VMess/VLess WS TLS : $tls\n"
   env_msg+="•VMess/VLess WS Non TLS : $none\n"
   env_msg+="•VLess TCP XTLS : $xray\n"
   env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
   env_msg+="•> Status = 👤 $dx / $getLimits Max \n"
   env_msg+="━━━━━━━━━━━━━━━━━━━━━\n\n"

# ShellBot.deleteMessage --chat_id ${message_chat_id[$id]} \
     # --message_id ${message_message_id[$id]}
ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
     --text "$env_msg" \
     --reply_markup "$pub_menu1" \
     --parse_mode html
}

ssh_publik(){
ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} --message_id ${callback_query_message_message_id[$id]}
func_limit_publik ${callback_query_from_id}
r0=$(tr -dc a-zA-Z </dev/urandom | head -c5)
r1=$(tr -dc 0-9 </dev/urandom | head -c3)
userna=$(echo $r0$r1)
passw=$r1
getDays=$(grep -w "MAX_DAYS" "/etc/.maAsiss/public_mode/settings" | awk '{print $NF}')
data=$(date '+%d/%m/%C%y' -d " +$getDays days")
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)

if /usr/sbin/useradd -M -N -s /bin/false $userna -e $exp; then
    (echo "${passw}";echo "${passw}") | passwd "${userna}"
else
    ShellBot.sendMessage --chat_id ${callback_query_chat_id[$id]} \
            --text "⛔ ERROR CREATING USER" \
            --parse_mode html
    return 0
fi

[[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]] && {
        mkdir -p /etc/.maAsiss/public_mode/${callback_query_from_id}
        echo "$userna:$passw:$data" >/etc/.maAsiss/public_mode/${callback_query_from_id}/$userna
        echo "$userna:$passw $getDays Days SSH | ${callback_query_from_first_name}" >> /root/log-public
}

ossl=`cat /root/log-install.txt | grep -w " OpenVPN" | cut -f2 -d: | awk '{print $6}'`
opensh=`cat /root/log-install.txt | grep -w "OpenSSH" | cut -f2 -d: | awk '{print $1}'`
db=`cat /root/log-install.txt | grep -w "Dropbear" | cut -f2 -d: | awk '{print $1,$2}'`
ssl="$(cat /root/log-install.txt | grep -w "Stunnel4" | cut -d: -f2)"
sqd="$(cat /root/log-install.txt | grep -w "Squid" | cut -d: -f2)"
ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
ovpn2="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
portsshws=`cat /root/log-install.txt | grep -w "SSH Websocket" | cut -d: -f2 | awk '{print $1}'`
OhpSSH=`cat /root/log-install.txt | grep -w "OHP SSH" | cut -d: -f2 | awk '{print $1}'`
OhpDB=`cat /root/log-install.txt | grep -w "OHP DBear" | cut -d: -f2 | awk '{print $1}'`
OhpOVPN=`cat /root/log-install.txt | grep -w "OHP OpenVPN" | cut -d: -f2 | awk '{print $1}'`
wsssl=`cat /root/log-install.txt | grep -w "SSH SSL Websocket" | cut -d: -f2 | awk '{print $1}'`

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>    🔸 SSH ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Host : $IPs \n"
env_msg+="Username: <code>$userna</code>\n"
env_msg+="Password: <code>$passw</code>\n"
env_msg+="Expired On: $data 📅\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="OpenSSH : $opensh\n"
env_msg+="Dropbear : $db\n"
env_msg+="SSH-WS : $portsshws\n"
env_msg+="SSH-WS-SSL : $wsssl\n"
env_msg+="SSL/TLS : $ssl\n"
env_msg+="OHP SSH : $OhpSSH\n"
env_msg+="OHP Dropbear : $OhpDB\n"
env_msg+="OHP OpenVPN : $OhpOVPN\n"
env_msg+="Port Squid : $sqd\n"
env_msg+="UDPGW : 7100-7900 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="OpenVPN Config : http://$IPs:81/\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Payload WS : \n\n"
env_msg+="<code>GET / HTTP/1.1[crlf]Host: $IPs [crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
ShellBot.sendMessage --chat_id ${callback_query_from_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
}

vmess_publik() {
ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} --message_id ${callback_query_message_message_id[$id]}
func_limit_publik ${callback_query_from_id}
r0=$(tr -dc a-zA-Z </dev/urandom | head -c5)
r1=$(tr -dc 0-9 </dev/urandom | head -c3)
userna=$(echo $r0$r1)
passw=$r1
getDays=$(grep -w "MAX_DAYS" "/etc/.maAsiss/public_mode/settings" | awk '{print $NF}')
data=$(date '+%d/%m/%C%y' -d " +$getDays days")
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)
        
domain=$(cat /etc/$raycheck/domain)
tls="$(cat /root/log-install.txt | grep -w "Vmess TLS" | cut -d: -f2|sed 's/ //g')"
none="$(cat /root/log-install.txt | grep -w "Vmess None TLS" | cut -d: -f2|sed 's/ //g')"

uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vmessWSTLS$/a\### '"$userna $exp"'\
},{"id": "'""$uuid""'","alterId": '"64"',"email": "'""$userna""'"' /etc/$raycheck/config.json
sed -i '/#vmessWS$/a\### '"$userna $exp"'\
},{"id": "'""$uuid""'","alterId": '"64"',"email": "'""$userna""'"' /etc/$raycheck/config.json
            
cat> /etc/$raycheck/$userna-tls.json <<-EOF
{
"v": "2",
"ps": "${userna}",
"add": "${domain}",
"port": "${tls}",
"id": "${uuid}",
"aid": "64",
"net": "ws",
"path": "/${raycheck}ws",
"type": "none",
"host": "",
"tls": "tls"
}
EOF
cat> /etc/$raycheck/$userna-none.json <<-EOF
{
"v": "2",
"ps": "${userna}",
"add": "${domain}",
"port": "${none}",
"id": "${uuid}",
"aid": "64",
"net": "ws",
"path": "/${raycheck}ws",
"type": "none",
"host": "",
"tls": "none"
}
EOF
            
vmess_base641=$( base64 -w 0 <<< $vmess_json1)
vmess_base642=$( base64 -w 0 <<< $vmess_json2)
vmesslink1="vmess://$(base64 -w 0 /etc/$raycheck/$userna-tls.json)"
vmesslink2="vmess://$(base64 -w 0 /etc/$raycheck/$userna-none.json)"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>    🔸 VMESS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Domain : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data 📅\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TLS : $tls\n"
env_msg+="Port None TLS : $none\n"
env_msg+="ID : $uuid\n"
env_msg+="AlterID : 64\n"
env_msg+="Security : auto\n"
env_msg+="Network : websocket/ws\n"
env_msg+="Path : /${raycheck}ws\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TLS : \n<code>$vmesslink1</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link None TLS : \n<code>$vmesslink2</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
rm /etc/$raycheck/$userna-tls.json > /dev/null 2>&1
rm /etc/$raycheck/$userna-none.json > /dev/null 2>&1

[[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]] && {
        mkdir -p /etc/.maAsiss/public_mode/${callback_query_from_id}
        echo "$userna:$uuid:$data" >/etc/.maAsiss/public_mode/${callback_query_from_id}/$userna
        echo "$userna:$uuid $getDays Days VMESS | ${callback_query_from_first_name}" >> /root/log-public
}

ShellBot.sendMessage --chat_id ${callback_query_from_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart $raycheck > /dev/null 2>&1
return 0
}

vless_publik() {
ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} --message_id ${callback_query_message_message_id[$id]}
func_limit_publik ${callback_query_from_id}
r0=$(tr -dc a-zA-Z </dev/urandom | head -c5)
r1=$(tr -dc 0-9 </dev/urandom | head -c3)
userna=$(echo $r0$r1)
passw=$r1
getDays=$(grep -w "MAX_DAYS" "/etc/.maAsiss/public_mode/settings" | awk '{print $NF}')
data=$(date '+%d/%m/%C%y' -d " +$getDays days")
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)

domain=$(cat /etc/$raycheck/domain)
tls="$(cat /root/log-install.txt | grep -w "Vless TLS" | cut -d: -f2|sed 's/ //g')"
none="$(cat /root/log-install.txt | grep -w "Vless None TLS" | cut -d: -f2|sed 's/ //g')"

uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vlessWSTLS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json
sed -i '/#vlessWS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json

vlesslink1="vless://${uuid}@${domain}:$tls?path=/vlessws%26security=tls%26encryption=none%26type=ws#${userna}"
vlesslink2="vless://${uuid}@${domain}:$none?path=/vlessws%26encryption=none%26type=ws#${userna}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>     🔸 VLESS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TLS : $tls\n"
env_msg+="Port None TLS : $none\n"
env_msg+="ID : <code>$uuid</code>\n"
env_msg+="Encryption : none\n"
env_msg+="Network : websocket/ws\n"
env_msg+="Path : /vlessws\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TLS : \n"
env_msg+="<code>$vlesslink1</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link None TLS : \n"
env_msg+="<code>$vlesslink2</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

[[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]] && {
        mkdir -p /etc/.maAsiss/public_mode/${callback_query_from_id}
        echo "$userna:$uuid:$data" >/etc/.maAsiss/public_mode/${callback_query_from_id}/$userna
        echo "$userna:$uuid $getDays Days VLESS | ${callback_query_from_first_name}" >> /root/log-public
}

ShellBot.sendMessage --chat_id ${callback_query_from_id[$id]} \
    --text "$env_msg" \
    --parse_mode html 
systemctl restart $raycheck > /dev/null 2>&1
return 0

}

trojan_publik() {
ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} --message_id ${callback_query_message_message_id[$id]}
func_limit_publik ${callback_query_from_id}
r0=$(tr -dc a-zA-Z </dev/urandom | head -c5)
r1=$(tr -dc 0-9 </dev/urandom | head -c3)
userna=$(echo $r0$r1)
passw=$r1
getDays=$(grep -w "MAX_DAYS" "/etc/.maAsiss/public_mode/settings" | awk '{print $NF}')
data=$(date '+%d/%m/%C%y' -d " +$getDays days")
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)

domain=$(cat /etc/$raycheck/domain)
tr="$(cat /root/log-install.txt | grep -w "Trojan " | cut -d: -f2|sed 's/ //g')"

uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#trojanTLS$/a\#! '"$userna $exp"'\
},{"password": "'""$uuid""'","email": "'""$userna""'"' /etc/$raycheck/config.json

trojanlink="trojan://${uuid}@${domain}:${tr}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>    🔸 TROJAN ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Domain : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data 📅\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port TR : $tr\n"
env_msg+="Key : $uuid\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link : \n<code>$trojanlink</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

[[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]] && {
        mkdir -p /etc/.maAsiss/public_mode/${callback_query_from_id}
        echo "$userna:$uuid:$data" >/etc/.maAsiss/public_mode/${callback_query_from_id}/$userna
        echo "$userna:$uuid $getDays Days TROJAN | ${callback_query_from_first_name}" >> /root/log-public
}

ShellBot.sendMessage --chat_id ${callback_query_from_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart $raycheck > /dev/null 2>&1
return 0
}

trgo_publik() {
ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} --message_id ${callback_query_message_message_id[$id]}
func_limit_publik ${callback_query_from_id}
r0=$(tr -dc a-zA-Z </dev/urandom | head -c5)
r1=$(tr -dc 0-9 </dev/urandom | head -c3)
userna=$(echo $r0$r1)
passw=$r1
getDays=$(grep -w "MAX_DAYS" "/etc/.maAsiss/public_mode/settings" | awk '{print $NF}')
data=$(date '+%d/%m/%C%y' -d " +$getDays days")
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)

domain=$(cat /etc/$raycheck/domain)
trgo="$(cat /root/log-install.txt | grep -w "Trojan Go" | cut -d: -f2|sed 's/ //g')"

uuidR=$(cat /proc/sys/kernel/random/uuid)
uuid=$(cat /etc/trojan-go/idtrojango)
sed -i '/"'""$uuid""'"$/a\,"'""$uuidR""'"' /etc/trojan-go/config.json
echo -e "### $userna $exp $uuidR" | tee -a /etc/trojan-go/akun.conf
linktrgo="trojan-go://${uuidR}@${domain}:${trgo}/?sni=${domain}%26type=ws%26host=${domain}%26path=/scvps%26encryption=none#${userna}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>    🔸 TROJAN GO ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="User : $userna\n"
env_msg+="Expired On : $data 🗓 \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $trgo\n"
env_msg+="Key : $uuidR\n"
env_msg+="Network : ws\n"
env_msg+="Path : /scvps\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link TRGO: \n\n"
env_msg+="<code>$linktrgo</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

[[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]] && {
        mkdir -p /etc/.maAsiss/public_mode/${callback_query_from_id}
        echo "$userna:$uuid:$data" >/etc/.maAsiss/public_mode/${callback_query_from_id}/$userna
        echo "$userna:$uuid $getDays Days TRJ-GO | ${callback_query_from_first_name}" >> /root/log-public
}

ShellBot.sendMessage --chat_id ${callback_query_from_id[$id]} \
    --text "$env_msg" \
    --parse_mode html
systemctl restart trojan-go > /dev/null 2>&1
return 0

}

xray_publik() {
ShellBot.deleteMessage --chat_id ${callback_query_message_chat_id[$id]} --message_id ${callback_query_message_message_id[$id]}
func_limit_publik ${callback_query_from_id}
r0=$(tr -dc a-zA-Z </dev/urandom | head -c5)
r1=$(tr -dc 0-9 </dev/urandom | head -c3)
userna=$(echo $r0$r1)
passw=$r1
getDays=$(grep -w "MAX_DAYS" "/etc/.maAsiss/public_mode/settings" | awk '{print $NF}')
data=$(date '+%d/%m/%C%y' -d " +$getDays days")
exp=$(echo "$data" | awk -F'/' '{print $2FS$1FS$3}' | xargs -i date -d'{}' +%Y-%m-%d)

domain=$(cat /etc/$raycheck/domain)
xray="$(cat /root/log-install.txt | grep -w "VLess TCP XTLS" | cut -d: -f2|sed 's/ //g')"

xCho='xtls-rprx-direct'
uuid=$(cat /proc/sys/kernel/random/uuid)
sed -i '/#vlessXTLS$/a\#& '"$userna $exp"'\
},{"id": "'""$uuid""'","flow": "'""$xCho""'","email": "'""$userna""'"' /usr/local/etc/xtls/config.json

vlessTcpXtls="vless://${uuid}@${domain}:$xray?path=/%26security=xtls%26encryption=none%26flow=${xCho}%26type=tcp#${userna}"

local env_msg
env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>    🔸 VLESS XTLS ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Address : $domain\n"
env_msg+="Remarks : $userna\n"
env_msg+="Expired On : $data \n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Port : $xray\n"
env_msg+="ID : <code>$uuid</code>\n"
env_msg+="Encryption : none\n"
env_msg+="Network : tcp\n"
env_msg+="Flow : $xCho\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
env_msg+="Link : \n"
env_msg+="<code>$vlessTcpXtls</code>\n"
env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"

[[ "${callback_query_from_id[$id]}" != "$Admin_ID" ]] && {
        mkdir -p /etc/.maAsiss/public_mode/${callback_query_from_id}
        echo "$userna:$uuid:$data" >/etc/.maAsiss/public_mode/${callback_query_from_id}/$userna
        echo "$userna:$uuid $getDays Days VLESS | ${callback_query_from_first_name}" >> /root/log-public
}

ShellBot.sendMessage --chat_id ${callback_query_from_id[$id]} \
    --text "$env_msg" \
    --parse_mode html 
systemctl restart xtls > /dev/null 2>&1
return 0

}

unset pub_menu
pub_menu=''
ShellBot.InlineKeyboardButton --button 'pub_menu' --line 1 --text '• VMess •' --callback_data 'vmess'
ShellBot.InlineKeyboardButton --button 'pub_menu' --line 1 --text '• VLess •' --callback_data 'vless'
ShellBot.InlineKeyboardButton --button 'pub_menu' --line 2 --text '• Trojan •' --callback_data 'trojan'
ShellBot.InlineKeyboardButton --button 'pub_menu' --line 2 --text '• TrojanGO •' --callback_data 'trgo'
ShellBot.InlineKeyboardButton --button 'pub_menu' --line 3 --text '• SSH •' --callback_data 'ssh'
ShellBot.InlineKeyboardButton --button 'pub_menu' --line 3 --text '• XRAY •' --callback_data 'xray'

ShellBot.regHandleFunction --function ssh_publik --callback_data ssh
ShellBot.regHandleFunction --function vmess_publik --callback_data vmess
ShellBot.regHandleFunction --function vless_publik --callback_data vless
ShellBot.regHandleFunction --function trojan_publik --callback_data trojan
ShellBot.regHandleFunction --function trgo_publik --callback_data trgo
ShellBot.regHandleFunction --function xray_publik --callback_data xray


unset pub_menu1
pub_menu1="$(ShellBot.InlineKeyboardMarkup -b 'pub_menu')"
while :; do
    ShellBot.getUpdates --limit 100 --offset $(ShellBot.OffsetNext) --timeout 35
    for id in $(ShellBot.ListUpdates); do
        (
            ShellBot.watchHandle --callback_data ${callback_query_data[$id]}
            [[ ${message_chat_type[$id]} != 'private' ]] && {
                   ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                        --text "$(echo -e "⛔ only run this command on private chat / pm on bot")" \
                        --parse_mode html
                   >$CAD_ARQ
                   break
                   ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                        --text "Func Error Do Nothing" \
                        --reply_markup "$(ShellBot.ForceReply)"
            }
            CAD_ARQ=/tmp/cad.${message_from_id[$id]}
            echotoprice=/tmp/price
            if [[ ${message_entities_type[$id]} == bot_command ]]; then
                case ${message_text[$id]} in
                *)
                    :
                    comando=(${message_text[$id]})
                    [[ "${comando[0]}" = "/start" ]] && msg_welcome
                    [[ "${comando[0]}" = "/menu" ]] && menu_func
                    [[ "${comando[0]}" = "/info" ]] && about_server
                    [[ "${comando[0]}" = "/anonym" ]] && hantuu
                    [[ "${comando[0]}" = "/free" ]] && _if_public
                    [[ "${comando[0]}" = "/disable" ]] && echo "${message_text[$id]}" > /tmp/order && Disable_Order
                    ;;
                esac
            fi
            if [[ ${message_reply_to_message_message_id[$id]} ]]; then
                case ${message_reply_to_message_text[$id]} in
                '👤 CREATE USER 👤\n\nUsername:')
                    verifica_acesso
                    Saldo_CheckerSSH
                    [[ "$_erro" != '1' ]] && {
                    [[ "$(awk -F : '$3 >= 1000 { print $1 }' /etc/passwd | grep -w ${message_text[$id]} | wc -l)" != '0' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⚠️ User Already Exist..")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    [ "${message_text[$id]}" == 'root' ] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ INVALID USER")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    sizemax=$(echo -e ${#message_text[$id]})
                    [[ "$sizemax" -gt '10' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use no maximum 10 characters [EX: RstoreVPN]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                    }
                    echo "Name: ${message_text[$id]}" >$CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Password:' \
                        --reply_markup "$(ShellBot.ForceReply)" # Força a resposta.
                    }
                    ;;
                'Password:')
                    verifica_acesso
                    Saldo_CheckerSSH
                    [[ "$_erro" != '1' ]] && {
                    echo "Password: ${message_text[$id]}" >>$CAD_ARQ
                    # Próximo campo.
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Validity in days: ' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    }
                    ;;
                'Validity in days:')
                    verifica_acesso
                    Saldo_CheckerSSH
                    [[ "$_erro" != '1' ]] && {
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 30]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                if ((${message_text[$id]} >= 1 && ${message_text[$id]} <= 30)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    cret_user $CAD_ARQ
                    [[ "(grep -w ${message_text[$id]} /etc/passwd)" = '0' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e ⛔ Error creating user !)" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }

                        ossl=`cat /root/log-install.txt | grep -w " OpenVPN" | cut -f2 -d: | awk '{print $6}'`
                        opensh=`cat /root/log-install.txt | grep -w "OpenSSH" | cut -f2 -d: | awk '{print $1}'`
                        db=`cat /root/log-install.txt | grep -w "Dropbear" | cut -f2 -d: | awk '{print $1,$2}'`
                        ssl="$(cat /root/log-install.txt | grep -w "Stunnel4" | cut -d: -f2)"
                        sqd="$(cat /root/log-install.txt | grep -w "Squid" | cut -d: -f2)"
                        ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
                        ovpn2="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
                        portsshws=`cat /root/log-install.txt | grep -w "SSH Websocket" | cut -d: -f2 | awk '{print $1}'`
                        OhpSSH=`cat /root/log-install.txt | grep -w "OHP SSH" | cut -d: -f2 | awk '{print $1}'`
                        OhpDB=`cat /root/log-install.txt | grep -w "OHP DBear" | cut -d: -f2 | awk '{print $1}'`
                        OhpOVPN=`cat /root/log-install.txt | grep -w "OHP OpenVPN" | cut -d: -f2 | awk '{print $1}'`
                        wsssl=`cat /root/log-install.txt | grep -w "SSH SSL Websocket" | cut -d: -f2 | awk '{print $1}'`

                        env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>       🔸 SSH ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
                        env_msg+="Host : $IPs \n"
                        env_msg+="Username: <code>$(awk -F " " '/Name/ {print $2}' $CAD_ARQ)</code>\n"
                        env_msg+="Password: <code>$(awk -F " " '/Password/ {print $2}' $CAD_ARQ)</code>\n"
                        env_msg+="Expired On: $(awk -F " " '/Validity/ {print $2}' $CAD_ARQ) 🗓\n"
                        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
                        env_msg+="OpenSSH : $opensh\n"
                        env_msg+="Dropbear : $db\n"
                        env_msg+="SSH-WS : $portsshws\n"
                        env_msg+="SSH-WS-SSL : $wsssl\n"
                        env_msg+="SSL/TLS : $ssl\n"
                        env_msg+="OHP SSH : $OhpSSH\n"
                        env_msg+="OHP Dropbear : $OhpDB\n"
                        env_msg+="OHP OpenVPN : $OhpOVPN\n"
                        env_msg+="Port Squid : $sqd\n"
                        env_msg+="UDPGW : 7100-7300 \n"
                        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
                        env_msg+="OpenVPN Config : http://$IPs:81/\n"
                        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
                        env_msg+="Payload WS : \n\n"
                        env_msg+="<code>GET / HTTP/1.1[crlf]Host: $IPs [crlf]Upgrade: websocket[crlf][crlf]</code>\n"
                        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
                        ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                            --text "$env_msg" \
                            --parse_mode html
                        break
                elif ((${message_text[$id]} >= 30 && ${message_text[$id]} <= 60)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    Saldo_CheckerSSH2Month
                    [[ "$_erro" != '1' ]] && {
                    2month_user $CAD_ARQ
                    [[ "(grep -w ${message_text[$id]} /etc/passwd)" = '0' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e ⛔ Error creating user !)" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }

                        ossl=`cat /root/log-install.txt | grep -w " OpenVPN" | cut -f2 -d: | awk '{print $6}'`
                        opensh=`cat /root/log-install.txt | grep -w "OpenSSH" | cut -f2 -d: | awk '{print $1}'`
                        db=`cat /root/log-install.txt | grep -w "Dropbear" | cut -f2 -d: | awk '{print $1,$2}'`
                        ssl="$(cat /root/log-install.txt | grep -w "Stunnel4" | cut -d: -f2)"
                        sqd="$(cat /root/log-install.txt | grep -w "Squid" | cut -d: -f2)"
                        ovpn="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
                        ovpn2="$(netstat -nlpu | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
                        portsshws=`cat /root/log-install.txt | grep -w "SSH Websocket" | cut -d: -f2 | awk '{print $1}'`
                        OhpSSH=`cat /root/log-install.txt | grep -w "OHP SSH" | cut -d: -f2 | awk '{print $1}'`
                        OhpDB=`cat /root/log-install.txt | grep -w "OHP DBear" | cut -d: -f2 | awk '{print $1}'`
                        OhpOVPN=`cat /root/log-install.txt | grep -w "OHP OpenVPN" | cut -d: -f2 | awk '{print $1}'`
                        wsssl=`cat /root/log-install.txt | grep -w "SSH SSL Websocket" | cut -d: -f2 | awk '{print $1}'`

                        local env_msg
                        env_msg="━━━━━━━━━━━━━━━━━━━━━\n<b>       🔸 SSH ACCOUNT 🔸 </b>\n━━━━━━━━━━━━━━━━━━━━━\n"
                        env_msg+="Host : $IPs \n"
                        env_msg+="Username: <code>$(awk -F " " '/Name/ {print $2}' $CAD_ARQ)</code>\n"
                        env_msg+="Password: <code>$(awk -F " " '/Password/ {print $2}' $CAD_ARQ)</code>\n"
                        env_msg+="Expired On: $(awk -F " " '/Validity/ {print $2}' $CAD_ARQ) 🗓\n"
                        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
                        env_msg+="OpenSSH : $opensh\n"
                        env_msg+="Dropbear : $db\n"
                        env_msg+="SSH-WS : $portsshws\n"
                        env_msg+="SSH-WS-SSL : $wsssl\n"
                        env_msg+="SSL/TLS : $ssl\n"
                        env_msg+="OHP SSH : $OhpSSH\n"
                        env_msg+="OHP Dropbear : $OhpDB\n"
                        env_msg+="OHP OpenVPN : $OhpOVPN\n"
                        env_msg+="Port Squid : $sqd\n"
                        env_msg+="UDPGW : 7100-7900 \n"
                        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
                        env_msg+="OpenVPN Config : http://$IPs:81/\n"
                        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
                        env_msg+="Payload WS : \n\n"
                        env_msg+="<code>GET / HTTP/1.1[crlf]Host: $IPs [crlf]Upgrade: websocket[crlf][crlf]</code>\n"
                        env_msg+="━━━━━━━━━━━━━━━━━━━━━\n"
                        ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                            --text "$env_msg" \
                            --parse_mode html
                        break
                        }
                else
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Can't be more than 60 Days")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                fi
                    }
                    ;;
                '⏳ Renew SSH ⏳\n\nUsername:')
                    verifica_acesso
                    Saldo_CheckerSSH
                    [[ "$_erro" != '1' ]] && {
                    echo "${message_text[$id]}" >/tmp/name-d
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Input the days or date:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    }
                    ;;
                'Input the days or date:')
                    verifica_acesso
                    Saldo_CheckerSSH
                    [[ "$_erro" != '1' ]] && {
                    [[ ${message_text[$id]} != ?(+|-)+([0-9/]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "⛔ Error! Follow the example \nData format [EX: 30]" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                if ((${message_text[$id]} >= 1 && ${message_text[$id]} <= 30)); then
                    func_renew_ssh $(cat /tmp/name-d) ${message_text[$id]}
                    [[ "$_erro" == '1' ]] && break
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "$(echo -e "━━━━━━━━━━━━━━━━━━━━━\n<b>✅ DATE CHANGED !</b> !\n━━━━━━━━━━━━━━━━━━━━━\n\n<b>Username:</b> $(cat /tmp/name-d)\n<b>New date:</b> $udata")" \
                        --parse_mode html
                    rm /tmp/name-d >/dev/null 2>&1
                else
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Can't be more than 30 Days")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                fi
                    }
                    ;;
                '🗑 REMOVE USER 🗑\n\nUsername:')
                    verifica_acesso
                    func_del_ssh ${message_text[$id]}
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "✅ *Successfully removed.* 🚮" \
                        --parse_mode markdown
                    ;;
                '👥 ADD Reseller 👥\n\nEnter the name:')
                    verifica_acesso
                    echo "Name: ${message_text[$id]}" > $CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'User token by generate:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'User token by generate:')
                    verifica_acesso
                    _VAR1=$(echo ${message_text[$id]} | sed -e 's/[^0-9]//ig'| rev)
                    [[ ! -z $(grep -w "$_VAR1" "$User_Active" ) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Already Registered")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "${message_text[$id]}" >/tmp/scvpsss
                    echo "User: $_VAR1" >> $CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Saldo:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Saldo:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⚠️ Use only numbers [EX: 100000]")" \
                            --parse_mode html
                        break
                    }
                    echo "Saldo: ${message_text[$id]}" >> $CAD_ARQ
                    sleep 1
                    cret_res $CAD_ARQ
                    ;;
                '🗑 REMOVE Reseller 🗑\n\nInput Name of Reseller:')
                    echo -e "${message_text[$id]}" >$CAD_ARQ
                    _VAR12=$(grep -w "${message_text[$id]}" "$Res_Token")
                    [[ -z $_VAR12 ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Token invalid")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    func_del_res $_VAR12
                    sed -i "/\b${message_text[$id]}\b/d" $Res_Token
                    break
                    ;;
                '💸 Topup Saldo 💸\n\nName reseller:')
                    verifica_acesso
                    cek_res_token=$(grep -w "${message_text[$id]}" "$Res_Token" | awk '{print $NF}' | sed -e 's/[^0-9]//ig'| rev)
                    echo $cek_res_token > /tmp/ruii
                    echo ${message_text[$id]} > /tmp/ruiix
                    [[ -z $cek_res_token ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ No user found")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                 #   _VARSaldo=$(echo ${message_text[$id]} | sed -e 's/[^0-9]//ig'| rev)
                 #   echo -e "${message_text[$id]}" > /tmp/name-l
                 #   sed -i 's/^@//' /tmp/name-l
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Topup Saldo:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Topup Saldo:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⚠️ Use only numbers [EX: 100000]")" \
                            --parse_mode html
                        break
                    }
                    func_topup_res $(cat /tmp/ruii) ${message_text[$id]}
                    [[ "$_erro" == '1' ]] && break
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "$(echo -e "━━━━━━━━━━━━━━━━━\n  ✅ <b>Succesfully Topup !</b> ✅ !\n━━━━━━━━━━━━━━━━━\n<b>Name:</b> $(cat /tmp/ruiix) \n<b>Topup Saldo:</b> ${message_text[$id]}\n<b>Total Saldo Now:</b> $_TopUpSal \n━━━━━━━━━━━━━━━━━")" \
                        --parse_mode html
                    rm /tmp/ruii >/dev/null 2>&1 && rm /tmp/ruiix >/dev/null 2>&1
                    ;;
                '👤 CREATE TRIAL SSH 👤\n\nHow many hours should it last ? EX: 1:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
                        func_verif_limite_res ${message_from_id}
                        [[ "$_result" -ge "$_limTotal" ]] && {
                            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                                --text "⛔ Max Limit Create Trial only $_limTotal Users\n\nYou Still Have User Active : $user_on" \
                                --parse_mode html
                            break
                            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                                 --text "Func Error Do Nothing" \
                                 --reply_markup "$(ShellBot.ForceReply)"
                        }
                    }
                    if ((${message_text[$id]} == 1 || ${message_text[$id]} == 2)); then
                        func_add_ssh_trial ${message_text[$id]}
                    else
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Trial Max Hours only 1-2")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    fi
                    ;;
                '👤 CREATE USER VMess 👤\n\nUsername:')
                    verifica_acesso
                    [ "${message_text[$id]}" == 'root' ] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ INVALID USER")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    sizemax=$(echo -e ${#message_text[$id]})
                    [[ "$sizemax" -gt '10' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use no maximum 10 characters [EX: RstoreVPN]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                    }
                    user_already_exist ${message_text[$id]}
                    echo "Name: ${message_text[$id]}" >$CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'VMess Validity in days: ' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'VMess Validity in days:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 30]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                if ((${message_text[$id]} >= 1 && ${message_text[$id]} <= 30)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_ray $CAD_ARQ
                elif ((${message_text[$id]} >= 30 && ${message_text[$id]} <= 60)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_ray2 $CAD_ARQ
                else
                    ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                        --text "$(echo -e "⛔ Can't be more than 60 Days")" \
                        --parse_mode html
                    >$CAD_ARQ
                    break
                    ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                        --text "Func Error Do Nothing" \
                        --reply_markup "$(ShellBot.ForceReply)"
                fi
                    ;;
                '👤 CREATE TRIAL VMess 👤\n\nHow many hours should it last ? EX: 1:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
                        user_on=$(ls /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold)
                        func_verif_limite_res ${message_from_id}
                        [[ "$_result" -ge "$_limTotal" ]] && {
                            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                                --text "⛔ Max Limit Create Trial only $_limTotal Users\n\nYou Still Have User Active : $user_on" \
                                --parse_mode html
                            break
                            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                                 --text "Func Error Do Nothing" \
                                 --reply_markup "$(ShellBot.ForceReply)"
                        }
                    }
                    if ((${message_text[$id]} == 1 || ${message_text[$id]} == 2)); then
                        func_add_ray_trial ${message_text[$id]}
                    else
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Trial Max Hours only 1-2")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    fi
                    ;;
                '🗑 REMOVE USER V2RAY 🗑\n\nUsername:')
                    verifica_acesso
                    func_del_ray ${message_text[$id]}
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "✅ *Successfully removed.* 🚮" \
                        --parse_mode markdown
                    ;;
                '👤 CREATE USER Trojan 👤\n\nUsername:')
                    verifica_acesso
                    [ "${message_text[$id]}" == 'root' ] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ INVALID USER")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    sizemax=$(echo -e ${#message_text[$id]})
                    [[ "$sizemax" -gt '10' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use no maximum 10 characters [EX: RstoreVPN]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                    }
                    user_already_exist ${message_text[$id]}
                    echo "Name: ${message_text[$id]}" >$CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Trojan Validity in days: ' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Trojan Validity in days:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 30]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                if ((${message_text[$id]} >= 1 && ${message_text[$id]} <= 30)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_trojan $CAD_ARQ
                elif ((${message_text[$id]} >= 30 && ${message_text[$id]} <= 60)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_trojan2 $CAD_ARQ
                else
                    ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                        --text "$(echo -e "⛔ Can't be more than 60 Days")" \
                        --parse_mode html
                    >$CAD_ARQ
                    break
                    ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                        --text "Func Error Do Nothing" \
                        --reply_markup "$(ShellBot.ForceReply)"
                fi
                    ;;
                '🗑 REMOVE USER TROJAN 🗑\n\nUsername:')
                    verifica_acesso
                    func_del_trojan ${message_text[$id]}
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "✅ *Successfully removed.* 🚮" \
                        --parse_mode markdown
                    ;;
                '👤 CREATE TRIAL Trojan 👤\n\nHow many hours should it last ? EX: 1:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
                        user_on=$(ls /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold)
                        func_verif_limite_res ${message_from_id}
                        [[ "$_result" -ge "$_limTotal" ]] && {
                            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                                --text "⛔ Max Limit Create Trial only $_limTotal Users\n\nYou Still Have User Active : $user_on" \
                                --parse_mode html
                            break
                            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                                 --text "Func Error Do Nothing" \
                                 --reply_markup "$(ShellBot.ForceReply)"
                        }
                    }
                    if ((${message_text[$id]} == 1 || ${message_text[$id]} == 2)); then
                        func_add_trojan_trial ${message_text[$id]}
                    else
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Trial Max Hours only 1-2")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    fi
                    ;;
                '👤 CREATE USER VLess 👤\n\nUsername:')
                    verifica_acesso
                    [ "${message_text[$id]}" == 'root' ] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ INVALID USER")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    sizemax=$(echo -e ${#message_text[$id]})
                    [[ "$sizemax" -gt '10' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use no maximum 10 characters [EX: RstoreVPN]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                    }
                    user_already_exist ${message_text[$id]}
                    echo "Name: ${message_text[$id]}" >$CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'VLess Validity in days: ' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'VLess Validity in days:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 30]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                if ((${message_text[$id]} >= 1 && ${message_text[$id]} <= 30)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_vless $CAD_ARQ
                elif ((${message_text[$id]} >= 30 && ${message_text[$id]} <= 60)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_vless2 $CAD_ARQ
                else
                    ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                        --text "$(echo -e "⛔ Can't be more than 60 Days")" \
                        --parse_mode html
                    >$CAD_ARQ
                    break
                    ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                        --text "Func Error Do Nothing" \
                        --reply_markup "$(ShellBot.ForceReply)"
                fi
                    ;;
                '🗑 REMOVE USER VLess 🗑\n\nUsername:')
                    verifica_acesso
                    func_del_vless ${message_text[$id]}
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "✅ *Successfully removed.* 🚮" \
                        --parse_mode markdown
                    ;;
                '👤 CREATE TRIAL VLess 👤\n\nHow many hours should it last ? EX: 1:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
                        user_on=$(ls /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold)
                        func_verif_limite_res ${message_from_id}
                        [[ "$_result" -ge "$_limTotal" ]] && {
                            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                                --text "⛔ Max Limit Create Trial only $_limTotal Users\n\nYou Still Have User Active : $user_on" \
                                --parse_mode html
                            break
                            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                                 --text "Func Error Do Nothing" \
                                 --reply_markup "$(ShellBot.ForceReply)"
                        }
                    }
                    if ((${message_text[$id]} == 1 || ${message_text[$id]} == 2)); then
                        func_add_vless_trial ${message_text[$id]}
                    else
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Trial Max Hours only 1-2")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    fi
                    ;;
                '👤 CREATE USER WireGuard 👤\n\nUsername:')
                    verifica_acesso
                    [ "${message_text[$id]}" == 'root' ] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ INVALID USER")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    sizemax=$(echo -e ${#message_text[$id]})
                    [[ "$sizemax" -gt '10' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use no maximum 10 characters [EX: RstoreVPN]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                    }
                    user_already_exist ${message_text[$id]}
                    echo "Name: ${message_text[$id]}" >$CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'WG Validity in days: ' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'WG Validity in days:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 30]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                if ((${message_text[$id]} >= 1 && ${message_text[$id]} <= 30)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_wg $CAD_ARQ
                elif ((${message_text[$id]} >= 30 && ${message_text[$id]} <= 60)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_wg2 $CAD_ARQ
                else
                    ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                        --text "$(echo -e "⛔ Can't be more than 60 Days")" \
                        --parse_mode html
                    >$CAD_ARQ
                    break
                    ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                        --text "Func Error Do Nothing" \
                        --reply_markup "$(ShellBot.ForceReply)"
                fi
                    ;;
                '🗑 REMOVE USER WireGuard 🗑\n\nUsername:')
                    verifica_acesso
                    func_del_wg ${message_text[$id]}
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "✅ *Successfully removed.* 🚮" \
                        --parse_mode markdown
                    ;;
                '👤 CREATE TRIAL WireGuard 👤\n\nHow many hours should it last ? EX: 1:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
                        user_on=$(ls /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold)
                        func_verif_limite_res ${message_from_id}
                        [[ "$_result" -ge "$_limTotal" ]] && {
                            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                                --text "⛔ Max Limit Create Trial only $_limTotal Users\n\nYou Still Have User Active : $user_on" \
                                --parse_mode html
                            break
                            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                                 --text "Func Error Do Nothing" \
                                 --reply_markup "$(ShellBot.ForceReply)"
                        }
                    }
                    if ((${message_text[$id]} == 1 || ${message_text[$id]} == 2)); then
                        func_add_wg_trial ${message_text[$id]}
                    else
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Trial Max Hours only 1-2")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    fi
                    ;;
                '👤 CREATE USER ShadowSocks 👤\n\nUsername:')
                    verifica_acesso
                    [ "${message_text[$id]}" == 'root' ] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ INVALID USER")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    sizemax=$(echo -e ${#message_text[$id]})
                    [[ "$sizemax" -gt '10' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use no maximum 10 characters [EX: RstoreVPN]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                    }
                    user_already_exist ${message_text[$id]}
                    echo "Name: ${message_text[$id]}" >$CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'SS Validity in days: ' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'SS Validity in days:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 30]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                if ((${message_text[$id]} >= 1 && ${message_text[$id]} <= 30)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_ss $CAD_ARQ
                elif ((${message_text[$id]} >= 30 && ${message_text[$id]} <= 60)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_ss2 $CAD_ARQ
                else
                    ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                        --text "$(echo -e "⛔ Can't be more than 60 Days")" \
                        --parse_mode html
                    >$CAD_ARQ
                    break
                    ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                        --text "Func Error Do Nothing" \
                        --reply_markup "$(ShellBot.ForceReply)"
                fi
                    ;;
                '🗑 REMOVE USER ShadowSocks 🗑\n\nUsername:')
                    verifica_acesso
                    func_del_ss ${message_text[$id]}
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "✅ *Successfully removed.* 🚮" \
                        --parse_mode markdown
                    ;;
                '👤 CREATE TRIAL ShadowSocks 👤\n\nHow many hours should it last ? EX: 1:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
                        user_on=$(ls /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold)
                        func_verif_limite_res ${message_from_id}
                        [[ "$_result" -ge "$_limTotal" ]] && {
                            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                                --text "⛔ Max Limit Create Trial only $_limTotal Users\n\nYou Still Have User Active : $user_on" \
                                --parse_mode html
                            break
                            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                                 --text "Func Error Do Nothing" \
                                 --reply_markup "$(ShellBot.ForceReply)"
                        }
                    }
                    if ((${message_text[$id]} == 1 || ${message_text[$id]} == 2)); then
                        func_add_ss_trial ${message_text[$id]}
                    else
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Trial Max Hours only 1-2")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    fi
                    ;;
                '👤 CREATE USER Shadowsocks-R 👤\n\nUsername:')
                    verifica_acesso
                    [ "${message_text[$id]}" == 'root' ] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ INVALID USER")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    sizemax=$(echo -e ${#message_text[$id]})
                    [[ "$sizemax" -gt '10' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use no maximum 10 characters [EX: RstoreVPN]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                    }
                    user_already_exist ${message_text[$id]}
                    echo "Name: ${message_text[$id]}" >$CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'SSR Validity in days: ' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'SSR Validity in days:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 30]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                if ((${message_text[$id]} >= 1 && ${message_text[$id]} <= 30)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_ssr $CAD_ARQ
                elif ((${message_text[$id]} >= 30 && ${message_text[$id]} <= 60)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_ssr2 $CAD_ARQ
                else
                    ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                        --text "$(echo -e "⛔ Can't be more than 60 Days")" \
                        --parse_mode html
                    >$CAD_ARQ
                    break
                    ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                        --text "Func Error Do Nothing" \
                        --reply_markup "$(ShellBot.ForceReply)"
                fi
                    ;;
                '🗑 REMOVE USER Shadowsocks-R 🗑\n\nUsername:')
                    verifica_acesso
                    func_del_ssr ${message_text[$id]}
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "✅ *Successfully removed.* 🚮" \
                        --parse_mode markdown
                    ;;
                '👤 CREATE TRIAL Shadowsocks-R 👤\n\nHow many hours should it last ? EX: 1:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
                        user_on=$(ls /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold)
                        func_verif_limite_res ${message_from_id}
                        [[ "$_result" -ge "$_limTotal" ]] && {
                            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                                --text "⛔ Max Limit Create Trial only $_limTotal Users\n\nYou Still Have User Active : $user_on" \
                                --parse_mode html
                            break
                            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                                 --text "Func Error Do Nothing" \
                                 --reply_markup "$(ShellBot.ForceReply)"
                        }
                    }
                    if ((${message_text[$id]} == 1 || ${message_text[$id]} == 2)); then
                        func_add_ssr_trial ${message_text[$id]}
                    else
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Trial Max Hours only 1-2")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    fi
                    ;;
                '👤 CREATE USER SSTP 👤\n\nUsername:')
                    verifica_acesso
                    [ "${message_text[$id]}" == 'root' ] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ INVALID USER")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    sizemax=$(echo -e ${#message_text[$id]})
                    [[ "$sizemax" -gt '10' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use no maximum 10 characters [EX: RstoreVPN]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                    }
                    user_already_exist ${message_text[$id]}
                    echo "Name: ${message_text[$id]}" >$CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'SSTP Password:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'SSTP Password:')
                    verifica_acesso
                    echo "Password: ${message_text[$id]}" >>$CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'SSTP Validity in days: ' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'SSTP Validity in days:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 30]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                if ((${message_text[$id]} >= 1 && ${message_text[$id]} <= 30)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_sstp $CAD_ARQ
                elif ((${message_text[$id]} >= 30 && ${message_text[$id]} <= 60)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_sstp2 $CAD_ARQ
                else
                    ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                        --text "$(echo -e "⛔ Can't be more than 60 Days")" \
                        --parse_mode html
                    >$CAD_ARQ
                    break
                    ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                        --text "Func Error Do Nothing" \
                        --reply_markup "$(ShellBot.ForceReply)"
                fi
                    ;;
                '🗑 REMOVE USER SSTP 🗑\n\nUsername:')
                    verifica_acesso
                    func_del_sstp ${message_text[$id]}
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "✅ *Successfully removed.* 🚮" \
                        --parse_mode markdown
                    ;;
                '👤 CREATE TRIAL SSTP 👤\n\nHow many hours should it last ? EX: 1:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
                        user_on=$(ls /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold)
                        func_verif_limite_res ${message_from_id}
                        [[ "$_result" -ge "$_limTotal" ]] && {
                            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                                --text "⛔ Max Limit Create Trial only $_limTotal Users\n\nYou Still Have User Active : $user_on" \
                                --parse_mode html
                            break
                            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                                 --text "Func Error Do Nothing" \
                                 --reply_markup "$(ShellBot.ForceReply)"
                        }
                    }
                    if ((${message_text[$id]} == 1 || ${message_text[$id]} == 2)); then
                        func_add_sstp_trial ${message_text[$id]}
                    else
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Trial Max Hours only 1-2")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    fi
                    ;;
                '👤 CREATE USER L2TP 👤\n\nUsername:')
                    verifica_acesso
                    [ "${message_text[$id]}" == 'root' ] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ INVALID USER")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    sizemax=$(echo -e ${#message_text[$id]})
                    [[ "$sizemax" -gt '10' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use no maximum 10 characters [EX: RstoreVPN]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                    }
                    user_already_exist ${message_text[$id]}
                    echo "Name: ${message_text[$id]}" >$CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'L2TP Password:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'L2TP Password:')
                    verifica_acesso
                    echo "Password: ${message_text[$id]}" >>$CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'L2TP Validity in days: ' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'L2TP Validity in days:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 30]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                if ((${message_text[$id]} >= 1 && ${message_text[$id]} <= 30)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_l2tp $CAD_ARQ
                elif ((${message_text[$id]} >= 30 && ${message_text[$id]} <= 60)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_l2tp2 $CAD_ARQ
                else
                    ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                        --text "$(echo -e "⛔ Can't be more than 60 Days")" \
                        --parse_mode html
                    >$CAD_ARQ
                    break
                    ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                        --text "Func Error Do Nothing" \
                        --reply_markup "$(ShellBot.ForceReply)"
                fi
                    ;;
                '🗑 REMOVE USER L2TP 🗑\n\nUsername:')
                    verifica_acesso
                    func_del_l2tp ${message_text[$id]}
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "✅ *Successfully removed.* 🚮" \
                        --parse_mode markdown
                    ;;
                '👤 CREATE TRIAL L2TP 👤\n\nHow many hours should it last ? EX: 1:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
                        user_on=$(ls /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold)
                        func_verif_limite_res ${message_from_id}
                        [[ "$_result" -ge "$_limTotal" ]] && {
                            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                                --text "⛔ Max Limit Create Trial only $_limTotal Users\n\nYou Still Have User Active : $user_on" \
                                --parse_mode html
                            break
                            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                                 --text "Func Error Do Nothing" \
                                 --reply_markup "$(ShellBot.ForceReply)"
                        }
                    }
                    if ((${message_text[$id]} == 1 || ${message_text[$id]} == 2)); then
                        func_add_l2tp_trial ${message_text[$id]}
                    else
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Trial Max Hours only 1-2")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    fi
                    ;;
                '👤 CREATE USER PPTP 👤\n\nUsername:')
                    verifica_acesso
                    [ "${message_text[$id]}" == 'root' ] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ INVALID USER")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    sizemax=$(echo -e ${#message_text[$id]})
                    [[ "$sizemax" -gt '10' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use no maximum 10 characters [EX: RstoreVPN]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                    }
                    user_already_exist ${message_text[$id]}
                    echo "Name: ${message_text[$id]}" >$CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'PPTP Password:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'PPTP Password:')
                    verifica_acesso
                    echo "Password: ${message_text[$id]}" >>$CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'PPTP Validity in days: ' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'PPTP Validity in days:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 30]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                if ((${message_text[$id]} >= 1 && ${message_text[$id]} <= 30)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_pptp $CAD_ARQ
                elif ((${message_text[$id]} >= 30 && ${message_text[$id]} <= 60)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_pptp2 $CAD_ARQ
                else
                    ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                        --text "$(echo -e "⛔ Can't be more than 60 Days")" \
                        --parse_mode html
                    >$CAD_ARQ
                    break
                    ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                        --text "Func Error Do Nothing" \
                        --reply_markup "$(ShellBot.ForceReply)"
                fi
                    ;;
                '🗑 REMOVE USER PPTP 🗑\n\nUsername:')
                    verifica_acesso
                    func_del_pptp ${message_text[$id]}
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "✅ *Successfully removed.* 🚮" \
                        --parse_mode markdown
                    ;;
                '👤 CREATE TRIAL PPTP 👤\n\nHow many hours should it last ? EX: 1:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
                        user_on=$(ls /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold)
                        func_verif_limite_res ${message_from_id}
                        [[ "$_result" -ge "$_limTotal" ]] && {
                            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                                --text "⛔ Max Limit Create Trial only $_limTotal Users\n\nYou Still Have User Active : $user_on" \
                                --parse_mode html
                            break
                            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                                 --text "Func Error Do Nothing" \
                                 --reply_markup "$(ShellBot.ForceReply)"
                        }
                    }
                    if ((${message_text[$id]} == 1 || ${message_text[$id]} == 2)); then
                        func_add_pptp_trial ${message_text[$id]}
                    else
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Trial Max Hours only 1-2")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    fi
                    ;;
                '👤 CREATE USER Trojan-GO 👤\n\nUsername:')
                    verifica_acesso
                    [ "${message_text[$id]}" == 'root' ] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ INVALID USER")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    sizemax=$(echo -e ${#message_text[$id]})
                    [[ "$sizemax" -gt '10' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use no maximum 10 characters [EX: RstoreVPN]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                    }
                    user_already_exist ${message_text[$id]}
                    echo "Name: ${message_text[$id]}" >$CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'TRGo Validity in days: ' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'TRGo Validity in days:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 30]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                if ((${message_text[$id]} >= 1 && ${message_text[$id]} <= 30)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_trgo $CAD_ARQ
                elif ((${message_text[$id]} >= 30 && ${message_text[$id]} <= 60)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_trgo2 $CAD_ARQ
                else
                    ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                        --text "$(echo -e "⛔ Can't be more than 60 Days")" \
                        --parse_mode html
                    >$CAD_ARQ
                    break
                    ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                        --text "Func Error Do Nothing" \
                        --reply_markup "$(ShellBot.ForceReply)"
                fi
                    ;;
                '🗑 REMOVE USER Trojan-GO 🗑\n\nUsername:')
                    verifica_acesso
                    func_del_trgo ${message_text[$id]}
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "✅ *Successfully removed.* 🚮" \
                        --parse_mode markdown
                    ;;
                '👤 CREATE TRIAL Trojan-GO 👤\n\nHow many hours should it last ? EX: 1:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    [[ "${message_from_id[$id]}" != "$Admin_ID" ]] && {
                        user_on=$(ls /etc/.maAsiss/db_reseller/${message_from_id}/trial-fold)
                        func_verif_limite_res ${message_from_id}
                        [[ "$_result" -ge "$_limTotal" ]] && {
                            ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                                --text "⛔ Max Limit Create Trial only $_limTotal Users\n\nYou Still Have User Active : $user_on" \
                                --parse_mode html
                            break
                            ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                                 --text "Func Error Do Nothing" \
                                 --reply_markup "$(ShellBot.ForceReply)"
                        }
                    }
                    if ((${message_text[$id]} == 1 || ${message_text[$id]} == 2)); then
                        func_add_trgo_trial ${message_text[$id]}
                    else
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Trial Max Hours only 1-2")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    fi
                    ;;
                '👤 CREATE USER Xray 👤\n\nUsername:')
                    verifica_acesso
                    [ "${message_text[$id]}" == 'root' ] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ INVALID USER")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    sizemax=$(echo -e ${#message_text[$id]})
                    [[ "$sizemax" -gt '10' ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use no maximum 10 characters [EX: RstoreVPN]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                    }
                    user_already_exist ${message_text[$id]}
                    echo "Name: ${message_text[$id]}" >$CAD_ARQ
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Xray Validity in days: ' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Xray Validity in days:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 30]")" \
                            --parse_mode html
                        >$CAD_ARQ
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                if ((${message_text[$id]} >= 1 && ${message_text[$id]} <= 30)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_xray $CAD_ARQ
                elif ((${message_text[$id]} >= 30 && ${message_text[$id]} <= 1000)); then
                    info_data=$(date '+%d/%m/%C%y' -d " +${message_text[$id]} days")
                    echo "Validity: $info_data" >>$CAD_ARQ
                    func_add_xray2 $CAD_ARQ
                else
                    ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                        --text "$(echo -e "⛔ Can't be more than 1000 Days")" \
                        --parse_mode html
                    >$CAD_ARQ
                    break
                    ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                        --text "Func Error Do Nothing" \
                        --reply_markup "$(ShellBot.ForceReply)"
                fi
                    ;;
                '🗑 REMOVE USER Xray 🗑\n\nUsername:')
                    verifica_acesso
                    func_del_xray ${message_text[$id]}
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "✅ *Successfully removed.* 🚮" \
                        --parse_mode markdown
                    ;;
                '💰 Change Price 💰\n\nPrice SSH:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        >$echotoprice
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "Price SSH : ${message_text[$id]}" >$echotoprice
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Price VMess:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Price VMess:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "Price VMess : ${message_text[$id]}" >>$echotoprice
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Price VLess:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Price VLess:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "Price VLess : ${message_text[$id]}" >>$echotoprice
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Price Trojan:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Price Trojan:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "Price Trojan : ${message_text[$id]}" >>$echotoprice
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Price TrojanGO:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Price TrojanGO:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "Price Trojan-GO : ${message_text[$id]}" >>$echotoprice
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Price Wireguard:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Price Wireguard:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "Price Wireguard : ${message_text[$id]}" >>$echotoprice
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Price Shadowsocks:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Price Shadowsocks:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "Price Shadowsocks : ${message_text[$id]}" >>$echotoprice
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Price Shadowsocks-R:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Price Shadowsocks-R:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "Price Shadowsocks-R : ${message_text[$id]}" >>$echotoprice
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Price SSTP:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Price SSTP:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "Price SSTP : ${message_text[$id]}" >>$echotoprice
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Price L2TP:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Price L2TP:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "Price L2TP : ${message_text[$id]}" >>$echotoprice
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Price PPTP:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Price PPTP:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "Price PPTP : ${message_text[$id]}" >>$echotoprice
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Price Xray:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Price Xray:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "Price Xray : ${message_text[$id]}" >>$echotoprice
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "✅ *Successfully Updated Price List* ✅" \
                        --parse_mode markdown
                    mv /tmp/price /etc/.maAsiss/
                    ;;
                '📢 Info for reseller 📢\n\ntype your information:')
                    verifica_acesso
                    echo "${message_text[$id]}" > /etc/.maAsiss/update-info
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text "✅ *Successfully Added Information* ✅" \
                        --parse_mode markdown
                    ;;
                '🌀 Reset Saldo Reseller 🌀\n\nInput Name of Reseller:')
                    verifica_acesso
                    _VAR14=$(grep -w "${message_text[$id]}" "$Res_Token")
                    [[ -z $_VAR14 ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "No username found 🔴")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo $_VAR14 > /tmp/resSaldo
                    func_reset_saldo_res
                    ;;
                '🌐 Enable Public Mode 🌐\n\nExpired Days [ex:3]:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        >$echotoprice
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "MAX_DAYS : ${message_text[$id]}" > /etc/.maAsiss/public_mode/settings
                    ShellBot.sendMessage --chat_id ${message_from_id[$id]} \
                        --text 'Max User [ex:10]:' \
                        --reply_markup "$(ShellBot.ForceReply)"
                    ;;
                'Max User [ex:10]:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 1000]")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    echo "MAX_USERS : ${message_text[$id]}" >> /etc/.maAsiss/public_mode/settings
                    ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                          --text "Succesfully enable public mode√\n\nShare your bot and tell everyones to type /free" \
                          --parse_mode html
                    ;;
                '😤 Unblock user 😤\n\nInput user ID to unblock:')
                    verifica_acesso
                    [[ ${message_text[$id]} != ?(+|-)+([0-9]) ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "⛔ Use only numbers [EX: 100938380]")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    _VA4=$(grep -w "${message_text[$id]}" "/etc/.maAsiss/user_flood")
                    [[ -z $_VA4 ]] && {
                        ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                            --text "$(echo -e "ID not found 🔴")" \
                            --parse_mode html
                        break
                        ShellBot.sendMessage --chat_id ${callback_query_message_chat_id[$id]} \
                            --text "Func Error Do Nothing" \
                            --reply_markup "$(ShellBot.ForceReply)"
                    }
                    sed -i "/^${message_text[$id]}/d" "/etc/.maAsiss/user_flood"
                    ShellBot.sendMessage --chat_id ${message_chat_id[$id]} \
                          --text "Succesfully unblock user id <b>${message_text[$id]}</b>" \
                          --parse_mode html
                    ;;
                esac
            fi
        ) &
    done
done
