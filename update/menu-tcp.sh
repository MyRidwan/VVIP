#!/bin/bash
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
###########- COLOR CODE -##############
colornow=$(cat /etc/ssnvpn/theme/color.conf)
NC="\e[0m"
RED="\033[0;31m" 
COLOR1="\033[1;36m"
COLBG1="\e[1;97;101m"                  
###########- END COLOR CODE -##########


# COLOR
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'

MYIP=$(curl -s https://icanhazip.com)

clear
tcp_status() {
  if [[ $(grep -c "^#PH56" /etc/sysctl.conf) -eq 1 ]]; then
    echo -e "   TCP 1 Current status : ${green}Installed${NC}"
  else
    echo -e "   TCP 1 Current status : ${red}Not Installed${NC}"
  fi
}

# status tweak
tcp_2_status() {
  if [[ $(grep -c "^##VpsPack" /etc/sysctl.conf) -eq 1 ]]; then
    echo -e "   TCP 2 Current status : ${green}Installed${NC}"
  else
    echo -e "   TCP 2 Current status : ${red}Not Installed${NC}"
  fi
}

# status bbr
bbr_status() {
  local param=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
  if [[ x"${param}" == x"bbr" ]]; then
    echo -e "   BBR status : ${green}Installed${NC}"
  else
    echo -e "   BBR status : ${red}Not Installed${NC}"
  fi
}

delete_bbr() {
  clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " $COLBG1          • TCP TWEAK PANEL •           $NC"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  read -p "   [INFO] Do you want to remove BBR? [y/n]: " -e answer0
  if [[ "$answer0" = 'y' ]]; then
    grep -v "^#BBR
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.conf >/tmp/syscl && mv /tmp/syscl /etc/sysctl.conf
sysctl -p /etc/sysctl.conf >/dev/null
echo "cubic" >/proc/sys/net/ipv4/tcp_congestion_control
echo -e "   [INFO] BBR settings successfully removed."
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
    menu-tcp
  else
    echo ""
    menu-tcp
  fi
}

sysctl_config() {
  sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
  sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
  echo "" >>/etc/sysctl.conf
  echo "#BBR" >>/etc/sysctl.conf
  echo "net.core.default_qdisc = fq" >>/etc/sysctl.conf
  echo "net.ipv4.tcp_congestion_control = bbr" >>/etc/sysctl.conf
  sysctl -p >/dev/null 2>&1
}

check_bbr_status() {
  local param=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
  if [[ x"${param}" == x"bbr" ]]; then
    return 0
  else
    return 1
  fi
}

version_ge() {
  test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"
}

check_kernel_version() {
  local kernel_version=$(uname -r | cut -d- -f1)
  if version_ge ${kernel_version} 4.9; then
    return 0
  else
    return 1
  fi
}

install_bbr2() {
  check_bbr_status
  if [ $? -eq 0 ]; then
echo -e "   [INFO]  TCP BBR already  installed."
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
    menu-tcp
  fi
  check_kernel_version
  if [ $? -eq 0 ]; then
echo -e "  [INFO]  Your kernel version is greater than 4.9, directly setting TCP BBR..."
    sysctl_config
echo -e "   [INFO]  Setting TCP BBR completed..."
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
    menu-tcp
  fi

  if [[ x"${release}" == x"centos" ]]; then
echo -e "   [ERROR] Centos not support"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
    menu-tcp
  fi
}

install_bbr() {
  clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " $COLBG1           • TCP TWEAK PANEL •          $NC"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  read -p "   [INFO] Proceed with installation? [y/n]: " -e answer
  if [[ "$answer" = 'y' ]]; then
    install_bbr2
  else
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
    menu-tcp
  fi
}

delete_Tweaker() {
  clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " $COLBG1            • TCP TWEAK PANEL •         $NC"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  read -p "   [INFO] Remove TCP Tweaker settings? [y/n]: " -e answer0
  if [[ "$answer0" = 'y' ]]; then
    grep -v "^#PH56
net.ipv4.tcp_window_scaling = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 16384 16777216
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_slow_start_after_idle = 0" /etc/sysctl.conf >/tmp/syscl && mv /tmp/syscl /etc/sysctl.conf
    sysctl -p /etc/sysctl.conf >/dev/null
echo -e "   [INFO] TCP Tweaker settings successfully removed."
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
    menu-tcp
  else
    echo ""
    menu-tcp
  fi
}

install_Tweaker() {
  clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " $COLBG1           • TCP TWEAK PANEL •          $NC"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  read -p "   [INFO] Proceed with installation? [y/n]: " -e answer
  if [[ "$answer" = 'y' ]]; then
    echo " " >>/etc/sysctl.conf
    echo "#PH56" >>/etc/sysctl.conf
    echo "net.ipv4.tcp_window_scaling = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 16384 16777216
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_slow_start_after_idle = 0" >>/etc/sysctl.conf
    sysctl -p /etc/sysctl.conf >/dev/null
echo -e "  [INFO] TCP Tweaker settings added successfully."
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
    menu-tcp
  else
echo -e " Installation was canceled by the user!"
  fi
}

delete_Tweaker_2() {
  clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " $COLBG1             • TCP TWEAK PANEL •        $NC"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  read -p "   [INFO] Remove TCP Tweaker settings? [y/n]: " -e answer0
  if [[ "$answer0" = 'y' ]]; then
    grep -v "^##VpsPack
net.ipv4.tcp_fin_timeout = 2
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_keepalive_time = 600
net.ipv4.ip_local_port_range = 2000 65000
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 36000
net.ipv4.route.gc_timeout = 100
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_synack_retries = 1
net.ipv4.tcp_max_orphans = 16384
net.core.somaxconn = 16384
net.core.netdev_max_backlog = 16384" /etc/sysctl.conf >/tmp/syscl && mv /tmp/syscl /etc/sysctl.conf
    sysctl -p /etc/sysctl.conf >/dev/null
echo -e "  TCP Tweaker settings successfully removed."
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
    menu-tcp
  else
    echo ""
    menu-tcp
  fi
}

install_Tweaker_2() {
  clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " $COLBG1             • TCP TWEAK PANEL •        $NC"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  read -p "   [INFO] Proceed with installation? [y/n]: " -e answer
  if [[ "$answer" = 'y' ]]; then
    echo " " >>/etc/sysctl.conf
    echo "##VpsPack" >>/etc/sysctl.conf
    echo "net.ipv4.tcp_fin_timeout = 2
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_keepalive_time = 600
net.ipv4.ip_local_port_range = 2000 65000
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 36000
net.ipv4.route.gc_timeout = 100
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_synack_retries = 1
net.ipv4.tcp_max_orphans = 16384
net.core.somaxconn = 16384
net.core.netdev_max_backlog = 16384" >>/etc/sysctl.conf
    sysctl -p /etc/sysctl.conf >/dev/null
echo -e "   [INFO] TCP Tweaker settings added successfully."
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
    echo ""
read -n 1 -s -r -p "   Press any key to back on menu"
    menu-tcp
  else
    
echo -e "   Installation was canceled by the user!"
    
  fi
}

# menu tweaker
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " $COLBG1           • TCP TWEAK PANEL •          $NC"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
tcp_status
tcp_2_status
bbr_status
echo -e "  "
echo -e "\033[1;93m〔⎆〕 ${grenbo}1.${NC} \033[0;36mInstall BBR${NC}"
echo -e "\033[1;93m〔⎆〕 ${grenbo}2.${NC} \033[0;36mInstall TCP 1${NC}"
echo -e "\033[1;93m〔⎆〕 ${grenbo}3.${NC} \033[0;36mInstall TCP 2 ${NC}"
echo -e "\033[1;93m〔⎆〕 ${grenbo}4.${NC} \033[0;36mDelete BBR  $sts ${NC}"
echo -e "\033[1;93m〔⎆〕 ${grenbo}5.${NC} \033[0;36mDelete TCP 1${NC}"
echo -e "\033[1;93m〔⎆〕 ${grenbo}6.${NC} \033[0;36mDelete TCP 2${NC}"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""
read -p " Select menu :  " opt
echo -e "$DF"
case $opt in
01 | 1) clear ; install_bbr ;;
02 | 2) clear ; install_Tweaker ;;
03 | 3) clear ; install_Tweaker_2 ;;
04 | 4) clear ; delete_bbr ;;
05 | 5) clear ; delete_Tweaker ;;
06 | 6) clear ; delete_Tweaker_2 ;;
00 | 0) clear ; menu-set ;;
*) clear ; menu-tcp ;;
esac
