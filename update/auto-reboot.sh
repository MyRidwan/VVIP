#!/bin/bash
red() { echo -e "\\033[32;1m${*}\\033[0m"; }
TIMES="10"
CHATID="1210833546"
KEY="6006599143:AAEgstCAioq35JgX97HaW_G3TAkLKzLZS_w"
URL="https://api.telegram.org/bot$KEY/sendMessage"
clear
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
if [ ! -e /usr/local/bin/reboot_otomatis ]; then
echo '#!/bin/bash' > /usr/local/bin/reboot_otomatis 
echo 'tanggal=$(date +"%m-%d-%Y")' >> /usr/local/bin/reboot_otomatis 
echo 'waktu=$(date +"%T")' >> /usr/local/bin/reboot_otomatis 
echo 'echo "Sucsesfully Reboot On $tanggal Time $waktu." >> /root/log-reboot.txt' >> /usr/local/bin/reboot_otomatis 
echo '/sbin/shutdown -r now' >> /usr/local/bin/reboot_otomatis 
chmod +x /usr/local/bin/reboot_otomatis
fi
curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL
clear
echo -e "\e[31m※\e[0m \e[33mPOWER BY XlordVPN\e[0m \e[31m※\e[0m"
    echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
  echo -e " \e[1;97;101m           AUTO REBOOT VPS              \e[0m"
  echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo "1.  Set Auto-Reboot 1 Hour Period"
echo "2.  Set Auto-Reboot 6 Hour Period"
echo "3.  Set Auto-Reboot 12 Hour Period"
echo "4.  Set Auto-Reboot 1 Day Period"
echo "5.  Set Auto-Reboot 1 Week Period"
echo "6.  Set Auto-Reboot 1 Month Period"
echo "7.  Deactivate Auto-Reboot"
echo "8.  See Reboot Log"
echo "9.  Delete Reboot Log"
echo -e "\e[36m----------------------------------------\e[0m"
read -p "Please Enter Your Choice From [1-9] : " x
echo -e "\e[36m---------------------------------------------\e[0m"
if test $x -eq 1; then
echo "59 * * * * root /usr/local/bin/reboot_otomatis" > /etc/cron.d/reboot_otomatis
echo -e "Auto-Reboot Sucsesfully Set By \e[32m1 Hour Period\e[0m"
echo -e "\e[36m---------------------------------------------\e[0m"
elif test $x -eq 2; then
echo "10 */6 * * * root /usr/local/bin/reboot_otomatis" > /etc/cron.d/reboot_otomatis
echo -e "Auto-Reboot Sucsesfully Set By \e[32m6 Hour Period\e[0m"
echo -e "\e[36m---------------------------------------------\e[0m"
elif test $x -eq 3; then
echo "10 */12 * * * root /usr/local/bin/reboot_otomatis" > /etc/cron.d/reboot_otomatis
echo -e "Auto-Reboot Sucsesfully Set By \e[32m12 Hour Period\e[0m"
echo -e "\e[36m---------------------------------------------\e[0m"
elif test $x -eq 4; then
echo "0 0 * * * root /usr/local/bin/reboot_otomatis" > /etc/cron.d/reboot_otomatis
echo -e "Auto-Reboot Sucsesfully Set By \e[32m1 Day Period\e[0m"
echo -e "\e[36m---------------------------------------------\e[0m"
elif test $x -eq 5; then
echo "10 0 */7 * * root /usr/local/bin/reboot_otomatis" > /etc/cron.d/reboot_otomatis
echo -e "Auto-Reboot Sucsesfully Set By \e[32m1 Week Period\e[0m"
echo -e "\e[36m---------------------------------------------\e[0m"
elif test $x -eq 6; then
echo "10 0 1 * * root /usr/local/bin/reboot_otomatis" > /etc/cron.d/reboot_otomatis
echo -e "Auto-Reboot Sucsesfully Set By \e[32m1 Month Period\e[0m"
echo -e "\e[36m---------------------------------------------\e[0m"
elif test $x -eq 7; then
rm -f /etc/cron.d/reboot_otomatis
echo -e "Auto-Reboot Sucsesfully \e[31mDeactivated ..!\e[0m"
echo -e "\e[36m---------------------------------------------\e[0m"
elif test $x -eq 8; then
if [ ! -e /root/log-reboot.txt ]; then
	echo "No Activity Found"
  echo -e "\e[36m---------------------------------------------\e[0m"
	else 
	echo ' LOG REBOOT |'
	echo "-------------"
	cat /root/log-reboot.txt
  echo -e "\e[36m---------------------------------------------\e[0m"
fi
elif test $x -eq 9; then
echo "" > /root/log-reboot.txt
echo -e "Auto Reboot Log Sucsesfully \e[31mDeleted ..!\e[0m"
echo -e "\e[36m---------------------------------------------\e[0m"
else
echo "Your Choice Canot Found On Menu"
echo -e "\e[36m---------------------------------------------\e[0m"
exit
fi
