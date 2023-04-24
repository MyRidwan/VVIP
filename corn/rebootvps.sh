#!/bin/bash
DATE=$(date +"%m-%d-%Y")
TIME=$(date +"%T")
rm -f /root/log-reboot.txt
echo -e "Server was successfully rebooted on $DATE at $TIME." >> /root/log-reboot.txt
/sbin/shutdown -r now
