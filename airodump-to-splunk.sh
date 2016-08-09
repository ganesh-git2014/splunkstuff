#!/bin/bash
# Credit to Pwnie Express (pwnieexpress.com)
# Modified from https://github.com/monzymerza/pwnexpress/blob/master/bin/pwnie-to-splunk.sh
# Updated by Brett Salmiery
# Description: Script to modify activity with wireless clients & APs
# Script revision: 4/21/2016

# Set variables

control_c() {
    cls
    echo "[!] Killing processes..."
    ifconfig "${wireless_interface}" down
    killall screen
    killall airodump-ng
    killall tail
    airmon-ng stop "${monitor_interface}"
    ifconfig "${wireless_interface}" up
    exit
}

trap control_c SIGINT

local_logpath="/root/Desktop/airodumpLogs"
wireless_interface="wlan0"
monitor_interface="wlan0mon"

# Verify we are root
if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root" 1>&2
   exit 1
fi
killall airodump-ng
killall tail
airmon-ng stop "${monitor_interface}"
airmon-ng check kill
rfkill unblock "${wireless_interface}"
airmon-ng start "${wireless_interface}"

# Terminate any existing airodump processes
ifconfig "${wireless_interface}" down
killall screen
echo "[*] Starting Monitor_AirodumpCSV.py now."
screen -d -m -S MonitorCSV python "${local_logpath}"/Monitor_AirodumpCSV.py

while true; do
    # Remove previous session logs and set wlan interface to down state
    rm "${local_logpath}"/*.log "${local_logpath}"/airodump-*

    # Launch a detached airodump session that logs output in CSV format

    screen -d -m -S AirodumpSession airodump-ng --output-format=csv --write-interval 2 --write="${local_logpath}"/airodump "${monitor_interface}"

    # Need to refresh it every 30 seconds, to see things that go away.
    sleep 30
done
