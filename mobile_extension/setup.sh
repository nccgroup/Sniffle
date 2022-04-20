#!/bin/bash

sudo chmod ugo+rwx sniffer
sudo apt update
sudo apt upgrade
sudo apt install pip
sudo pip install -m requirements.txt
sudo apt install usbmount
sudo chmod +x home/sniffer/mobile_extension/utils/find_usb_devices.sh
