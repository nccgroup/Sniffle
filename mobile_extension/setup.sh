#!/bin/bash

sudo apt update
sudo apt upgrade
sudo apt install pip
sudo pip install -r ../requirements.txt
sudo pip3 uninstall numpy  # remove previously installed version
sudo apt install python3-numpy
sudo chmod +x /sniffer/mobile_extension/utils/find_usb_devices.sh
