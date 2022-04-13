#!/bin/bash

sudo apt update
sudo apt upgrade
sudo apt install pip
pip install -m requirements.txt
sudo apt install usbmount
chmod +x utils/find_usb_devices.sh
