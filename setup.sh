#!/bin/bash

sudo apt update
sudo apt upgrade
sudo apt install pip
pip install -m requirements.txt
chmod +x mobile_extension/find_usbDevice.sh