#!/bin/bash

#source: https://github.com/km4ack/pi-scripts/blob/master/rtc
#install/configure real time clock
#20190203 km4ack
#script based on directions from the following web site
#https://thepihut.com/blogs/raspberry-pi-tutorials/17209332-adding-a-real-time-clock-to-your-raspberry-pi

clear;echo;echo

IC2ACTIVE=$(ls "/dev/i2c-1")

if [ $IC2ACTIVE = "/dev/i2c-1" ]
then
echo "IC2 is active"
else
clear;echo;echo
echo "Please enable IC2 interface in the "
echo "Raspberry Pi Configuration and try again"
exit 0
fi

clear;echo;echo
date
echo
read -p "Is the time above correct? y/n " ANS

if [ $ANS = 'y' ] || [ $ANS = 'Y' ]; then
echo "Time OK"
else
echo; echo "Please connect to the internet"
echo "or GPS to get correct time"; echo
exit 0
fi

sudo i2cdetect -y 1

echo;echo
read -p "Do you see 68 in the info listed above? y/n " ANS1
echo
if [ $ANS1 = 'y' ] || [ $ANS1 = 'Y' ]; then
sudo modprobe rtc-ds1307
echo "ds1307 0x68" | sudo tee -a /sys/class/i2c-adapter/i2c-1/new_device
sudo hwclock -w
echo rtc-ds1307 | sudo tee -a /etc/modules

sudo sed -i 's/exit\ 0//' /etc/rc.local
echo "echo ds1307 0x68 > /sys/class/i2c-adapter/i2c-1/new_device" | sudo tee -a /etc/rc.local > /dev/null 2>&1
echo "sudo hwclock -s" | sudo tee -a /etc/rc.local > /dev/null 2>&1
echo "date" | sudo tee -a /etc/rc.local > /dev/null 2>&1
echo "exit 0" | sudo tee -a /etc/rc.local > /dev/null 2>&1
echo
echo "The real time clock has been installed & configured"
echo "It is advised you check to make sure everything"
echo "is working correctly. See the video for instructions"
echo "Enjoy! 73, de KM4ACK"
else
echo "Please check that the real time"
echo "clock is installed correctly"
echo "and try again"
fi

